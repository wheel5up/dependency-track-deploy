import json
import os

import boto3
import requests

DT_API_KEY_SECRET_ARN = os.environ["DT_API_KEY_SECRET_ARN"]
APISERVER_BASE_URL = os.environ["APISERVER_BASE_URL"]

secrets_client = boto3.client("secretsmanager")

# Cached across warm invocations -- same idiom as the existing
# scan/upload Lambdas in dependency-track-syft-scanner.
_api_key_cache = None


def _get_api_key():
    global _api_key_cache
    if _api_key_cache is None:
        secret = secrets_client.get_secret_value(SecretId=DT_API_KEY_SECRET_ARN)
        _api_key_cache = json.loads(secret["SecretString"])["apiKey"]
    return _api_key_cache


def _properties_dict(sbom):
    # Every Inspector CycloneDX export (EC2/ECR/Lambda alike) carries
    # its identifying fields as metadata.properties, a flat list of
    # {"name": "amazon:inspector:X", "value": "..."} pairs -- flatten
    # to a dict keyed by the part after the "amazon:inspector:" prefix
    # for easy lookup.
    props = {}
    for prop in sbom.get("metadata", {}).get("properties", []):
        name = prop.get("name", "")
        if name.startswith("amazon:inspector:"):
            props[name[len("amazon:inspector:"):]] = prop.get("value")
    return props


def _sanitize_ec2_sbom(sbom):
    # EC2-only pre-upload fixups for two known Inspector SBOM defects
    # that fail DT's schema validation on /api/v1/bom. Scoped to EC2 only:
    # these are the only failure shapes observed so far, and ECR/Lambda
    # SBOMs shouldn't be silently mutated on a hunch they might have
    # the same issue when there's no evidence they do.
    #
    # 1. Drop "unresolved-hash" stub components -- Inspector emits a
    #    component with only a hash and an
    #    amazon:inspector:unresolved-hash property when it can't
    #    identify a file, omitting the CycloneDX-required "type" (and
    #    "name") field entirely. No real data loss: a bare hash
    #    Inspector itself couldn't identify isn't useful in DT either.
    components = sbom.get("components", [])
    dropped = 0
    kept = []
    for c in components:
        if "type" not in c and "name" not in c:
            dropped += 1
            continue
        kept.append(c)
    sbom["components"] = kept

    # 2. De-duplicate vulnerabilities[].affects entries -- seen only on
    #    Ubuntu 22.04 SBOMs so far, looks like an Inspector
    #    vuln-matching bug producing repeated {"ref": ...} entries in
    #    the same affects array, which DT's schema (uniqueItems) rejects.
    deduped_vuln_count = 0
    for vuln in sbom.get("vulnerabilities", []):
        affects = vuln.get("affects")
        if not affects:
            continue
        seen = set()
        unique_affects = []
        for a in affects:
            key = json.dumps(a, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            unique_affects.append(a)
        if len(unique_affects) != len(affects):
            deduped_vuln_count += 1
            vuln["affects"] = unique_affects

    return sbom, dropped, deduped_vuln_count


def _region_from_arn(arn):
    # arn:{partition}:{service}:{region}:{account}:{resource} -- works
    # for EC2/ECR/Lambda ARNs alike.
    parts = arn.split(":")
    if len(parts) > 3:
        return parts[3]
    return None


def _derive_project(sbom, props):
    resource_type = props.get("resource_type")
    account_id = props.get("account_id")

    if resource_type == "AWS_EC2_INSTANCE":
        instance_id = props["instance_id"]
        # No AMI identity is present in the SBOM's own
        # amazon:inspector:* properties for EC2 (unlike ECR's image
        # digest or Lambda's qualifier). An ec2:DescribeInstances
        # lookup was considered but rejected: this account is an
        # Inspector delegated administrator, so exported EC2 instances
        # routinely belong to 50+ different member accounts, and this
        # Lambda's role has no cross-account access into any of them --
        # a lookup would only ever succeed for the one account (this
        # one) that owns the role, an unhelpful ratio not worth the
        # added complexity/IAM surface.
        #
        # Instead, use metadata.component -- the OS distribution
        # identity CycloneDX itself carries. .name is the OS family
        # (e.g. "AMAZON_LINUX_2023", "BOTTLEROCKET") -- surfaced as the
        # "os" tag below, not the version, since it collapses distinct
        # builds together (e.g. every Bottlerocket build reports the
        # same "BOTTLEROCKET" name). .version carries the actual
        # build/patch string (e.g. "2023" for AL2023, "2026.9.18" for a
        # specific Bottlerocket build) -- always present in the SBOM
        # with no extra API call and no cross-account concern, so this
        # is used as projectVersion. A version bump minting a new DT
        # project version (rather than updating in place) is expected
        # and fine here: DT has no operational/lifecycle knowledge of
        # the underlying machine, only of the SBOMs it's given, and
        # instances on immutable OSes like Bottlerocket are normally
        # replaced (new instance ID) rather than patched in place on a
        # build bump anyway. Orphaned old versions are an expected
        # outcome of SBOM-only visibility, not a bug -- clean up
        # periodically, same as any other stale project version.
        component = sbom.get("metadata", {}).get("component", {})
        os_name = component.get("name") or "unknown"
        version = component.get("version") or "unknown"
        return {
            "projectName": f"{account_id}/{instance_id}",
            "projectVersion": version,
            "region": _region_from_arn(props.get("resource_arn", "")),
            "os": os_name,
        }

    if resource_type == "AWS_ECR_CONTAINER_IMAGE":
        repo_arn = props.get("repository_arn", "")
        # arn:aws:ecr:{region}:{account}:repository/{repo/name}
        repo_name = repo_arn.split("repository/", 1)[-1] if "repository/" in repo_arn else repo_arn
        # {accountId}/{repoName}, same pattern as EC2/Lambda -- checked
        # against a real org-wide export (1698 images, 290 distinct
        # repo names) and found 4 repo names duplicated across
        # different accounts (e.g. "anycable-go" in two unrelated
        # accounts) -- account_id prefix is required here, not just a
        # style match with the other resource types.
        image_digest = props.get("image_id", "unknown")
        # metadata.component (OS family/version) is present here too,
        # same shape as EC2's -- but far less reliable: missing in the
        # large majority of a real sample (136/150, ~91%), and when
        # present, sometimes wrong (e.g. a container built FROM a
        # docker:19.03.13-dind base reported metadata.component.version
        # "19.03.13" -- Docker Engine's own version, not the OS's,
        # under name "AMAZON_LINUX_2"). Kept as an os: tag only
        # (best-effort, matching EC2's tag), never used for
        # projectVersion -- image_digest (below) is the only reliably
        # present, reliably unique identifier here.
        component = sbom.get("metadata", {}).get("component", {})
        os_name = component.get("name")
        architecture = props.get("architecture")
        result = {
            "projectName": f"{account_id}/{repo_name}",
            "projectVersion": image_digest,
            "region": _region_from_arn(repo_arn),
        }
        if os_name:
            result["os"] = os_name
        if architecture:
            result["architecture"] = architecture
        return result

    if resource_type == "AWS_LAMBDA_FUNCTION":
        function_name = props["function_name"]
        resource_arn = props.get("resource_arn", "")
        # arn:aws:lambda:{region}:{account}:function:{name}:{qualifier}
        # -- the ARN's own qualifier (e.g. "$LATEST") is NOT used as
        # projectVersion: confirmed via a full org-wide export that
        # every function in this org is $LATEST-only (nobody publishes
        # versions/aliases), so it carries zero signal as a version.
        # amazon:inspector:runtime (e.g. "PYTHON_3_13", "PROVIDED_AL2023")
        # is used instead -- always present in the SBOM with no extra
        # API call and no cross-account concern, and gives a real,
        # varying value (14 distinct runtimes observed org-wide) that
        # actually distinguishes projects, unlike a constant qualifier.
        # Note PROVIDED_AL2023 only identifies the custom-runtime OS
        # layer, not the function's actual language (e.g. Rust/Go
        # using a custom bootstrap) -- a known limitation of this field,
        # not something this pipeline can resolve without inspecting
        # the deployment package itself.
        runtime = props.get("runtime") or "unknown"
        return {
            "projectName": f"{account_id}/{function_name}",
            "projectVersion": runtime,
            "region": _region_from_arn(resource_arn),
            "runtime": runtime,
        }

    raise ValueError(f"Unrecognized Inspector resourceType: {resource_type}")


def _build_tags(project, props):
    # DT lowercases tag names on ingest (confirmed by testing) --
    # lowercase here too so the sent value matches what's actually
    # stored, avoiding any confusion when diffing/auditing tags later.
    tags = [
        f"resourcetype:{props.get('resource_type', 'unknown')}".lower(),
        f"accountid:{props.get('account_id', 'unknown')}".lower(),
        f"region:{project.get('region') or 'unknown'}".lower(),
        "sbomsource:inspector",
    ]
    # EC2/ECR: OS family (e.g. "amazon_linux_2023", "bottlerocket"),
    # kept as a tag rather than in projectVersion since it collapses
    # distinct builds together -- see _derive_project's EC2/ECR
    # branches. Absent for ECR images where Inspector didn't report an
    # OS at all (the common case, ~91% of a real sample).
    if "os" in project:
        tags.append(f"os:{project['os']}".lower())
    # ECR-only: image architecture (e.g. "amd64", "arm64") -- always
    # present in the SBOM, no extra API call.
    if "architecture" in project:
        tags.append(f"architecture:{project['architecture']}".lower())
    # Lambda-only: runtime, duplicated from projectVersion so it's
    # still filterable/visible as a tag even though it's now also the
    # version -- see _derive_project's Lambda branch.
    if "runtime" in project:
        tags.append(f"runtime:{project['runtime']}".lower())
    return ",".join(tags)


def lambda_handler(event, context):
    detail = event["detail"]
    bucket = detail["bucket"]["name"]
    key = detail["object"]["key"]
    # Use the event's own region -- not the Lambda's own region --
    # since events from the remote-region export bucket are forwarded
    # cross-region to this catcher via EventBridge, but the object
    # itself still lives in the remote region (S3 buckets are regional;
    # Inspector requires bucket+key to be same-region as the export).
    # The top-level EventBridge envelope's "region" field reflects the
    # origin region even after cross-region forwarding.
    source_region = event.get("region", os.environ["AWS_REGION"])

    # Folder-marker objects (zero-byte keys ending in "/") also fire
    # ObjectCreated -- skip them rather than failing on a JSON parse
    # of an empty body.
    if key.endswith("/"):
        return {"status": "skipped", "reason": "folder marker, not an SBOM object"}
    if not key.endswith("_CYCLONEDX_1_4.json"):
        return {"status": "skipped", "reason": "not a CycloneDX SBOM object"}

    s3_client = boto3.client("s3", region_name=source_region)
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    sbom_bytes = obj["Body"].read()
    sbom = json.loads(sbom_bytes)

    props = _properties_dict(sbom)
    project = _derive_project(sbom, props)
    tags = _build_tags(project, props)

    # EC2-only sanitization -- see _sanitize_ec2_sbom's docstring
    # for why this is scoped to EC2 and not applied to ECR/Lambda.
    dropped_components = 0
    deduped_vulns = 0
    if props.get("resource_type") == "AWS_EC2_INSTANCE":
        sbom, dropped_components, deduped_vulns = _sanitize_ec2_sbom(sbom)
        sbom_bytes = json.dumps(sbom).encode("utf-8")

    api_key = _get_api_key()
    response = requests.post(
        f"{APISERVER_BASE_URL}/api/v1/bom",
        headers={"X-Api-Key": api_key},
        data={
            "projectName": project["projectName"],
            "projectVersion": project["projectVersion"],
            "autoCreate": "true",
            "projectTags": tags,
        },
        files={"bom": (os.path.basename(key), sbom_bytes, "application/json")},
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(
            f"Dependency-Track BOM upload failed for "
            f"{project['projectName']}@{project['projectVersion']}: "
            f"HTTP {response.status_code} {response.text}"
        )

    return {
        "status": "uploaded",
        "projectName": project["projectName"],
        "projectVersion": project["projectVersion"],
        "tags": tags,
        "droppedComponents": dropped_components,
        "dedupedVulnerabilities": deduped_vulns,
    }
