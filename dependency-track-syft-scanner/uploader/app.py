import json
import os

import boto3
import requests

DT_API_KEY_SECRET_ARN = os.environ["DT_API_KEY_SECRET_ARN"]
APISERVER_BASE_URL = os.environ["APISERVER_BASE_URL"]

secrets_client = boto3.client("secretsmanager")
s3_client = boto3.client("s3")

_api_key_cache = None


def _build_tags(event):
    # Project-level tags only -- DT has no component/package-level
    # labeling, and a given purl is not deduped/shared across projects
    # (each project gets its own Component rows even for an identical
    # package+version). See TODO.md for the full reasoning and what's
    # deliberately deferred (custom properties -- needs a GitHub App
    # permission change, not added yet).
    #
    # Lowercased here to match what DT actually stores (it lowercases
    # tag names on ingest regardless -- confirmed against the existing
    # inspector-sbom-catcher's _build_tags, mirrored here for
    # consistency) -- avoids diff-noise when auditing tags later.
    #
    # Returns a plain list -- callers format it per-endpoint: the /bom
    # upload's projectTags field wants a comma-joined string, while
    # PATCH /project/{uuid}'s tags field wants [{"name": ...}, ...].
    #
    # This Lambda is shared by two callers with genuinely different
    # tag schemas -- dependency-track-syft-scanner's own scan/app.py
    # (git repos: owner/repo/repo_metadata with visibility/fork/archived/
    # language) and dependency-track-ghcr-scanner's scan/app.py
    # (container images: owner/repo only, no repo_metadata at all).
    # Branching on sbom_source rather than defaulting missing
    # git-repo fields to "unknown"/False -- confirmed via a real GHCR
    # upload that the git-repo defaults produce misleading tags for a
    # container image project: "org:unknown"/"repo:unknown" (should
    # just be the real GHCR owner/repo, which IS available -- the
    # unknown fallback was masking data scan/app.py already had, not
    # genuinely-missing data), and "archived:false"/"fork:false"
    # (asserting something false about a concept -- GitHub repo
    # archival/fork status -- that doesn't apply to a container image
    # at all, worse than "unknown" since it looks like a verified fact
    # rather than an inapplicable field).
    if event.get("sbom_source") == "ghcr":
        owner = event.get("owner", "unknown")
        repo = event.get("repo", "unknown")
        return [
            f"org:{owner}".lower(),
            f"repo:{repo}".lower(),
            # Every project reaching this Lambda from
            # dependency-track-ghcr-scanner's pipeline was discovered
            # via a live Cartography query of what's actually
            # scheduled on the Kubernetes fleet right now -- unlike
            # visibility/fork/archived (GitHub-repo-API concepts with
            # no container-image equivalent), "is this confirmed
            # running" is real, verified information this pipeline
            # actually has, not a guess or an inapplicable default.
            "deployed:true",
            # syft generated this SBOM either way (git-repo or
            # container image) -- sbomsource describes the tool, not
            # the scan target, so it stays "syft" for both branches.
            # What actually differs here is the target type, which DT
            # already surfaces as the project's classifier
            # (CONTAINER, per syft's own CycloneDX metadata.component.
            # type for image scans). Mirroring that as an explicit tag
            # -- rather than a new "sbomsource:ghcr" value that would
            # conflate tool with target -- keeps sbomsource meaningful
            # and makes the target type filterable/visible without
            # cross-referencing the separate classifier column.
            "classifier:container",
            "sbomsource:syft",
        ]

    owner = event.get("owner", "unknown")
    repo = event.get("repo", "unknown")
    metadata = event.get("repo_metadata") or {}

    tags = [
        f"org:{owner}".lower(),
        f"repo:{repo}".lower(),
        f"visibility:{metadata.get('visibility', 'unknown')}".lower(),
        f"fork:{metadata.get('fork', False)}".lower(),
        f"archived:{metadata.get('archived', False)}".lower(),
        "sbomsource:syft",
    ]
    language = metadata.get("language")
    if language:
        tags.append(f"language:{language}".lower())
    return tags


def _get_api_key():
    global _api_key_cache
    if _api_key_cache is None:
        secret = secrets_client.get_secret_value(SecretId=DT_API_KEY_SECRET_ARN)
        _api_key_cache = json.loads(secret["SecretString"])["apiKey"]
    return _api_key_cache


def _patch_project_tags(api_key, project_uuid, tags):
    # Always called, not just for freshly-created projects: DT's /bom
    # response gives no signal to distinguish create vs. update (same
    # 200 status, no distinguishing field/header -- confirmed by direct
    # testing), so detecting "just created" cleanly would require an
    # extra GET /project/lookup beforehand, defeating the point of
    # avoiding extra calls. A redundant PATCH on the create path (where
    # projectTags on the /bom upload already set these same tags) is a
    # harmless no-op write -- not worth the extra round-trip to skip it.
    #
    # This is also what makes tags self-heal on every future field
    # addition and on any drift (e.g. a repo's visibility changes) --
    # every scheduled re-scan re-applies current tags, no separate
    # backfill script ever needed again after this.
    response = requests.patch(
        f"{APISERVER_BASE_URL}/api/v1/project/{project_uuid}",
        headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
        json={"tags": [{"name": t} for t in tags]},
        timeout=30,
    )
    if not response.ok:
        raise RuntimeError(
            f"Dependency-Track project tag update failed for "
            f"{project_uuid}: HTTP {response.status_code} {response.text}"
        )


def lambda_handler(event, context):
    bucket = event["bucket"]
    key = event["key"]
    project_name = event["project_name"]
    project_version = event["project_version"]
    tags = _build_tags(event)

    # Reads the SBOM straight from S3 -- this is the whole point of
    # routing through S3 instead of Step Functions data: no 256 KB
    # state payload limit applies to what a Lambda does internally.
    sbom_path = f"/tmp/{context.aws_request_id}.cdx.json"

    try:
        s3_client.download_file(bucket, key, sbom_path)

        api_key = _get_api_key()
        with open(sbom_path, "rb") as sbom_file:
            response = requests.post(
                f"{APISERVER_BASE_URL}/api/v1/bom",
                headers={"X-Api-Key": api_key},
                data={
                    "projectName": project_name,
                    "projectVersion": project_version,
                    "autoCreate": "true",
                    "projectTags": ",".join(tags),
                },
                files={"bom": (os.path.basename(key), sbom_file, "application/json")},
                timeout=60,
            )
        if not response.ok:
            raise RuntimeError(
                f"Dependency-Track BOM upload failed for "
                f"{project_name}@{project_version}: HTTP {response.status_code} "
                f"{response.text}"
            )

        # /bom's own response already carries the project's UUID for
        # both new and existing projects (confirmed by direct testing)
        # -- no extra GET /project/lookup needed to resolve it.
        project_uuid = response.json()["projectUuid"]
        _patch_project_tags(api_key, project_uuid, tags)

        return {
            "project_name": project_name,
            "project_version": project_version,
            "status": "uploaded",
            "tags": tags,
        }
    finally:
        try:
            os.remove(sbom_path)
        except FileNotFoundError:
            pass
