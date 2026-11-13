import json
import os
import subprocess

import boto3

# VERIFIED 2026-09-29 via a real local `syft` run (not yet re-verified
# inside an actual Lambda invocation, but the mechanism itself is
# confirmed) -- see README.md "Open questions" for the full test
# writeup. A classic PAT (dependency-track/ghcr-packages-pat) works
# directly as SYFT_REGISTRY_AUTH_PASSWORD for a real GHCR registry
# pull; no GitHub App installation token fallback needed.
GHCR_PAT_SECRET_ARN = os.environ["GHCR_PAT_SECRET_ARN"]
ARTIFACT_BUCKET = os.environ["ARTIFACT_BUCKET"]

secrets_client = boto3.client("secretsmanager")
s3_client = boto3.client("s3")

# Cached across warm invocations -- same idiom as
# dependency-track-syft-scanner/scanner/app.py and
# dependency-track-inspector-sbom-catcher/catcher/app.py's own secret
# caching (GitHub App credentials there; a PAT here, but the same
# "don't re-fetch a secret that can't change without a redeploy/rotation"
# reasoning applies).
_pat_cache = None


def _get_pat():
    global _pat_cache
    if _pat_cache is None:
        secret = secrets_client.get_secret_value(SecretId=GHCR_PAT_SECRET_ARN)
        data = json.loads(secret["SecretString"])
        _pat_cache = data["token"]
    return _pat_cache


def _run_syft(image_reference, sbom_path):
    # registry: prefix forces syft to pull directly from the registry
    # over HTTPS rather than trying a local Docker/Podman daemon first
    # (there is none in a Lambda) -- see README.md "Why registry: mode,
    # no image pull" for why this avoids needing to `docker pull` the
    # full image into Lambda's ephemeral storage first.
    env = dict(os.environ)
    env["SYFT_REGISTRY_AUTH_AUTHORITY"] = "ghcr.io"
    # GHCR's own convention for `docker login ghcr.io` accepts any
    # non-empty username alongside a PAT password -- "x-access-token"
    # matches GitHub's own doc convention for token-based registry
    # auth generally.
    env["SYFT_REGISTRY_AUTH_USERNAME"] = "x-access-token"
    env["SYFT_REGISTRY_AUTH_PASSWORD"] = _get_pat()

    # --platform required: confirmed via real testing that some GHCR
    # images (e.g. ghcr.io/example-org/example-service-prod) are
    # multi-arch manifest indexes, and syft fails outright
    # ("no child with platform ... in index") without an explicit
    # platform to resolve against. Hardcoded to linux/amd64 to match
    # this Lambda's actual runtime architecture (see template.yaml,
    # Architectures: [x86_64] is the implicit default for
    # AWS::Serverless::Function when unset). Confirmed via the same
    # testing that this flag is a safe no-op against already-single-
    # arch images (e.g. ones with an explicit "-arm64" suffix in their
    # own name/tag convention) -- component count was identical with
    # and without the flag for one such image. See README.md "Open
    # questions" for the full test writeup.
    subprocess.run(
        [
            "syft",
            f"registry:{image_reference}",
            "--platform", "linux/amd64",
            "-o", f"cyclonedx-json={sbom_path}",
        ],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )


def lambda_handler(event, context):
    # {"image": "ghcr.io/example-org/foo:abc123"} -- one image reference
    # per invocation, same one-item-per-call shape as
    # dependency-track-syft-scanner/scanner/app.py (one repo@ref per
    # call). Fan-out across the discovery Lambda's full image list is
    # the state machine's job (a Map state), not this Lambda's.
    image_reference = event["image"]

    # ghcr.io/{owner}/{repoPath}:{tag} -- repoPath may itself contain
    # slashes (e.g. ghcr.io/software-advice/softwareadvice/admin-api),
    # so split on the FIRST "/" only to get the owner, and take
    # everything after the LAST ":" as the tag (safe: GHCR image
    # references don't put a bare port number in the host part the way
    # some other registry references can, so the last ":" is always
    # the tag separator here, never a port).
    without_scheme = image_reference.removeprefix("ghcr.io/")
    owner, repo_and_tag = without_scheme.split("/", 1)
    repo_path, tag = repo_and_tag.rsplit(":", 1)

    sbom_path = "/tmp/sbom.cyclonedx.json"
    _run_syft(image_reference, sbom_path)

    with open(sbom_path, "rb") as f:
        sbom_bytes = f.read()

    # Same split-work-across-two-Lambdas reasoning as
    # dependency-track-syft-scanner's scan/upload split: keep SBOM
    # bytes out of the state machine's own JSON (Step Functions caps
    # state data at 256 KB, a real SBOM can exceed that) by handing off
    # only an S3 pointer. Reuses dependency-track-syft-scanner's
    # existing `upload` Lambda unchanged for the actual POST to DT --
    # see README.md "Reusing the existing upload Lambda".
    s3_key = f"ghcr-sboms/{owner}/{repo_path}/{tag}.cyclonedx.json"
    s3_client.put_object(Bucket=ARTIFACT_BUCKET, Key=s3_key, Body=sbom_bytes)

    return {
        "bucket": ARTIFACT_BUCKET,
        "key": s3_key,
        # {owner}/{repoPath} as projectName, tag as projectVersion --
        # see README.md "Project naming / tagging logic" for why (git-
        # short-SHA-style tags observed in Cartography's data are
        # assumed unique per repo, same reasoning as ECR's digest-based
        # versioning, but using the tag as-is rather than resolving a
        # true immutable digest -- see README.md "Tag vs digest
        # identity" for the tradeoff this accepts).
        "project_name": f"{owner}/{repo_path}",
        "project_version": tag,
        # owner/repo passed through so uploader/app.py's _build_tags
        # can emit real org:/repo: tags instead of falling back to its
        # git-repo-pipeline defaults (which produced literal
        # "org:unknown"/"repo:unknown" the first time this ran, since
        # those defaults assume a GitHub Search API-sourced repo
        # object this pipeline never has). sbom_source flags which
        # tag branch _build_tags should take -- see that function for
        # why archived:/fork:/visibility: are deliberately NOT emitted
        # for GHCR-sourced projects (none of those concepts map onto a
        # container image; a git-repo default of False for fork/archived
        # would assert something untrue, not just "unknown").
        "owner": owner,
        "repo": repo_path,
        "sbom_source": "ghcr",
    }
