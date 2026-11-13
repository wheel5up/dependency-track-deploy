import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import boto3
import jwt
import requests

ARTIFACT_BUCKET = os.environ["ARTIFACT_BUCKET"]
GITHUB_APP_SECRET_ARN = os.environ["GITHUB_APP_SECRET_ARN"]

secrets_client = boto3.client("secretsmanager")
s3_client = boto3.client("s3")

# Cached across warm invocations of the same execution environment.
# App credentials never change without a redeploy; installation tokens
# are cached per-org and refreshed only once they're near expiry (GitHub
# mints them with a 1-hour lifetime).
_app_credentials_cache = None
_installation_cache = {}  # org login -> {"installation_id", "token", "expires_at"}


def _get_app_credentials():
    global _app_credentials_cache
    if _app_credentials_cache is None:
        secret = secrets_client.get_secret_value(SecretId=GITHUB_APP_SECRET_ARN)
        data = json.loads(secret["SecretString"])
        _app_credentials_cache = (data["app_id"], data["private_key"])
    return _app_credentials_cache


def _build_app_jwt(app_id, private_key_pem):
    now = int(time.time())
    payload = {
        "iat": now - 60,  # allow for clock drift between here and GitHub
        "exp": now + (9 * 60),  # GitHub caps this at 10 minutes; leave margin
        "iss": app_id,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def _get_installation_token(owner):
    # Dynamic per-org lookup: this GitHub App can be installed into any
    # number of orgs independently, each with its own installation ID.
    # Rather than hardcode one org's ID, resolve it per request so
    # installing the app into a new org needs no code or secret change.
    now = datetime.now(timezone.utc)
    cached = _installation_cache.get(owner)
    if cached and cached["expires_at"] > now + timedelta(minutes=5):
        return cached["token"]

    app_id, private_key = _get_app_credentials()
    app_jwt = _build_app_jwt(app_id, private_key)
    auth_headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
    }

    installation_id = cached.get("installation_id") if cached else None
    if installation_id is None:
        resp = requests.get(
            f"https://api.github.com/orgs/{owner}/installation",
            headers=auth_headers,
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(
                f"GitHub App is not installed on org '{owner}' (or org does not "
                f"exist): HTTP {resp.status_code}"
            )
        installation_id = resp.json()["id"]

    resp = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=auth_headers,
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(
            f"Failed to mint an installation token for org '{owner}': "
            f"HTTP {resp.status_code}"
        )
    data = resp.json()
    token = data["token"]
    expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))

    _installation_cache[owner] = {
        "installation_id": installation_id,
        "token": token,
        "expires_at": expires_at,
    }
    return token


def _parse_owner_repo(repo_url):
    path = urlparse(repo_url).path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    parts = path.split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse owner/repo from repo_url: {repo_url}")
    return parts[0], parts[1]


def _get_repo_metadata(owner, repo, token):
    # Covered by the same Contents:Read-only permission already used
    # for tarball downloads -- no GitHub App permission change needed.
    # Only called when the caller didn't already supply repo_metadata
    # (e.g. an ad-hoc single-repo start-execution) -- batch-scan runs
    # get this for free from list-repos-page's own Search API response
    # instead of paying for a second HTTP call per repo.
    resp = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(
            f"GitHub repo metadata lookup failed for {owner}/{repo}: "
            f"HTTP {resp.status_code}"
        )
    data = resp.json()
    return {
        "visibility": data.get("visibility"),
        "fork": data.get("fork", False),
        "archived": data.get("archived", False),
        "language": data.get("language"),
    }


def _download_tarball(owner, repo, ref, dest_path, token):
    # Syft has no "scan a git URL" mode -- it needs a local source tree.
    # A tarball avoids depending on the `git` binary and skips
    # .git history/metadata that syft doesn't need.
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{ref}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        # Header only -- never embedded in the URL, a git remote, or a
        # subprocess arg list, so it can't leak into a stack trace.
        headers["Authorization"] = f"token {token}"
    with requests.get(url, headers=headers, stream=True, timeout=60) as response:
        if not response.ok:
            raise RuntimeError(
                f"GitHub tarball download failed for {owner}/{repo}@{ref}: "
                f"HTTP {response.status_code}"
            )
        with open(dest_path, "wb") as out_file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                out_file.write(chunk)


def _extract_tarball(tarball_path, dest_dir):
    import tarfile

    with tarfile.open(tarball_path) as tar:
        tar.extractall(dest_dir, filter="data")
    # GitHub tarballs contain exactly one top-level "<owner>-<repo>-<sha>" dir.
    entries = os.listdir(dest_dir)
    if len(entries) != 1:
        raise RuntimeError(
            f"Unexpected tarball layout, expected one top-level dir, got: {entries}"
        )
    return os.path.join(dest_dir, entries[0])


def _run_syft(source_dir, sbom_path):
    subprocess.run(
        ["syft", source_dir, "-o", f"cyclonedx-json={sbom_path}"],
        check=True,
        capture_output=True,
        text=True,
    )


def lambda_handler(event, context):
    repo_url = event["repo_url"]
    ref = event["ref"]
    owner, repo = _parse_owner_repo(repo_url)
    project_name = event.get("project_name") or f"{owner}/{repo}"
    project_version = event.get("project_version") or ref

    # Unique per-invocation scratch dir: /tmp persists across warm
    # invocations of the same execution environment, so at "dozens of
    # calls an hour" a shared fixed path would accumulate downloads and
    # extracted trees across calls until ephemeral storage fills up.
    workdir = f"/tmp/{context.aws_request_id}"
    os.makedirs(workdir, exist_ok=True)
    tarball_path = os.path.join(workdir, "src.tar.gz")
    extract_dir = os.path.join(workdir, "extracted")
    sbom_path = os.path.join(workdir, "sbom.json")

    try:
        token = _get_installation_token(owner)

        # Batch-scan already has this from list-repos-page's own Search
        # API response -- reuse it instead of paying for a second HTTP
        # call per repo. Ad-hoc single-repo executions (repo_url passed
        # directly to start-execution, no batch orchestrator involved)
        # won't have it, so fetch it here instead.
        repo_metadata = event.get("repo_metadata") or _get_repo_metadata(owner, repo, token)

        _download_tarball(owner, repo, ref, tarball_path, token)
        source_dir = _extract_tarball(tarball_path, extract_dir)
        _run_syft(source_dir, sbom_path)

        key = f"{owner}/{repo}/{ref}/{context.aws_request_id}.cdx.json"
        s3_client.upload_file(sbom_path, ARTIFACT_BUCKET, key)

        return {
            "bucket": ARTIFACT_BUCKET,
            "key": key,
            "project_name": project_name,
            "project_version": project_version,
            "owner": owner,
            "repo": repo,
            "repo_metadata": repo_metadata,
        }
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"syft failed for {owner}/{repo}@{ref}: {exc.stderr}") from None
    finally:
        # Runs on every path -- success, syft failure, or download
        # failure -- so a warm environment never inherits a previous
        # invocation's files.
        shutil.rmtree(workdir, ignore_errors=True)
