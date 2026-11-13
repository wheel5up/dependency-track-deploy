import json
import os
import time

import boto3
import jwt
import requests

GITHUB_APP_SECRET_ARN = os.environ["GITHUB_APP_SECRET_ARN"]

secrets_client = boto3.client("secretsmanager")

# Cached across warm invocations of the same execution environment --
# same idiom as scan/app.py. App credentials never change without a
# redeploy; the installation token is cached per-org and refreshed only
# once near expiry (GitHub mints them with a 1-hour lifetime).
_app_credentials_cache = None
_installation_cache = {}  # org login -> {"installation_id", "token", "expires_at"}

SEARCH_PAGE_SIZE = 100


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


def _get_installation_token(org):
    # Same per-org dynamic lookup as scan/app.py -- no installation ID
    # is stored, so installing the App into a new org needs no code or
    # secret change.
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    cached = _installation_cache.get(org)
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
            f"https://api.github.com/orgs/{org}/installation",
            headers=auth_headers,
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(
                f"GitHub App is not installed on org '{org}' (or org does not "
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
            f"Failed to mint an installation token for org '{org}': "
            f"HTTP {resp.status_code}"
        )
    data = resp.json()
    token = data["token"]
    expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))

    _installation_cache[org] = {
        "installation_id": installation_id,
        "token": token,
        "expires_at": expires_at,
    }
    return token


def _build_search_query(org, prop, values):
    # GitHub custom-properties search qualifier: props.<name>:<value>.
    # Multiple values are OR'd by repeating the qualifier, not by a
    # comma-joined single qualifier. prop/values are optional -- when
    # absent, the query is just org + archived:false + fork:true.
    #
    # fork:true is required -- the Search API silently excludes forks
    # by default (confirmed: org:<org> archived:false alone returned
    # 648 vs. the org's real 750 non-archived repos; the missing 102
    # were 100% forks). We deliberately include forks even though some
    # are untouched upstream mirrors -- if the org is running it, its
    # dependency tree belongs in the inventory regardless of who
    # authored the code.
    if not prop or not values:
        return f"org:{org} archived:false fork:true"
    props_clause = " ".join(f"props.{prop}:{v}" for v in values)
    return f"org:{org} archived:false fork:true {props_clause}".strip()


def lambda_handler(event, context):
    org = event["org"]
    prop = event.get("property")
    values = event.get("values")
    exclude = set(event.get("exclude") or [])
    page = event.get("page", 1)
    # None (or absent) means "no limit" -- scan every non-excluded,
    # non-archived match. Distinct from 0, which would mean "stop now".
    limit_remaining = event.get("limit_remaining")

    token = _get_installation_token(org)
    query = _build_search_query(org, prop, values)

    resp = requests.get(
        "https://api.github.com/search/repositories",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
        params={"q": query, "page": page, "per_page": SEARCH_PAGE_SIZE},
        timeout=30,
    )
    if resp.status_code in (403, 429):
        # Let ASL's Retry block handle backoff -- surface enough detail
        # to see whether this was the secondary rate limit or the
        # 30-req/min Search API limit specifically.
        raise RuntimeError(
            f"GitHub Search API rate-limited: HTTP {resp.status_code} "
            f"remaining={resp.headers.get('X-RateLimit-Remaining')} "
            f"retry-after={resp.headers.get('Retry-After')}"
        )
    if not resp.ok:
        raise RuntimeError(
            f"GitHub Search API request failed for query '{query}': "
            f"HTTP {resp.status_code} {resp.text}"
        )

    data = resp.json()
    items = data.get("items", [])
    total_count = data.get("total_count", 0)

    repos = []
    for repo in items:
        full_name = repo["full_name"]
        if full_name in exclude:
            continue
        repos.append(
            {
                "repo_url": repo["html_url"],
                "ref": repo["default_branch"],
                # Free -- already present in the Search API's own
                # response for every result. Threaded through to scan
                # so it doesn't need to pay for a second
                # GET /repos/{owner}/{repo} call per repo. See
                # scan/app.py's _get_repo_metadata for the ad-hoc
                # single-repo equivalent (used when this isn't
                # available).
                "repo_metadata": {
                    # "visibility" (public/private/internal) is present
                    # directly on Search API repo items -- fall back to
                    # the "private" boolean only if it's ever absent.
                    "visibility": repo.get("visibility")
                    or ("private" if repo.get("private") else "public"),
                    "fork": repo.get("fork", False),
                    "archived": repo.get("archived", False),
                    "language": repo.get("language"),
                },
            }
        )
        if limit_remaining is not None and len(repos) >= limit_remaining:
            break

    limit_remaining_after = (
        None if limit_remaining is None else limit_remaining - len(repos)
    )
    has_more_pages = page * SEARCH_PAGE_SIZE < total_count
    has_next_page = has_more_pages and (
        limit_remaining_after is None or limit_remaining_after > 0
    )

    return {
        "items": repos,
        "has_next_page": has_next_page,
        "limit_remaining": limit_remaining_after,
    }
