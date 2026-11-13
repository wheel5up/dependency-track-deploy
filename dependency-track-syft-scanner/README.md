# dependency-track-syft-scanner

Generates SBOMs for GitHub repos with [syft](https://github.com/anchore/syft)
and uploads them to Dependency-Track. It can scan one repo on demand, or
every repo in a GitHub org. It only adds resources. It does not change
`dependency-track-db` or `dependency-track-workload`.

## Components

- **`scan` Lambda** downloads a repo tarball for a ref using a GitHub App
  installation token (no `git`, no history). It runs syft, writes the
  CycloneDX SBOM to S3, and returns only an `{bucket, key}` pointer.
- **`upload` Lambda** reads the SBOM from S3 and POSTs it to the
  apiserver's `/api/v1/bom`. It runs in the workload VPC subnets, because
  the apiserver is only reachable privately. It also tags the project
  (see below).
- **`list-repos-page` Lambda** returns one page (100 repos) from the
  GitHub Search API (`org:{org} archived:false fork:true`, plus optional
  custom-property filters). It drops excluded repos and applies the limit.
- **`ScanAndUploadStateMachine`** (Standard, `dependency-track-syft-scanner`):
  `Scan → Upload` for one repo.
- **`BatchScanStateMachine`** (Express, `dependency-track-batch-scan`):
  lists an org's repos and starts one scanner execution per repo.
- One S3 artifact bucket, two Secrets Manager secrets, two SSM parameters.

## Design notes

- **SBOMs go through S3, not Step Functions state.** Step Functions caps
  state data at 256 KB. Real SBOMs often exceed that.
- **Only `upload` is in the VPC.** `scan` needs internet egress to GitHub.
  `upload` only needs the apiserver. The stack adds one ingress rule to
  the existing workload security group.
- **The batch scan is Express.** That means no Distributed Map and no
  `.sync`. Per-repo calls are fire-and-forget. Per-repo success or failure
  shows only in the scanner state machine's history, not in the batch
  result.
- **Pagination uses self-recursion.** After each page, the batch state
  machine starts a new execution of itself for the next page. This resets
  the Express 5-minute limit and gives each page its own history.
- **Repos are scanned one at a time.** `MapRepos` uses `MaxConcurrency: 1`
  plus a configurable delay, so the single apiserver isn't flooded.
- **SSM config is read on every page.** Changes to the delay or exclude
  list take effect on the next page, even mid-run.
- **Forks are included.** The Search API skips forks by default.
  `fork:true` adds them back, since forks you deploy are part of your
  dependency inventory.

## Project tagging

Every project the pipeline touches gets these tags:

| Tag | Source |
|---|---|
| `org:{owner}`, `repo:{repo}` | parsed from `repo_url` |
| `visibility:{public\|private\|internal}` | GitHub repo metadata |
| `fork:{true\|false}`, `archived:{true\|false}` | GitHub repo metadata |
| `language:{name}` | primary language (omitted if null) |
| `sbomsource:syft` | constant |

Batch scans get metadata from the Search response. Single-repo scans make
one extra `GET /repos/{owner}/{repo}` call.

Dependency-Track's `/bom` endpoint only sets tags when it creates a new
project. So `upload` also calls `PATCH /v1/project/{uuid}` after every
upload. Tags are replaced, not appended, so this is idempotent and fixes
drift on each re-scan.

## Parameters

Copy `samconfig.example.toml` to `samconfig.toml` (gitignored) and edit.

| Parameter | Default | Notes |
|---|---|---|
| `DbStackName` | `dependency-track-db` | Used for VPC, subnet, and SG imports. |
| `ApiserverBaseUrl` | `/dependency-track/apiserver-base-url` | SSM parameter written by `dependency-track-workload`. Resolved at deploy time. |
| `ApiserverPort` | `8081` | Apiserver host port. Used for the SG rule. |
| `SyftVersion` | `v1.18.0` | Pinned syft release. |
| `ScanMemorySizeMb` / `EphemeralStorageSizeMb` | `2048` / `2048` | Raise for very large repos. |
| `ScanTimeoutSeconds` | `300` | |
| `UploadMemorySizeMb` / `UploadTimeoutSeconds` | `512` / `60` | |
| `ListReposPageMemorySizeMb` / `ListReposPageTimeoutSeconds` | `512` / `60` | |
| `BatchScanInterRepoDelaySeconds` | `1` | Initial value of the delay SSM parameter. |
| `BatchScanExcludeRepos` | `[]` | Initial value of the exclude SSM parameter. |

No IAM role names are fixed, so CloudFormation generates them.

### SSM parameters (shared by all orgs)

| Parameter | Purpose |
|---|---|
| `/dependency-track/batch-scan/inter-repo-delay-seconds` | Seconds between repo scan kickoffs. |
| `/dependency-track/batch-scan/exclude-repos` | JSON array of `owner/repo` names to skip. |

```bash
aws ssm put-parameter --name /dependency-track/batch-scan/inter-repo-delay-seconds \
  --value "2" --type String --overwrite

# Paste the full list, not just new entries
aws ssm put-parameter --name /dependency-track/batch-scan/exclude-repos \
  --value '["example-org/empty-repo"]' --type String --overwrite
```

## Secrets

Both secrets are created empty. Fill them in after the first deploy.

**`dependency-track/syft-github-token`**: your GitHub App's credentials.
The app needs read access to repository contents and metadata, and must
be installed in each org you scan. The installation ID is looked up per
org at runtime, so adding a new org needs no change here.

```bash
aws secretsmanager put-secret-value \
  --secret-id dependency-track/syft-github-token \
  --secret-string "$(jq -n --arg id "123456" --rawfile key app.pem \
    '{app_id:$id, private_key:$key}')"
```

**`dependency-track/syft-dtrack-api-key`**: a Dependency-Track API key.
Create it in the UI under Administration → Access Management. Grant
`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, and
`PORTFOLIO_MANAGEMENT_UPDATE` (needed for tagging). Do not grant
`PORTFOLIO_MANAGEMENT_DELETE`.

```bash
aws secretsmanager put-secret-value \
  --secret-id dependency-track/syft-dtrack-api-key \
  --secret-string '{"apiKey":"odt_..."}'
```

## Deploy

Deploy `dependency-track-db` and `dependency-track-workload` first.

```bash
cp samconfig.example.toml samconfig.toml
sam build
sam deploy
```

`ApiserverBaseUrl` is resolved only at deploy time. If the workload
instance is replaced, redeploy this stack to pick up the new URL.

## Run

Get the ARNs from the stack outputs (`StateMachineArn`,
`BatchScanStateMachineArn`).

### Single repo

```bash
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:<region>:111122223333:stateMachine:dependency-track-syft-scanner \
  --input '{"repo_url":"https://github.com/example-org/example-repo","ref":"main"}'
```

`project_name` and `project_version` default to `owner/repo` and `ref`.

### Whole org

```bash
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:<region>:111122223333:stateMachine:dependency-track-batch-scan \
  --input '{"org":"example-org","limit":50}'
```

Omit `limit` to scan every match. Optional filters:
`{"property":"tier","values":["1","2"]}` (GitHub custom properties). The
exclude list comes only from SSM, not from input.

Scheduled batch scans are defined in `dependency-track-schedules`
(`BatchScanOrg1` / `BatchScanOrg2`).

## Validate

Express executions can't be described after the fact. Use logs:

```bash
aws logs tail /stepfunctions/dependency-track-batch-scan --since 10m
```

Check for failed per-repo scans:

```bash
aws stepfunctions list-executions \
  --state-machine-arn arn:aws:states:<region>:111122223333:stateMachine:dependency-track-syft-scanner \
  --status-filter FAILED
```

Then confirm the projects and tags appear in the Dependency-Track UI.

## Architecture

```
{org, limit?, property?, values?}
        │
        ▼
BatchScanStateMachine (Express)
  GetSsmConfig ◀── SSM: delay, exclude list
  FetchPage ──▶ list-repos-page ──▶ GitHub Search API
  MapRepos (concurrency 1, paced)
    └─ startExecution ──▶ ScanAndUploadStateMachine (Standard)
                            ├─ Scan ──▶ scan Lambda ──▶ GitHub tarball ──▶ syft ──▶ S3
                            └─ Upload ──▶ upload Lambda (VPC) ──▶ apiserver
                                            POST /bom, PATCH /project/{uuid}
  more pages? ── yes ──▶ startExecution on self (page + 1)
              └─ no ───▶ reportStats
```

## Gotchas

- **Empty repos fail.** Repos with no commits still report a default
  branch, so Search returns them, but the tarball download 404s. Add them
  to the exclude list.
- **Archived repos keep stale tags.** The Search query uses
  `archived:false`, so once a repo is archived it is no longer re-scanned
  and its `archived:false` tag is never updated.
- **Search API rate limit.** The authenticated limit is 30 requests per
  minute. A 2-second wait between pages keeps the batch under it.
- **No S3 lifecycle policy.** SBOMs accumulate in the artifact bucket.
  Add a lifecycle rule if volume matters.
- **Exports are reused.** `dependency-track-ghcr-scanner` imports the
  artifact bucket, upload Lambda ARN, and API key secret ARN. Deploy this
  stack first.
