# dependency-track-ghcr-scanner

Scans container images in GitHub Container Registry (GHCR) with `syft` and uploads the SBOMs to Dependency-Track.

> **This stack is optional.** It needs a [Cartography](https://github.com/cartography-cncf/cartography) Neo4j instance in the same VPC, and Cartography must be ingesting Kubernetes data. It reads two SSM parameters from your Cartography deployment:
>
> - `/cartography/neo4j/private-ip`: Neo4j's private IP
> - `/cartography/sg/neo4j`: Neo4j's security group ID
>
> The stack **adds an ingress rule** (TCP 8443, Bolt) to that Neo4j security group. It does not change or remove existing rules.

Amazon Inspector can't scan GHCR. This stack fills that gap. It extends `dependency-track-syft-scanner` and reuses that stack's `UploadFunction` and `ArtifactBucket` (SBOMs go under the `ghcr-sboms/` prefix).

## What it deploys

- **`DiscoveryFunction`** (VPC Lambda). Queries Neo4j for every distinct `ghcr.io` image running in Kubernetes. Writes the list as JSON to an SSM parameter (`/dependency-track/ghcr-scan/image-list`).
- **`ScanFunction`** (VPC Lambda with `syft`). Takes one `{"image": "ghcr.io/..."}`, runs `syft registry:<image> --platform linux/amd64`, and writes the CycloneDX SBOM to S3.
- **`ScanAllStateMachine`** (Step Functions, Standard). Runs `Discover` → `GetImageList` → `ScanAll`. `ScanAll` is a Map over every image (`MaxConcurrency: 1`) that runs `Scan` then the syft-scanner's `Upload`.

## Prerequisites

- `dependency-track-db` deployed (VPC and subnet exports).
- `dependency-track-syft-scanner` deployed (`UploadFunctionArn` and `ArtifactBucketName` exports).
- Cartography Neo4j reachable from the workload subnets, with the two SSM parameters above.
- Neo4j reachable over Bolt on port 8443 **without auth**. `DiscoveryFunction` connects with `auth=None`. If your Neo4j needs credentials, update `discovery/app.py`.
- A GitHub **classic PAT** with `read:packages` (see below).

## Design notes

- **Why a classic PAT.** GitHub App installation tokens can't use the Packages API. A classic PAT with `read:packages` is required. The same PAT is used as the registry password (`SYFT_REGISTRY_AUTH_*` env vars, username `x-access-token`).
- **Why `registry:` mode.** syft pulls only the layers it needs over HTTPS. No Docker daemon, no full image download.
- **Why `--platform linux/amd64`.** Some images are multi-arch indexes and fail without a platform. The flag is a no-op for single-arch images.
- **Why unfiltered.** The Neo4j query has no org filter. Third-party images running in your clusters are still your exposure, so they're scanned too.
- **Why an SSM list.** Map states need the item list in state. Writing it to SSM also lets you inspect the current list between runs.
- **Why SSM Advanced tier.** A full image list can easily exceed Standard's 4 KB limit. Advanced allows 8 KB, keeps version history, and needs no extra resources.
- **Why Standard, not Express.** Each Map iteration blocks on Scan and Upload. A full run can take far longer than Express's 5-minute cap.
- **Tags as versions.** `project_version` is the image tag as found in Kubernetes, not a resolved digest.
- **Concurrency 1.** A safe starting point. The DT `/api/v1/bom` endpoint is shared with other pipelines and can return `409` under heavy concurrent load.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `SyftScannerStackName` | `dependency-track-syft-scanner` | Source of `UploadFunctionArn` / `ArtifactBucketName` exports |
| `DbStackName` | `dependency-track-db` | Source of VPC and subnet exports |
| `Neo4jSecurityGroupSsmParameterName` | `/cartography/sg/neo4j` | SG that gets the new ingress rule |
| `ImageListSsmParameterName` | `/dependency-track/ghcr-scan/image-list` | Created by this stack (Advanced tier) |
| `DiscoveryMemorySizeMb` / `DiscoveryTimeoutSeconds` | `256` / `60` | |
| `ScanMemorySizeMb` / `ScanTimeoutSeconds` | `2048` / `300` | |
| `ScanEphemeralStorageSizeMb` | `2048` | `/tmp` for syft's layer cache |
| `SyftVersion` | `v1.18.0` | Keep in sync with `dependency-track-syft-scanner` |

The Neo4j IP SSM name (`/cartography/neo4j/private-ip`) is hardcoded in `template.yaml`. SAM transforms don't allow a CloudFormation parameter inside a `{{resolve:ssm:...}}` reference.

## Deploy

```bash
cp samconfig.example.toml samconfig.toml   # gitignored; set region
sam build
sam deploy
```

## Secret setup

The stack creates `dependency-track/ghcr-packages-pat` with an empty
token. After the first deploy, set it to a classic PAT with
`read:packages`:

```bash
aws secretsmanager put-secret-value \
  --secret-id dependency-track/ghcr-packages-pat \
  --secret-string '{"token": "<classic PAT>"}'
```

Until then, `ScanFunction` fails at runtime. The secret is deleted with
the stack.

## Run

Full run (refresh the list from Cartography, then scan everything):

```bash
aws stepfunctions start-execution \
  --state-machine-arn <StateMachineArn output> \
  --input '{}'
```

Test specific images (skips `Discover`, leaves the SSM list untouched):

```bash
aws stepfunctions start-execution \
  --state-machine-arn <StateMachineArn output> \
  --input '{"images": ["ghcr.io/example-org/example-image:1.2.3"]}'
```

An empty or missing `images` array runs the normal full path.

There is no schedule. Add an EventBridge rule if you want one, staggered from your other scan schedules.

## Validate

```bash
aws logs tail /aws/vendedlogs/states/dependency-track-ghcr-scanner --since 10m
aws logs tail /aws/lambda/dependency-track-ghcr-scanner-scan --since 10m
aws ssm get-parameter --name /dependency-track/ghcr-scan/image-list \
  --query Parameter.Value --output text | python3 -m json.tool
```

Then check Dependency-Track for projects named `<owner>/<repo>` with the image tag as the version.

## Gotchas

- **Discovery times out.** Check the Neo4j SG ingress rule and that Neo4j is in the same VPC as the workload subnets.
- **Empty image list.** Cartography isn't ingesting Kubernetes data, or no `ghcr.io` images are running.
- **`no child with platform ...`.** A multi-arch image without an amd64 variant. Not supported as-is.
- **401/403 from ghcr.io.** The PAT is missing `read:packages`, is expired, or lacks access to that org's packages (SSO authorization may be required).
- **Every run is a full rescan.** Each new image tag creates a new DT project version. Old versions aren't cleaned up.

## Keeping syft in sync

`SyftVersion` here should match `dependency-track-syft-scanner`. Nothing enforces it. Bump both together so SBOMs from both pipelines look the same.
