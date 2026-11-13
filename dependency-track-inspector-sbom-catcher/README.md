# dependency-track-inspector-sbom-catcher

Uploads Amazon Inspector SBOM exports to Dependency-Track. When an
SBOM object lands in either region's export bucket, this stack reads
it, derives a project name, version, and tags, and posts it to
`/api/v1/bom`.

Deploy it once, in the home region (the region where Dependency-Track
runs).

It is a separate stack from `dependency-track-syft-scanner`, so the
Inspector-specific code stays apart. It reuses that stack's DT API key
secret and the `dependency-track-db` VPC wiring through
`Fn::ImportValue`. No secrets or VPC config are duplicated.

## Resources

- **`CatcherFunction`** (Lambda, container image). Attached to the
  workload subnets with its own security group. That group can reach
  the workload security group on the apiserver port. The function reads
  the S3 object, parses the CycloneDX SBOM, and uploads it.
- **`CatcherStateMachine`** (Express Step Functions). One Task state
  that invokes the Lambda, with retries on transient Lambda errors. It
  exists for retries and execution history. The Lambda does the work.
- **`SbomObjectCreatedRule`** (EventBridge). Matches S3 `Object Created`
  events from the home and remote buckets, and starts the state
  machine.

## Why one region

The Lambda must be in the VPC to reach the apiserver's private
address. A Lambda can only attach to a VPC in its own region. So the
catcher runs in the home region only.

Remote-region bucket events reach it through a cross-region EventBridge
forward. That forward is defined in the remote region's
`dependency-track-inspector-sbom` stack.

The object still lives in the remote region. The Lambda creates its S3
client with the event's `region` field, which keeps the origin region
after forwarding. If the event has no region, it falls back to
`AWS_REGION`.

```
 remote-region bucket          home-region bucket
         │ cross-region forward        │ native
         └──────────────┬──────────────┘
                        ▼
            home-region default event bus
                        ▼
          SbomObjectCreatedRule → CatcherStateMachine
                        ▼
          CatcherFunction (VPC-attached)
                        ▼
          Dependency-Track apiserver (/api/v1/bom)
```

## Project naming and tags

Inspector SBOMs carry their identity in `metadata.properties` as
`amazon:inspector:*` pairs. The shape is the same for EC2, ECR, and
Lambda.

| Resource type | `projectName` | `projectVersion` |
|---|---|---|
| `AWS_EC2_INSTANCE` | `{accountId}/{instanceId}` | `metadata.component.version` (the OS build, e.g. `2023` for Amazon Linux 2023) |
| `AWS_ECR_CONTAINER_IMAGE` | `{accountId}/{repoName}` | image digest (`sha256:...`) |
| `AWS_LAMBDA_FUNCTION` | `{accountId}/{functionName}` | runtime (e.g. `PYTHON_3_13`) |

Why these choices:

- The account prefix is needed. Repo and function names can repeat
  across accounts.
- ECR uses the digest because tags can move. Digests do not.
- Lambda uses the runtime, not the ARN qualifier. Most functions run
  only `$LATEST`, so the qualifier says nothing.
- EC2 uses the OS build from the SBOM. Looking up the AMI ID would
  need cross-account access to every member account.
- An OS build change creates a new project version. This is expected.

Every upload sets these tags:

```
resourcetype:aws_ec2_instance,accountid:111122223333,region:<region>,sbomsource:inspector
```

Extra tags by type:

- **EC2 / ECR:** `os:{metadata.component.name}` (e.g. `os:bottlerocket`).
  For ECR this field is often missing and sometimes wrong. It is a
  best-effort tag only.
- **ECR:** `architecture:{arch}` (e.g. `architecture:amd64`).
- **Lambda:** `runtime:{runtime}`. This repeats the version so you can
  filter by tag.

Dependency-Track lowercases tags. The catcher sends them lowercase
already.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `DbStackName` | `dependency-track-db` | VPC, subnet, and workload SG imports |
| `SyftScannerStackName` | `dependency-track-syft-scanner` | Imports `DtApiKeySecretArn` |
| `LocalExportStackName` | `dependency-track-inspector-sbom` | Home-region export stack. Bucket and key are imported via `Fn::ImportValue` |
| `RemoteSbomBucketArn` | — | Copy from the remote export stack's `SbomBucketArn` output |
| `RemoteSbomKmsKeyArn` | — | Copy from the remote export stack's `SbomKmsKeyArn` output |
| `ApiserverBaseUrl` | `/dependency-track/apiserver-base-url` | SSM parameter written by `dependency-track-workload` |
| `ApiserverPort` | `8081` | Used for the security group rules |
| `CatcherMemorySizeMb` | `512` | |
| `CatcherTimeoutSeconds` | `60` | |

`Fn::ImportValue` cannot cross regions. That is why the remote bucket
and key are plain parameters.

The stack does not set a fixed IAM role name.

## Deploy

```bash
cp samconfig.example.toml samconfig.toml   # gitignored; fill in values
sam build
sam deploy
```

## Validate

Trigger an Inspector SBOM export in either region, then:

```bash
aws logs tail /stepfunctions/dependency-track-inspector-sbom-catcher --region <home-region> --since 10m
```

A successful run returns something like:

```json
{"status":"uploaded","projectName":"111122223333/i-...","projectVersion":"2023","tags":"resourcetype:aws_ec2_instance,accountid:111122223333,region:<region>,sbomsource:inspector,os:amazon_linux_2023"}
```

Then check the project in the Dependency-Track UI.

## Gotchas

- **Apiserver URL is resolved at deploy time.** If the workload
  instance is replaced, redeploy this stack to pick up the new URL.
- **Remote bucket or key replaced?** Copy the new ARNs into
  `RemoteSbomBucketArn` / `RemoteSbomKmsKeyArn` and redeploy. They do
  not sync on their own.
- **Some EC2 SBOMs fail DT schema validation.** Inspector sometimes
  emits components with no `type`/`name`, or duplicate
  `vulnerabilities[].affects` entries. The catcher strips these for
  EC2 SBOMs before upload. ECR and Lambda SBOMs are sent unchanged.
- **Concurrency is capped** (`ReservedConcurrentExecutions: 15`). A
  large org-wide export can fire thousands of events at once. With no
  cap, DT returns HTTP 409 errors. With too low a cap, Lambda
  throttling exhausts the state machine retries. The right value
  depends on burst size. Retune if a bigger export starts failing.
- **HTTP 500 on every upload** usually means the apiserver can't reach
  its database. Check the RDS instance's storage and status.
- Non-SBOM objects and folder markers are skipped. Only keys ending in
  `_CYCLONEDX_1_4.json` are processed.
- No dead-letter queue. A run that fails after retries is only visible
  in the state machine logs.
- New Inspector resource types need a code change in `catcher/app.py`.
