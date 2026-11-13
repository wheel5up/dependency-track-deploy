# dependency-track-inspector-sbom

Starts an [Amazon Inspector SBOM export](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html)
for EC2, ECR, and Lambda resources. Inspector writes CycloneDX SBOMs to an
S3 bucket in the same region.

## Why one stack per region

Inspector is regional. The export's S3 bucket and KMS key must be in the
same region as the export. So you deploy this template once per region.
Every stack uses the same name: `dependency-track-inspector-sbom`.

- **Home region** — where Dependency-Track and the catcher stack run.
  Bucket events land on the home default event bus natively.
  Set `DeployCrossRegionForward=false`.
- **Remote regions** — set `DeployCrossRegionForward=true`. This creates
  `ForwardToHomeRule`, which forwards the bucket's S3 `Object Created`
  events to the home region's default bus.

```
remote region                         home region
S3 bucket ──ForwardToHomeRule──────▶  default event bus ◀── S3 bucket (native)
                                              │
                                              ▼
                              dependency-track-inspector-sbom-catcher
                                              │
                                              ▼
                              Dependency-Track (/api/v1/bom)
```

The catcher lives in its own stack. See
`../dependency-track-inspector-sbom-catcher/README.md`.

## What it creates

- **S3 bucket** — public access blocked, SSE-KMS, EventBridge
  notifications on.
- **Bucket policy** — lets `inspector2.amazonaws.com` call `s3:PutObject`,
  `s3:PutObjectAcl`, and `s3:AbortMultipartUpload`. Scoped by
  `aws:SourceAccount` and `aws:SourceArn` to this account's Inspector
  reports in this region.
- **KMS key + alias** — root account admin, plus `kms:Decrypt` and
  `kms:GenerateDataKey*` for Inspector, scoped the same way.
- **Express state machine** — one Task state calling
  `inspector2:CreateSbomExport` through the Step Functions AWS SDK
  integration. No Lambda.
- **`ForwardToHomeRule`** and its IAM role — remote regions only.

### Design choices

- **Express, no Lambda.** It is a single API call. JSONata builds the
  request inline.
- **Fire-and-forget.** The execution only starts the export and returns a
  `reportId`. It does not poll `GetSbomExport`. Exports can take minutes,
  and S3 + EventBridge already signal when files land.

## Parameters

| Name | Default | Notes |
|---|---|---|
| `SbomBucketName` | — (required) | e.g. `<prefix>-inspector-sboms-<region>` |
| `SbomKmsKeyAliasName` | `alias/inspector-sbom-export` | Aliases are regional, so one name works everywhere. |
| `DeployCrossRegionForward` | `true` | `false` in the home region. |
| `CatcherEventBusArn` | `unused` | Remote regions: `arn:aws:events:<home-region>:<account-id>:event-bus/default` |

## Deploy

```bash
cp samconfig.example.toml samconfig.toml   # gitignored; fill in your values
sam build
sam deploy                         # home region
sam deploy --config-env remote     # remote region
```

## Run an export

```bash
# EC2 instances in one account
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:<region>:111122223333:stateMachine:dependency-track-inspector-sbom-export \
  --input '{"resourceType":"AWS_EC2_INSTANCE","accountId":"111122223333"}' \
  --region <region>

# Unfiltered (all resource types)
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:<region>:111122223333:stateMachine:dependency-track-inspector-sbom-export \
  --input '{}' \
  --region <region>
```

Input fields (all optional):

- `resourceType`: `AWS_EC2_INSTANCE`, `AWS_ECR_CONTAINER_IMAGE`, or
  `AWS_LAMBDA_FUNCTION`
- `accountId`

Conditions within a field are OR'd. Conditions across fields are AND'd.
Other `resourceFilterCriteria` fields are not wired up yet.

If the account is an Inspector delegated administrator, an empty filter
covers every member account in that region.

## Validate

```bash
aws inspector2 get-sbom-export --report-id <reportId> --region <region>
aws s3 ls s3://<prefix>-inspector-sboms-<region>/ --recursive
```

An empty filter finishes in seconds. A few EC2 instances take about two
minutes.

## Gotchas

- **Same region.** The bucket and KMS key must be in the export's region.
- **Policies must allow Inspector.** Both the bucket policy and the KMS
  key policy need the `inspector2.amazonaws.com` statements above.
  Missing either one fails the export.
- **Description limit.** CloudFormation template and parameter
  `Description` fields max out at 1024 characters.
- **SDK integration casing.** Step Functions AWS SDK tasks use PascalCase
  parameters (`ReportFormat`, `S3Destination`), even though the Inspector
  API is camelCase.
- **Don't forward in the home region.** It would duplicate every catcher
  trigger.
- **No explicit IAM role names.** Roles are global. Fixed names would
  collide across the per-region stacks.
