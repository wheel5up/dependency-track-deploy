# dependency-track-schedules

Daily EventBridge rules that start other stacks' pipelines.

Deploy one stack per Inspector region. Each stack is named
`dependency-track-schedules`.

- **Every region:** three Amazon Inspector SBOM export rules (EC2,
  Lambda, ECR). They start the `dependency-track-inspector-sbom` state
  machine in the same region.
- **Home region only:** up to two GitHub org batch-scan rules. They
  start `dependency-track-syft-scanner`'s `BatchScanStateMachine`.

## What it creates

### Inspector SBOM export rules (every region)

| Rule | Default schedule | Input |
|---|---|---|
| `dependency-track-inspector-sbom-export-ec2-daily` | `cron(0 6 * * ? *)` | `{"resourceType": "AWS_EC2_INSTANCE"}` |
| `dependency-track-inspector-sbom-export-lambda-daily` | `cron(30 6 * * ? *)` | `{"resourceType": "AWS_LAMBDA_FUNCTION"}` |
| `dependency-track-inspector-sbom-export-ecr-daily` | `cron(0 7 * * ? *)` | `{"resourceType": "AWS_ECR_CONTAINER_IMAGE"}` |

- There is no `accountId` filter. If this account is the Inspector
  delegated administrator, each export covers every member account in
  that region.
- One IAM role lets EventBridge call `states:StartExecution` on that
  state machine only.
- The rules are staggered by 30 minutes. One org-wide export can send
  a large burst of SBOMs to the shared catcher Lambda and the
  Dependency-Track API server. Running them at the same time would stack
  those bursts.

### GitHub batch-scan rules (home region only)

- Created only when `DeployBatchScanRules=true`.
- Rule names: `dependency-track-batch-scan-<org>-daily`.
- `BatchScanOrg1` is required. `BatchScanOrg2` is optional; leave it
  blank to skip the second rule.
- Input is `{"org": "<org>"}`. There is no `limit`, so the full org is
  scanned each run.
- Both rules share `ScheduleExpression`. They are not staggered,
  because the state machine already runs one repo at a time.
- The exclude list and delay between repos live in SSM. The state
  machine reads them; see `dependency-track-syft-scanner/README.md`.
- One IAM role lets EventBridge start only the batch-scan state machine.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `SyftScannerStackName` | `dependency-track-syft-scanner` | Import source for the batch-scan state machine. Used only when batch-scan rules are on. |
| `ScheduleExpression` | `cron(0 6 * * ? *)` | Shared by both batch-scan rules. |
| `DeployBatchScanRules` | `"false"` | `"true"` in the home region only. |
| `BatchScanOrg1` | `""` | Required when batch-scan rules are on, e.g. `example-org`. |
| `BatchScanOrg2` | `""` | Optional second org. |
| `InspectorSbomStackName` | `dependency-track-inspector-sbom` | Inspector stack name **in the same region**. |
| `Ec2ScheduleExpression` | `cron(0 6 * * ? *)` | EC2 export. |
| `LambdaScheduleExpression` | `cron(30 6 * * ? *)` | Lambda export. |
| `EcrScheduleExpression` | `cron(0 7 * * ? *)` | ECR export. |

## Deploy

Copy the example config. `samconfig.toml` is gitignored.

```bash
cp samconfig.example.toml samconfig.toml   # then fill in your values
sam build
sam deploy                         # home region, DeployBatchScanRules=true
sam deploy --config-env remote     # remote region, DeployBatchScanRules=false
```

## Check or disable schedules

```bash
# List rules and their state
aws events list-rules --name-prefix dependency-track- --region <region>

# Pause a rule
aws events disable-rule --name dependency-track-inspector-sbom-export-ecr-daily --region <region>

# Resume it
aws events enable-rule --name dependency-track-inspector-sbom-export-ecr-daily --region <region>
```

EventBridge has no "run now" button for scheduled rules. To test, start
the target state machine by hand with the same input:

```bash
aws stepfunctions start-execution \
  --state-machine-arn <batch-scan-state-machine-arn> \
  --input '{"org": "example-org"}' --region <home-region>
```

Or set the rule to a one-off cron a few minutes ahead, watch it fire,
then put the original schedule back.

## Gotchas

- `Fn::ImportValue` can't cross regions. That is why the batch-scan
  rules exist only in the home region, and why `InspectorSbomStackName`
  must name the same-region stack.
- Changes made with `put-rule`, `disable-rule`, or `enable-rule` live
  outside CloudFormation. The next `sam deploy` may reset them to the
  template values.
- Deploy the target stacks first. The imports fail if their exports
  don't exist yet.
- There is no alert if a scheduled run fails to start. Check the
  CloudWatch metrics for the rules (`FailedInvocations`) or the state
  machine logs.
