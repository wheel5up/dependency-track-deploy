# dependency-track-db

RDS PostgreSQL for Dependency-Track, plus the security groups that this
stack and `dependency-track-workload` use. Deploy it first, in the home
region.

## What it creates

- RDS PostgreSQL 15 (gp3, encrypted, storage autoscaling, 7-day backups,
  not public, single-AZ).
- A Secrets Manager secret `dependency-track/db-credentials` with a
  generated password.
- An RDS security group that allows 5432 only from the workload SG.
- The workload security group. It lives here, not in the workload stack,
  so the RDS ingress rule can reference it. It starts with no egress; the
  workload stack adds its egress rules.

It uses an existing VPC and two private (NAT-routed) subnets. It creates
no VPC, subnets, or NAT.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `VpcId` | — | Existing VPC |
| `DbSubnetId1` / `DbSubnetId2` | — | Private subnets in two AZs. Subnet 1 is also the default workload subnet |
| `DbSnapshotIdentifier` | blank | Snapshot ARN to restore from. See below |
| `DbName` / `DbMasterUsername` | `dtrack` | |
| `DbInstanceClass` | `db.t3.medium` | |
| `DbAllocatedStorage` | `40` | GB. Can only grow |
| `DbMaxAllocatedStorage` | `100` | Autoscaling ceiling in GB |

## Deploy

```bash
cp samconfig.example.toml samconfig.toml   # fill in parameters
sam build
sam deploy
```

## Outputs

Exported as `<stack-name>-<Output>`: `VpcId`, `WorkloadSubnet1Id`,
`WorkloadSubnet2Id`, `WorkloadSecurityGroupId`, `RdsSecurityGroupId`,
`RdsEndpoint`, `RdsPort`, `DbSecretArn`. The workload, syft-scanner, and
catcher stacks import them.

## Gotchas

- **Restoring from a snapshot:** set `DbSnapshotIdentifier` on the first
  deploy. Never change or clear it later, or CloudFormation replaces the
  database. The restored DB keeps the snapshot's master password, so
  update the secret to match. `DbAllocatedStorage` must be at least the
  snapshot's size.
- **Storage only grows.** Keep `DbAllocatedStorage` at or above the live
  size, since autoscaling may have raised it. Most growth is daily
  component metrics; size against `metrics.retention.days`.
- **`DeletionProtection` is off.** Turn it on before holding real data.
  Deleting or replacing the instance still takes a final snapshot.
- Deploy this stack before the others. Stacks that import its outputs
  block changes to those outputs.
