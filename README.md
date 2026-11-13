# Dependency-Track on AWS

AWS SAM stacks that run [OWASP Dependency-Track](https://dependencytrack.org/)
on ECS (EC2 launch type) in an existing VPC, plus pipelines that feed it
SBOMs automatically:

- **GitHub repos**: syft generates an SBOM per repo, for one repo or a
  whole org.
- **AWS resources**: Amazon Inspector exports SBOMs for EC2, ECR and
  Lambda, and a catcher uploads them.
- **GHCR images** (optional): syft scans `ghcr.io` images that
  [Cartography](https://github.com/cartography-cncf/cartography) sees
  running in Kubernetes.

The templates create no VPC, subnets, IGW or NAT. You supply an existing
VPC with two private, NAT-routed subnets. Public access is through a
Cloudflare Tunnel (outbound only), so nothing needs inbound internet
access.

## Stacks

| Stack | Region | Purpose |
|---|---|---|
| [`dependency-track-db`](dependency-track-db/README.md) | home | RDS PostgreSQL and the shared security groups |
| [`dependency-track-workload`](dependency-track-workload/README.md) | home | ECS on one EC2 instance: frontend, apiserver, cloudflared |
| [`dependency-track-syft-scanner`](dependency-track-syft-scanner/README.md) | home | GitHub repo → syft SBOM → Dependency-Track, single repo or whole org |
| [`dependency-track-inspector-sbom`](dependency-track-inspector-sbom/README.md) | every Inspector region | Starts Amazon Inspector SBOM exports into a regional bucket |
| [`dependency-track-inspector-sbom-catcher`](dependency-track-inspector-sbom-catcher/README.md) | home | Uploads exported SBOMs from every region to Dependency-Track, with tags |
| [`dependency-track-schedules`](dependency-track-schedules/README.md) | every Inspector region | EventBridge schedules for the batch scan (home only) and Inspector exports |
| [`dependency-track-ghcr-scanner`](dependency-track-ghcr-scanner/README.md) | home | Optional. Needs Cartography's Neo4j in the same VPC |

"Home" is the region where Dependency-Track runs. "Remote" is any other
region where you want Inspector SBOMs.

## How the stacks connect

```
                      ┌─────────────────────┐
                      │ dependency-track-db │  RDS, workload SG, RDS SG
                      └──────────┬──────────┘
                                 │ exports: VpcId, WorkloadSubnet1/2Id,
                                 │ WorkloadSecurityGroupId, DbSecretArn
          ┌──────────────────────┼─────────────────────────┐
          ▼                      ▼                         ▼
┌───────────────────┐  ┌───────────────────┐  ┌─────────────────────────┐
│ workload          │  │ syft-scanner      │  │ inspector-sbom-catcher  │
│ ECS + EC2         │◀─│ scan/upload/batch │◀─│ catcher Lambda (VPC)    │
│ apiserver, UI,    │  │ Lambdas           │  │                         │
│ cloudflared       │  └───────────────────┘  └────────────▲────────────┘
└─────────┬─────────┘                                      │ S3 ObjectCreated
          │ writes SSM /dependency-track/apiserver-base-url │ (home default bus)
          ▼                                                │
   read by syft-scanner and catcher at deploy time         │
                                    ┌──────────────────────┴───────────┐
                                    │                                  │
                      ┌─────────────┴────────────┐  ┌──────────────────┴─────┐
                      │ inspector-sbom (home)    │  │ inspector-sbom (remote) │
                      │ Inspector export → S3    │  │ Inspector export → S3   │
                      │ events land natively     │  │ rule forwards events    │
                      └──────────────────────────┘  │ to the home bus         │
                                                    └─────────────────────────┘
```

## Deploy order

Each stack after the first imports exports from an earlier one, so the
order matters.

1. **`dependency-track-db`.** It owns the workload security group as well
   as the RDS one. That avoids a circular dependency: the RDS ingress rule
   references the workload SG, and the workload stack attaches it.
2. **`dependency-track-workload`.** Imports the VPC, subnet, SG and DB
   secret. Writes the apiserver's in-VPC URL to SSM
   (`/dependency-track/apiserver-base-url`). Then do the Cloudflare Tunnel
   steps in its README.
3. **`dependency-track-syft-scanner`.** Reads the apiserver URL from SSM.
   Set its two secrets (GitHub token, DT API key) after the first deploy.
4. **`dependency-track-inspector-sbom`**, once per region. Independent of
   the other stacks. Remote regions forward bucket events to the home
   region's default event bus.
5. **`dependency-track-inspector-sbom-catcher`.** Imports the home export
   stack's bucket/key and syft-scanner's DT API key secret. The remote
   bucket and key ARNs are plain parameters, because `Fn::ImportValue`
   can't cross regions.
6. **`dependency-track-schedules`**, once per region.
7. **`dependency-track-ghcr-scanner`** (optional).

Each stack directory has a `samconfig.example.toml`. Copy it to
`samconfig.toml` (gitignored) and fill in the placeholders.

```bash
for s in db workload syft-scanner; do
  (cd dependency-track-$s && sam build && sam deploy)
done

(cd dependency-track-inspector-sbom && sam build && sam deploy && sam deploy --config-env remote)
(cd dependency-track-inspector-sbom-catcher && sam build && sam deploy)
(cd dependency-track-schedules && sam build && sam deploy && sam deploy --config-env remote)
```

The apiserver URL is resolved when syft-scanner and the catcher deploy.
If the workload instance is replaced, redeploy both.

### Dependency table

| Stack | Depends on | How | Values |
|---|---|---|---|
| `workload` | `db` | `Fn::ImportValue` | `VpcId`, `WorkloadSubnet1/2Id`, `WorkloadSecurityGroupId`, `DbSecretArn` |
| `syft-scanner` | `db` | `Fn::ImportValue` | VPC/subnet/SG |
| `syft-scanner` | `workload` | SSM parameter | `/dependency-track/apiserver-base-url` |
| `inspector-sbom` (remote) | home region | plain parameter | `CatcherEventBusArn` (the home default bus) |
| `catcher` | `db` | `Fn::ImportValue` | VPC/subnet/SG |
| `catcher` | `syft-scanner` | `Fn::ImportValue` | `DtApiKeySecretArn` |
| `catcher` | `workload` | SSM parameter | `/dependency-track/apiserver-base-url` |
| `catcher` | `inspector-sbom` (home) | `Fn::ImportValue` | `SbomBucketArn`, `SbomBucketName`, `SbomKmsKeyArn` |
| `catcher` | `inspector-sbom` (remote) | plain parameters | `RemoteSbomBucketArn`, `RemoteSbomKmsKeyArn` |
| `schedules` | `syft-scanner`, `inspector-sbom` (same region) | `Fn::ImportValue` | state machine ARNs |

## The SBOM pipelines

| | GitHub repos (`syft-scanner`) | AWS resources (`inspector-sbom` + `catcher`) |
|---|---|---|
| Source | GitHub Search API (org) or one repo URL | Amazon Inspector (EC2, ECR, Lambda) |
| Trigger | Schedule or manual `start-execution` | Schedule or manual export, then automatic (S3 event → catcher) |
| SBOM generator | syft (in Lambda) | Amazon Inspector |
| Format | CycloneDX | CycloneDX |
| Project tags | `org`, `repo`, `visibility`, `fork`, `archived`, `language`, `sbomsource:syft` (updated every run) | `resourcetype`, `accountid`, `region`, `sbomsource:inspector` (set at creation) |

## Why Inspector needs a stack per region

Amazon Inspector has no cross-region aggregation. A delegated
administrator sees every account in a region, but only that region. SBOM
export also requires the bucket and KMS key to be in the same region as
the export. So each region gets its own export stack, and remote regions
forward their bucket events to the home region's default event bus,
where the single catcher runs.

## Sizing

- **Database:** most growth is Dependency-Track's daily component
  metrics. Size storage against `metrics.retention.days` (Administration →
  Configuration). With thousands of projects, 30 days is a reasonable
  start. RDS storage autoscaling is on, up to `DbMaxAllocatedStorage`.
- **RDS CPU** is the tighter resource during batch scans. `db.t3.medium`
  handles a few thousand projects.
- **Workload:** `t3.xlarge` by default. Peak usage is well below that,
  so `t3.large` is likely enough.

## Known quirks

- GitHub's Search API excludes forks by default. syft-scanner adds
  `fork:true`.
- CloudFormation `Description` fields are limited to 1024 characters.
  Keep template descriptions short and put detail in comments.
- If a bot-protection service sits in front of your domain, a new
  hostname without an access policy may be challenged. Put Cloudflare
  Access (or similar) in front of both hostnames.
