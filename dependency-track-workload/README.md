# dependency-track-workload

Runs OWASP Dependency-Track as one ECS task (EC2 launch type) on one EC2
instance. Traffic arrives via a Cloudflare Tunnel gated by Cloudflare
Access. No load balancer, no inbound ports, no public IP.

## What it creates

- ECS cluster with one EC2 instance (ECS-optimized Amazon Linux 2023).
  Uses the security group from `dependency-track-db`.
- Encrypted root volume, plus a data volume mounted into `apiserver` at
  `/data`.
- Task definition (`bridge` mode) with pinned `apiserver` (host port
  8081), `frontend` (host port 8080), and `cloudflared` images.
- ECS service (desired count 1), log group `/ecs/dependency-track`.
- IAM roles for the instance (ECS + SSM Session Manager, no SSH) and
  task execution. Names are generated.
- Secret `dependency-track/cloudflare-tunnel-token`.
- SSM parameter `/dependency-track/apiserver-base-url` with the in-VPC
  apiserver URL (`http://<private-ip>:8081`).

## Design notes

- **ECS, not docker-compose.** Config lives in the task definition. User
  data only joins the cluster and mounts the volume.
- **Bridge mode.** `apiserver` and `frontend` both listen on 8080.
  Bridge mode maps them to different host ports, and container links let
  `cloudflared` reach them by name.
- **`cloudflared` is not essential.** Its token is blank on first deploy,
  so it exits. If it were essential, ECS would crash-loop the whole task.
- **SSM parameter, not an export.** The URL changes if the instance is
  replaced. An imported export can't change.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `DbStackName` | `dependency-track-db` | |
| `WorkloadAmiId` | none | Required. See below. |
| `WorkloadSubnetId` | blank | Blank = db stack's first subnet. Needs NAT. |
| `InstanceType` | `t3.xlarge` | |
| `RootVolumeSizeGb` / `DataVolumeSizeGb` | `30` / `10` | |
| `ApiserverImageTag` / `FrontendImageTag` | `5.1.0` | Keep in lockstep. |
| `CloudflaredImageTag` | pinned | |
| `CloudflareTunnelToken` | blank | Set the real token in Secrets Manager. |
| `PublicApiBaseUrl` | `http://localhost:8081` | Public apiserver URL the browser calls. |
| `Oidc*` | disabled | See [OIDC login](#oidc-login). |
| `ApiserverBaseUrlParameterName` | `/dependency-track/apiserver-base-url` | |

`WorkloadAmiId` is pinned so routine deploys don't replace the instance.
Get the current AMI for your home region:

```bash
aws ssm get-parameter \
  --name /aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id \
  --query Parameter.Value --output text
```

> **Warning:** The data volume is inline on the instance. Replacing the
> instance (new AMI, subnet, etc.) gives you an empty data volume.

## Setup and deploy

Deploy `dependency-track-db` first. Then:

```bash
cp samconfig.example.toml samconfig.toml   # gitignored; fill in values
sam build
sam deploy
```

On first boot `sam deploy` may time out waiting for the service. That
doesn't mean it failed. Check:

```bash
aws ecs describe-services --cluster dependency-track-cluster \
  --services dependency-track \
  --query "services[0].{Running:runningCount,Desired:desiredCount}"
```

## Post-deploy (first time only)

1. In Cloudflare Zero Trust, create a tunnel and copy its token. Don't
   run the install command it shows.
2. Add public hostnames to the tunnel:
   - `dtrack.example.com` → `http://frontend:8080`
   - `dtrack-api.example.com` → `http://apiserver:8080`
3. Add a Cloudflare Access application covering both hostnames.
4. Store the token:

   ```bash
   aws secretsmanager put-secret-value \
     --secret-id dependency-track/cloudflare-tunnel-token \
     --secret-string '{"token":"<token>"}'
   ```

5. Set `PublicApiBaseUrl=https://dtrack-api.example.com` and redeploy.
6. Restart the task to pick up the token:

   ```bash
   aws ecs update-service --cluster dependency-track-cluster \
     --service dependency-track --force-new-deployment
   ```

7. Log in and change the default `admin`/`admin` password.

For a shell, run `aws ssm start-session --target <InstanceId output>`.

## OIDC login

v5 uses a public SPA client (Authorization Code + PKCE). There's no
client secret, so all values are plain parameters.

1. In your IdP (e.g. Okta), create an OIDC SPA app with a redirect URI
   on `https://dtrack.example.com`.
2. Use a dedicated custom authorization server. Add a `groups` claim to
   the ID token, always included.
3. Redeploy with `OidcEnabled=true`, `OidcClientId=<client-id>`, and
   `OidcIssuer=https://example.okta.com/oauth2/<auth-server-id>`.
4. Map IdP groups to teams in **Administration → Access Management**.

Don't add `groups` to `OidcScope`. Okta rejects unknown scopes. v5 reads
`DT_OIDC_*` env vars and refuses to start on old `ALPINE_OIDC_*` names.

## Redeploying safely

- Omitted parameters revert to defaults. Keep `samconfig.toml` complete.
- Don't change `CloudflareTunnelToken`. A new value overwrites the real
  token in Secrets Manager.
- Pin image tags explicitly. On Docker Hub, `:latest` still points at
  v4. `ghcr.io` is the primary registry for v5+.
- If the instance is replaced, its private IP changes. Redeploy
  `dependency-track-syft-scanner` and
  `dependency-track-inspector-sbom-catcher`. They read the SSM parameter
  only at deploy time.

## Gotchas

- **ECS agent stuck after boot.** If 0 tasks run for a few minutes,
  start a session and run `sudo systemctl start ecs`.
- **Tunnel needs 7844.** `cloudflared` needs outbound 7844/udp and
  7844/tcp, not just 443. The stack adds these rules.
- **Bot protection.** A new hostname without an Access app in front may
  be challenged by bot protection. Adding the Access app fixes it.

## Architecture

```
Internet ──▶ Cloudflare Access ──▶ Cloudflare Tunnel
                                         │
                               ┌─────────┴─────────┐
                               │  EC2 / ECS bridge │
                               │  cloudflared ─────┼──▶ frontend:8080
                               │                ───┼──▶ apiserver:8080
                               └─────────┬─────────┘
                                         │ 5432/tcp
                                         ▼
                              dependency-track-db (RDS)
```
