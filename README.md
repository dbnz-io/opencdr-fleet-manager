# OpenCDR Fleet Manager

An optional Serverless management service deployed in your organization's **AWS
security account**. Use it when managing multiple OpenCDR Core deployments.
Single-agent operators can continue connecting directly to Core.

Fleet Manager polls enabled agents every minute, caches their reported status and
configuration, and forwards explicitly requested API calls. It does not deploy
Core stacks, create cross-account IAM roles, execute its own incident response, or
continuously enforce a desired configuration. Core remains authoritative.

```mermaid
flowchart LR
  Clients[Web / opencdr-deploy / MCP] -->|Multi-account API operations| Fleet[Fleet Manager in security account]
  Fleet -->|Core API reads and explicit writes| Agents[Core agents in member accounts]
  Timer[One-minute schedule] --> Queue[Poll queue]
  Queue --> Poll[Read-only poll workers]
  Poll --> Agents
  Poll --> Status[(Agent status)]
  Poll --> Cache[(Configuration snapshots)]
  Fleet --> Registry[(Agent registry)]
  Fleet --> Status
  Fleet --> Cache
```

## What is included

- A registry keyed by agent ID, with unique account/region/stage identities,
  enable/disable controls and revision-guarded updates.
- A status table with reported Core version, capabilities, security profile,
  archive/tracing flags when reported, evaluator state, timestamps, errors,
  polling request counts and API quota warnings.
- Complete paginated snapshots of rules, active reusable lists with their values,
  registered notification profiles, responder mappings, parser catalog and known
  integration bindings. Notification credentials are additionally redacted locally.
- Snapshot deduplication, chunking for large lists, pinned pagination and TTL
  expiration. Failed collections retain the last complete snapshot.
- A live, identity-checked Core API proxy, including a bounded multi-agent API.
  Agent HTTP status codes and partial-write details are preserved. Writes are not retried.
- Separate read and write agent credentials in security-account SSM SecureString
  parameters. Poll workers cannot read write credentials.
- AWS IAM/SigV4 authorization on every fleet API endpoint. No new IAM users or
  permanent AWS access keys are needed.
- Packaging from an explicit runtime allowlist, hashed Python dependencies,
  pinned Serverless tooling, CI and an account-checked deployment script.

This repository implements the service. OpenCDR Deploy provides its installed
operational CLI, and compatible web/MCP clients use explicit fleet connection
adapters. Existing direct-Core connections are never silently redirected.
Cases, triage, assignments and approvals are not migrated into this first release.

## Install the Python package

```bash
python -m pip install opencdr-fleet-manager
python -c "import opencdr_fleet; print(opencdr_fleet.__version__)"
```

The PyPI package provides the Python service modules. For AWS deployment and
operator commands, use the matching source release and the Serverless workflow
below. The source distribution also includes the deployment templates, operator
scripts and locked requirements.

## Install and manage the service

Use **OpenCDR Deploy 0.6.0+** as the user-facing CLI. It links to this repository
and manages the source checkout, locked build tools and Serverless deployment for
you. You can run it from any directory; no manual fleet-manager clone or `scripts/`
path is needed.

```bash
python -m pip install --upgrade 'opencdr-deploy>=0.6.0'
aws sso login --profile security-admin
opencdr-deploy fleet deploy security-prod \
  --profile security-admin --security-account-id 222222222222 \
  --region us-east-1 --stage prod \
  --package-only --output /tmp/opencdr-fleet-reviewed
```

Review `/tmp/opencdr-fleet-reviewed/cloudformation-template-update-stack.json`.
**`--package-only` builds local artifacts and does not create a stack.** Deploy
that exact package and check the live manager:

```bash
opencdr-deploy fleet deploy security-prod --artifact /tmp/opencdr-fleet-reviewed
opencdr-deploy fleet status --fleet security-prod
```

The CLI saves the API endpoint from CloudFormation outputs. Use `fleet connect`
with the endpoint/account/region/stage/profile to register an already deployed
manager, and `fleet list` to inspect saved managers.

Copy [examples/agent.json](examples/agent.json) to `agent.json` and set the real Core
account, region, stage and URL. Register it with optional credential preparation:

```bash
aws sso login --profile member-admin
opencdr-deploy fleet agents register --fleet security-prod \
  --file agent.json --core-profile member-admin
opencdr-deploy fleet agents list --fleet security-prod
opencdr-deploy fleet agents show member-prod --fleet security-prod
opencdr-deploy fleet agents request member-prod GET '/rules?rule_kind=signal' --fleet security-prod
```

Use the actual `agent_id` from your document in place of `member-prod`. With
`--core-profile`, the CLI verifies both accounts, prepares scoped API keys and
copies them to security-account SSM without displaying the keys. Without that
flag, registration assumes credentials were prepared separately. Start with
`allow_writes: false`. Inspect Core's monthly management API quota before enabling
one-minute polling; the legacy 10,000/month quota cannot support that cadence.

The complete setup, credential rotation, revision-guarded updates, configuration
pagination, Core API forwarding and explicit multi-agent calls are documented in
the [OpenCDR Deploy walkthrough](https://github.com/dbnz-io/opencdr-deploy#deploy-and-operate-fleet-manager).
IAM/SigV4 still protects every fleet route; see [access.md](docs/access.md).
The API contract remains [openapi.yml](openapi.yml). Manager responses retain
per-agent HTTP status, partial results and uncertain outcomes; HTTP 207 alone does
not prove that every target succeeded.

### Failed first deployment and small Lambda quotas

The default worker uses shared Lambda capacity with an SQS concurrency cap of 2,
without a fixed Lambda reservation. This supports accounts whose regional Lambda
quota starts at 10. Larger fleets can set `--poll-concurrency` after reviewing
their quota, other workloads and queue backlog. The cap does not reserve capacity.

If rollback removes the stack but leaves its retained DynamoDB tables, preserve
them and review `opencdr-deploy fleet recover` before retrying deployment. Recovery
imports the existing tables instead of deleting data. An existing failed stack
requires review before recovery; the tool does not delete stacks automatically.

The Node `url.parse()` deprecation warning is separate from deployment success.
An older helper's `allowedAgentHosts=` error is fixed by omitting empty CLI
parameters. Always check the final packaging/deployment result. Package-only
success produces no CloudFormation stack outputs.

### Source/developer deployment

Contributors can still clone this repository, install `requirements.lock` and
`npm ci`, and use `python scripts/deploy.py` with the same account/profile/region/
stage guards. These are implementation helpers behind the installed CLI.
`--package-only` validates packaging without deploying; omit it for deployment.
Use the installed CLI's `--artifact` workflow when promoting an already reviewed
package. PyPI's `opencdr-fleet-manager` distribution contains the service Python
modules; `opencdr-deploy` is the operational console command.

## Configuration and operational limits

`--pause-polling` disables the schedule. Set `enabled: false` through a revision-
guarded registration update to pause one agent and disable forwarding to it.
The registry and last observations are retained; there is no destructive agent
deletion endpoint. An in-flight HTTP call may finish, but a disabled/changed
registration fences old poll workers from publishing a new snapshot.

`--security-profile hardened` opts the three fleet tables into PITR. Standard
uses encryption at rest and retained tables; both profiles use encrypted queues.
Tables have Retain/UpdateReplacePolicy Retain, so removing the stack leaves them
for explicit operator cleanup. Object Lock, AWS Backup and customer KMS keys are
not introduced. Changing profile, retention, allowed hosts or polling settings
uses the same deployment command with new flags and a reviewed Serverless package.

The one-minute schedule is a target cadence, not an exact freshness guarantee.
HTTP latency, retries and backlog affect observation age. Polls have a 40-second
collection budget, 200-page bounds per listing, and a 5,000-resource/20 MB snapshot
limit (2 MB per upstream HTTP response). Overflow or collection failure keeps the previous complete snapshot and
reports failure. Poll jobs older than thirty minutes are discarded. The queue is
limited to 2 concurrent poll workers by default, configurable with `--poll-concurrency`; monitor backlog before expanding a large fleet.

Only profiles named in `settings_ids` and bindings named in `integration_ids`
can be enumerated reliably: Core currently has no saved-profile/binding listing
endpoint. Default notification coverage is `global`. Rules, list membership and
responder mappings are fully paginated. Snapshots are complete collections with
resource revisions, not cross-resource database transactions. List revision and
rule catalog changes during collection abort publication.

Configuration snapshots default to 24-hour TTL retention (2–168 configurable
hours). Unchanged content is reused until near expiry, avoiding full cache writes
every minute. This reduces write/storage costs; agent API reads still happen on
every poll. Fleet does not copy logs or detection telemetry into these tables.
Cache rules and list values as sensitive operational data. Notification secret
fields are redacted, and API keys remain exclusively in SSM.

Default agent hosts must be the expected region's AWS execute-api domain. Custom
domains require an exact `--allowed-agent-hosts` list reviewed at deployment.
The fleet Lambdas must be able to reach those endpoints. Private-network access,
Core API exposure policies and client workload credentials remain deployment
choices. No member-account AWS role is assumed during normal fleet operation.

See [architecture](https://github.com/dbnz-io/opencdr-fleet-manager/blob/main/docs/architecture.md), [access](https://github.com/dbnz-io/opencdr-fleet-manager/blob/main/docs/access.md) and
[acceptance checks](https://github.com/dbnz-io/opencdr-fleet-manager/blob/main/docs/acceptance.md) before connecting production agents.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest
python scripts/package.py
```

`requirements.lock` includes wheel hashes for every runtime dependency. Review
version changes in `scripts/lock-runtime.py` before regenerating it. Builds include
only locked vendor files and `src/opencdr_fleet/*.py`; credentials, `.env`, Git
metadata, tests and workstation build artifacts cannot enter the Lambda ZIP.
CI validates Python 3.12–3.14 and packages the service. Deployment is operator-
controlled. A published GitHub release runs the dedicated PyPI workflow; no AWS
deployment is triggered by package publication.

## Publishing releases

The PyPI publisher uses short-lived GitHub OIDC credentials and the `pypi`
GitHub environment. It builds and checks the wheel and source distribution,
verifies the release tag matches the package version, then publishes those exact
artifacts. No PyPI API token is stored in GitHub.

For initial setup, add a pending publisher at
[PyPI account publishing](https://pypi.org/manage/account/publishing/):

| Field | Value |
| --- | --- |
| PyPI project | `opencdr-fleet-manager` |
| GitHub owner | `dbnz-io` |
| Repository | `opencdr-fleet-manager` |
| Workflow filename | `publish.yml` |
| Environment | `pypi` |

The first successful publication creates the PyPI project. For subsequent
releases, update `pyproject.toml`, `opencdr_fleet.__version__` and `package.json`
together, wait for validation, and publish a GitHub release named `v<version>`.
The initial release is `v0.1.0`. Package publication and AWS deployment are
separate operator actions.

Licensed under the [Mozilla Public License 2.0 (MPL-2.0)](https://github.com/dbnz-io/opencdr-fleet-manager/blob/main/LICENSE).
