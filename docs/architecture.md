# Organization-local fleet service

One deployment serves one organization in its security AWS account. The registry
and IAM caller policies define its organizational boundary. This is not a shared
multi-tenant SaaS database. Never share a manager's global inventory/bulk IAM
permissions with an unrelated tenant.

## Storage ownership

| Table | Key | Contents |
| --- | --- | --- |
| Registry | `id` | Agent identity, endpoint, configuration coverage, registration revision, enabled/write controls, polling leases; unique deployment identity locks |
| Status | `agent_id` | Current poll outcome plus last verified Core report, runtime state, cache generation and timestamps |
| Configuration | `pk = agent_id#generation`, `sk` | Complete manifest, per-resource metadata and chunked JSON documents with TTL |

Credentials are separate SSM SecureStrings beneath
`/opencdr-fleet-manager/<stage>/agents/<agent_id>/{read,write}-key`. The API never
accepts their plaintext values in registration documents. Poll workers only have
GetParameter permission for `read-key`, and no mutation route is called by polling.

The configuration cache uses document chunks smaller than DynamoDB's 400 KB item
limit. Publication happens after the full collection, manifest and chunks are
written. One transaction checks the agent revision and lease token, publishes
the new status pointer, and completes the lease. Interrupted writes leave TTL-
expiring unreferenced data rather than a partially published snapshot.

Unchanged configuration reuses a content digest and generation while its TTL is
safely in the future. Verification time still advances every successful poll.
Snapshot pagination binds the agent, resource kind and generation into its cursor;
an old cursor can continue a retained snapshot after another poll completes.
Missing chunks or checksum failures are errors, not empty configuration.

## Scheduling and consistency

A one-minute EventBridge rule invokes a dispatcher. Registry pages use a GSI,
not full-table scans; batches of up to ten SQS messages fan out the work. Each
worker claims an expiring lease conditioned on the registration revision and
last completed sequence. Older/duplicate polls cannot overwrite a newer result.
Re-registering or disabling an agent removes the lease fence, so old workers
cannot publish after the change.

Each poll verifies Core identity and management contract compatibility, reads
runtime activation, collects all supported configuration pages and reads runtime
generation again. A list revision mismatch or changing rule catalog aborts cache
publication. Other resources retain their per-record revisions; Core does not
provide a distributed read transaction over all resources. The cache is an
observed collection, never an automatic restore source or desired-state mandate.
Do not round-trip redacted notification snapshots into write requests. Use the
live API and its secret-preserving update semantics when authoring changes.

Agent/network failures become visible status records and the next minute tries
again. Infrastructure/storage failures use SQS partial batch retry and eventually
a dead-letter queue. Polls older than thirty minutes are discarded. This schedule
provides no exact-second SLA; latency, scale and backlogs are exposed through
timestamps, stale flags and queue alarms.

## Forwarding

All fleet API calls use IAM/SigV4. Live agent operations use allowlisted Core
routes and a registered HTTPS endpoint. Endpoints default to AWS execute-api
hosts in the registered region; custom DNS hosts need an explicit deployment
allowlist. HTTP redirects are disabled. Credential headers, caller authorization
headers and upstream cookies are never relayed between endpoints.

Before forwarding any operation, Fleet reads `/status` with the read key and
checks product/account/region/stage/management contract. A mutating operation
requires `allow_writes` and the separate operator credential. The agent receives
the exact caller-provided body and revision guard; Fleet does not read a fresh
revision and replace an old guard. It forwards application API operations only,
not CloudFormation deployment commands or arbitrary HTTP destinations.

Multi-agent calls are bounded to eight explicitly named targets and return each
target's result. There is no cross-agent transaction or rollback. A timeout after
a write starts has an unknown outcome and is never automatically retried.
Successful writes enqueue a fresh observation; inability to enqueue does not
change the already accepted write's result. Core propagation is reported by
Core's runtime endpoint, not inferred from a successful API response.

Bulk responses have a bounded size. They preserve every target's status/outcome
and explicitly mark oversized bodies omitted. Use per-agent proxy calls for
large payloads or detailed partial-write evidence. Fleet does not persist arbitrary
proxy responses, which could contain telemetry or other sensitive content.

## Client boundary

The deployed API is the future multi-account entry point for Web, opencdr-deploy
and MCP adapters. Single-agent direct Core operation remains independent. Client
adapters must negotiate `/v1/status`, keep IAM credentials out of the browser,
preserve per-target failures, and unwrap the Core result envelope. Do not point
an existing Core client at the fleet URL and assume the contracts match.

Select the connection mode explicitly. A multi-account installation uses its
fleet connection even when an operator filters down to one agent; the single-
target proxy exists for that purpose and for per-agent revision guards. A
single-agent installation can use direct Core mode. Do not silently switch to
direct credentials when a fleet request fails or its target selection has size one.

Core infrastructure installation/upgrades still use local AWS profiles through
opencdr-deploy. This service does not take over that execution responsibility.
Future SOC storage or desired-state rollouts require separate versioned APIs;
neither is silently migrated from the web platform by this release.

## Recovery and deployment choices

Core detection and response continue with their last accepted configuration if
the fleet service is unavailable. Central inventory and cached configuration may
be stale. API forwarding is unavailable until Fleet recovers, while independently
authorized direct Core access remains an operator recovery path.

All tables are retained on deletion/replacement; hardened enables PITR at added
cost. Restore registry and status coherently, verify account identity, re-import
credentials if necessary, and repoll before enabling writes. Cached configuration
can be rebuilt from Core; it is not a backup of agent runtime state. Customer
network design, Core API exposure, role issuance and recovery objectives remain
operator responsibilities.

References: [DynamoDB limits](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Constraints.html),
[SQS partial batch results](https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-errorhandling.html),
[Serverless IAM endpoints](https://www.serverless.com/framework/docs/providers/aws/events/apigateway#http-endpoints-with-aws_iam-authorizers).
