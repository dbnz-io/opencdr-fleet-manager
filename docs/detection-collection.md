# Durable detection collection

This is the local P1 implementation, not a published or live-accepted release.
Fleet collects both signal matches and correlated alerts from Core's IAM-only
delivery contract. Receipt-capable Core uses `/detections/consumers/{id}/read`;
older Core uses the stateless `/detections/feed` contract (1.0.0, 1.1.0 or 1.2.0). The initial Core capability negotiation and
every subsequent page validate the selected deployment identity. A successful
registration revision reuses capability negotiation; each ordinary empty poll
then needs one delivery request. Changing the registration requires negotiation again.
Legacy API-key agents are excluded; they must migrate to IAM for collection.

## Scheduling and installation

Detection collection has its own EventBridge schedule, SQS queue, worker and
per-agent lease. Configuration generation, health polling and configuration
refresh never suppress it. Deploy source builds accept:

```bash
opencdr-deploy fleet package security-prod \
  --detection-poll-interval-minutes 1 \
  --detection-retention-days 90 \
  --detection-poll-concurrency 2 \
  --enable-detection-polling \
  --output /tmp/opencdr-fleet-with-detections
```

Review the resulting package before deploying it. These options also exist on
`fleet deploy` and compatible portable `release plan` artifacts. Omitted values
preserve saved source-deployment configuration or existing portable stack
parameters. `--pause-detection-polling` stops new schedule work; queued work may
finish. `--pause-polling` controls health/configuration only. Cadence is 1–60
minutes, evidence retention 7–365 days (default 90), queue concurrency 2–1000.
The queue cap does not reserve idle account concurrency.

Upgrade Core with its journal first, then Fleet, then add Fleet's new
`DetectionPollRoleArn` to Core's exact management principals using Deploy's
reviewed bootstrap plan. The detection worker can invoke observer GET routes and
the dedicated delivery consumer GET/POST prefix. It has no Core configuration-write
credential, STS role-assumption permission or response permission. Core must have
the new `managementDelivery` function before receipt negotiation succeeds.
Status remains failed until Core trusts this role. Existing
registrations keep their immutable account/region/stage identities.

## Receipt and recovery behavior

A worker claims a 90-second per-agent lease and processes at most five pages of
20 records, subject to its time budget. Each page is validated in full before
storage: schema, deployment, contiguous sequence, unique IDs, kind, revision,
payload identity and byte bounds. Late source event times do not affect progress.
A DynamoDB transaction writes all page records and its checkpoint together,
conditioned on the current registration revision, enabled flag and unexpired
worker token. An interrupted or uncertain write resumes from the durable
checkpoint. Duplicate queue deliveries cannot reapply completed ticks.

When Core advertises `detection_consumers: 1.0.0`, that same transaction also stores
the page's server-issued receipt and consumer revision. The next request ACKs the
prior durable page and reads another. Empty steady polls still use one request;
unchanged Core consumer state is not rewritten. An uncertain ACK/read response
is reconciled against Fleet's durable checkpoint, never used to adopt remote
progress beyond locally persisted records. Once selected, receipt mode has no
stateless fallback. Existing stateless registrations renegotiate after a reviewed
registration revision change. Historical completeness and reset remain separate.

Records are keyed by agent and detection identity. A day/time index projects
summaries, excluding full evidence. Payloads over 100 KB are stored in an
encrypted private S3 bucket with content hashes before the transaction commits.
The table uses TTL, PITR and retain-on-delete/replace protection; the bucket also
has retention and public-access blocks. A failed transaction can leave an
unreferenced object that lifecycle expiry removes. No cursor moves on a failed
upload or incomplete transaction.

A Core HTTP 410 creates a persistent `gap` state. Future scheduled work leaves
that cursor untouched. Missing epochs, malformed pages, identity mismatch and
unsupported contracts also never advance the checkpoint. Reviewed retained-source
backfill and same-incarnation reconciliation are available as described below. Do not edit a
checkpoint to the current head to make the gap disappear.

Keep the evidence bucket and table together during recovery. The local Deploy
implementation now supports reviewed reattachment of the original retained set,
with table UUID/lineage checks and a pinned bucket name. The first runtime update
must preserve storage and keep both schedules paused. See the workspace
[recovery guide](https://github.com/dbnz-io/opencdr-deploy/blob/main/docs/fleet-storage-recovery.md).
Live import acceptance and PITR restoration remain open. Replaced worker
principals now have an explicit [reviewed handoff](https://github.com/dbnz-io/opencdr/blob/main/docs/detection-handoffs.md)
within the same Core feed incarnation; this also awaits live acceptance.
Do not delete a stack to repair a collection error.

## Observe collection

Existing agent list/detail responses, including CLI and MCP agent status tools,
now contain `detections`. The dedicated status endpoint is also available:

```bash
opencdr-deploy fleet agents show member-prod --fleet security-prod
opencdr-deploy fleet request GET \
  /v1/agents/member-prod/detections/status --fleet security-prod
```

`state` is `not_collected`, `ready`, `catching_up`, `failed` or `gap`;
`last_success_at`, `last_attempt_at`, `registration_current`, `stale`, `has_more`,
`last_sequence`, `last_page_records` and a sanitized error code explain coverage.
Receipt mode also exposes `delivery_protocol`, `consumer_id`, `consumer_rev`,
`consumer_acknowledged_sequence` and `receipt_pending`. The final ACK usually
travels with the next scheduled poll; locally caught-up state can precede Core's
ACK by one interval. Status does not expose evidence, receipts or the opaque cursor. Freshness is stale after
three cadence intervals, on an unsuccessful state, disabled registration or
registration mismatch. `ready` means caught up at the last successful page;
it does not promise complete pre-journal history.

Workers emit CloudWatch metrics in `OpenCDR/Fleet`, dimension `Stage`:

| Metric | Interpretation |
| --- | --- |
| `DetectionRecordsCollected` | Records durably receipted in this invocation |
| `DetectionDeliveryLagSeconds` | Maximum journal-commit-to-Fleet-receipt delay among those records |
| `DetectionBacklog` | Worker stopped with more feed records available |
| `DetectionCollectionFailures` | Feed/capability/identity validation or remote-read failure |
| `DetectionRetentionGaps` | Unresolved retention gaps; requires reconciliation |

Use Sum for records/failures/gaps and Maximum for backlog/delivery delay. Empty
polls emit zero delay; they are not latency samples for detections. For per-record
percentiles and end-to-end source-to-web latency, the P8 workload harness is still
required. SQS oldest-message age and DLQ alarms cover
queue/storage failures; separate custom alarms cover remote failures and gaps.
Logs contain IDs, counts and error codes, not feed payloads or credentials.

Polling dominates idle request volume. For 100 enabled agents at one minute,
31 days means 4,464,000 steady-state delivery requests (POST in receipt mode, GET
for older Core), plus first/revision checks, registration, conflict recovery and
catch-up pages. Health/configuration traffic, DynamoDB receipt/lease writes,
Lambda/SQS/logging and retained evidence are additional. This is request
arithmetic, not measured AWS spend or a capacity guarantee. Benchmark the default
concurrency with realistic latency/outages before accepting the 100-account SLO.

## Remaining P1 acceptance

The table now serves `/v1/detections`, `/v1/detections/summary` and
`/v1/detections/detail`; `/v1/status` advertises `central_detection_queries: 1.0.0`.
The SaaS exposes these through a read-only preview, preserving the existing
case/triage workspace until ownership migration. Core consumer registration and
receipts are implemented locally. Retained-source backfill and explicit same-incarnation gap repair are implemented locally. Live IAM/trigger testing,
recovery rehearsal and measured 100-account throughput/cost remain open.
The local suite exercises 100-agent scheduling and actual Core feed serialization
against Moto, including the actual Core receipt state machine and lost responses.
Cross-repository feed/receipt tests require a sibling Core checkout; a standalone
Fleet checkout explicitly skips those integration cases.

## Reviewed gap recovery

Core feed 1.1 introduces `detection.backfilled` entries. Fleet accepts native 1.0
and 1.1 entries and validates historical metadata. A historical repeat of an
existing detection checks its evidence digest without replacing retention or
handling fields. Newly imported records expire no later than their source expiry.
Upgrade this dual-version reader before upgrading Core to feed 1.1.

`POST /v1/agents/{agent_id}/detections/reconcile` is administrator-only. It accepts
an exact checkpoint generation, registration revision, completed Core job ID and
digest, reason, unique request ID and `accept_unrecoverable: true`. The durable
intent queues the original detection worker; the caller cannot impersonate that
worker's consumer. Query `/v1/agents/{agent_id}/detections/status` for completion,
`reconciled_request_id`, `last_reconciliation` and remaining gaps. A different
pending intent requires explicit `supersedes_request_id` and retains prior audit.
Queue failure does not erase accepted intent; the next enabled schedule retries.

Use Deploy `fleet agents request` for Core backfill plan/step/results and
`fleet request` for Fleet reconciliation. The generic proxy allows administrator
backfill maintenance but cannot mutate delivery consumers. See the workspace
Core guide `../opencdr-internal/docs/detection-backfill.md` for exact JSON, commands,
measurement points and crash tests. These APIs are local source, not yet released.
Feed replacement, old-writer activation and point-in-time table/bucket restoration
remain separate unfinished gates. Retained-resource reattachment and principal
handoff are implemented locally but not live-accepted; gap repair never claims
complete history. Handoff does not run a normal collection page or clear a gap.


## Reviewed replay after storage or checkpoint recovery

The [feed recovery manual](https://github.com/dbnz-io/opencdr/blob/main/docs/detection-feed-recovery.md)
covers the local storage guard, generation rotation and completed-backfill replay.
With detection polling paused, administrators GET/POST
`/v1/agents/{agent_id}/detections/recover`. The request captures the exact previous
checkpoint and registration and binds a reviewed target epoch/worker principal.
The worker creates a fresh Core consumer and stops at `recovery_paused`. It never
rewinds the old consumer or implicitly resumes collection. After explicit resume,
backfilled records preserve existing evidence, retention and handling metadata.
Lost Core responses, local commits and queue failures retry the same durable intent.

This supersedes the runtime feed-replacement gap described above; actual AWS PITR
restore/reattachment and coordinated activation are still open. Ordinary unchanged
polling remains one Core HTTP call, but physical identity checking adds DynamoDB
DescribeTable calls inside Core. Measure those costs/latencies separately.

Feed 1.2.0 adds handling metadata events. See [handling operations](detection-handling.md) for reader-before-writer upgrade order and separate triage access.
