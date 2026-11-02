# Live acceptance before production registration

Local tests use Moto and mocked HTTPS. Complete this against a staging fleet
with at least two explicitly selected Core deployments before promoting it.
Use the README commands and invoke-only caller policies; record stack/release
identities and results. No command here is executed automatically by CI.

1. Deploy in the expected security account. Verify the three tables, encrypted
   queues, one-minute schedule, per-function roles and IAM on every API method.
   An unsigned request must receive 403. A caller without write-route permission
   must also receive 403 for proxy writes and bulk invoke.
2. Onboard two agents with different account IDs and read-only keys. Confirm every
   minute produces fresh status and complete snapshots with the correct account,
   region and stage, actual feature flags, runtime generation and API quota data.
   Missing reported fields must stay unknown. Check actual Core usage-plan limits.
3. Add a multi-page rule catalog and reusable lists. Read every cache page, verify
   list membership and resource counts, and continue a pinned cursor across a new
   poll. Include a list exceeding 400 KB to verify chunk reconstruction. Inspect
   notification cache documents: no webhook credentials, tokens or header values.
4. Block one agent temporarily. Confirm the other continues to update and that
   the failed target retains its previous snapshot with a failure/stale indication.
   Restore access and confirm freshness recovers without replaying any writes.
5. Point a test registration at the other agent's valid URL. A live proxy write
   must be refused for identity mismatch. Change the registration while a poll is
   running and verify the old worker cannot publish its result.
6. Enable a staging operator key and write flag. Proxy a benign revision-guarded
   change, then send an intentionally stale revision. Confirm the exact conflict
   and per-agent outcome are returned without silent rebasing or rollback of
   successful targets. Verify one accepted change gets a fresh cached observation.
7. Simulate a timeout after an agent accepts a write. Verify Fleet returns an
   unknown outcome and does not automatically retry it. Inspect Core before any
   operator retry. Do not use a destructive response action for this exercise.
8. Pause polling, re-enable it, disable a registration, and rotate a read key.
   Confirm disabled registrations receive no new scheduled reads or forwarded
   calls. Allow for an already-running HTTP request to complete.
9. Verify queue lag and DLQ alarms in CloudWatch, log redaction, TTL expiration,
   retained-table cleanup procedures and recovery ownership. For hardened, perform
   an isolated PITR restore drill before depending on it for recovery.

Monitor both Lambda/queue failures and agent status records: an unreachable agent
is a reported observation, not necessarily a failed Lambda invocation. The
configuration cache is not a cross-resource transaction or an agent backup.
