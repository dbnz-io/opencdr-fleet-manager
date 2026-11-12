# IAM agents and durable rollouts

New registrations default to `auth_mode: iam`. Supply the regional Core API URL
including its stage, expected account and region, and `write_access` (`operator`,
`responder` or `administrator`). Initially keep `allow_writes: false`. Existing
records without `auth_mode` retain their legacy-key interpretation; explicitly
change the registration when Core trust is ready. There is no credential fallback.

Trust the role ARNs exported by this Fleet stack in Core's
`managementPrincipalArns` parameter. Polling only uses the observer path. For
management clients, configure `access` to select
`/management/{access}/v1/...`; the existing `/v1/...` routes remain a migration
interface. Only administrators can change registrations through the new paths.
Core continues to authorize every forwarded operation.

Polls fetch status every minute by default. `--poll-interval-minutes` configures
the health/configuration interval; `--full-refresh-minutes` configures full
reconciliation. See the README for bounds and deployment examples. These settings
do not control the independent [detection collector](detection-collection.md).
Include its exported `DetectionPollRoleArn` in Core trust when upgrading.
If the management generation is unchanged,
the registration revision still matches and the cached snapshot is usable, no
configuration pages are fetched. Full snapshots reconcile hourly by default and after changes.
Health timestamps and full-snapshot timestamps are distinct. An active Core writer
or inconsistent collection produces a degraded/stale result, never a healthy
partial snapshot. The status includes observed request counts and an estimated
monthly request count; rule/list counts and update frequency affect actual costs.

Durable rollouts support 1–8 explicitly selected IAM agents per job:

1. `POST /v1/rollouts/plan` with `agent_ids` and a rule-release `manifest`.
2. Review every target's operations and save `rollout_id` and `review_digest`.
3. Within 15 minutes, `POST /v1/rollouts/{id}/apply` with that digest, using the
   same management access as the review.
4. Poll `GET /v1/rollouts/{id}`. Fetch details at
   `GET /v1/rollouts/{id}/results/{agent_id}`.
5. `POST /v1/rollouts/{id}/drift` compares live rules with the manifest and reports
   differences without modifying Core.

Every worker uses the original per-agent plan digest and registration revision.
Queue redelivery cannot resend a claimed write. Outcomes include `succeeded`,
`conflict`, `partial`, `failed`, `not_sent` and `unknown`. An interrupted claim
becomes unknown in status after two minutes. Inspect the agent before creating a
new plan for a partial or uncertain result. A successful configuration write is
not proof of evaluator activation; inspect Core runtime status separately.

Plans, results and audit timestamps are retained for seven days. The rollout table
has point-in-time recovery. Operator, responder and administrator workers use
separate queues and IAM policies; DynamoDB leading-key conditions prevent a lower
privilege worker from modifying a higher privilege plan. Drift is report-only;
there is no automatic repair or rollback of response actions.

The installed CLI can use these routes with `opencdr-deploy fleet request`.
MCP exposes typed plan, apply, status and drift tools. The SaaS can implement the
same contract later; it does not need to become the customer-side state authority.
