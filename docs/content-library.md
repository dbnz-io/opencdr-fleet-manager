# Fleet-owned content library (P3 local candidate)

Fleet implements `/v1/library/items`, version/artifact/history subroutes and
`/v1/library/releases` using the shared Core management domain, vendored with
SHA-256 pins. It is customer-wide authoring storage. Library requests do not
contact member agents or filter content by case/account grants. Each customer
needs a separate Fleet owner and trusted IAM connection.

Observer/triage can read; operator/responder/administrator can author. Delivery,
integration and legacy API keys cannot author/read the library. Reads and writes
carry Fleet deployment identity. DynamoDB metadata/audit/receipts and S3 artifacts
are retained separately from active Core configuration and the configuration cache.

Saved versions have `validation_state: not_run`. Import provenance is
`caller_declared`. Frozen snapshots pin up to 25 items including declared
dependencies, with `deployment_state: not_requested`. No validation, approval,
Git fetch or rollout happens when saving/freezing. Exact request retries are
idempotent; stale revisions and conflicting pins fail. There is no delete API.

Use the coordinated [Core library manual](https://github.com/dbnz-io/opencdr/blob/main/docs/content-library.md)
for the route matrix, Deploy examples, web/MCP parity, restore limitations,
manual acceptance and cost/KPI measurements. The repository's OpenAPI documents
the concrete routes and physical proxy. This candidate has not been deployed or
promoted; native test evidence, verified imports, promotion and migration remain
separate roadmap work.
