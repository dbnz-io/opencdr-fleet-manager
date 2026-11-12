# Detection handling

Fleet projects Core handling revisions monotonically and preserves evidence/expiry on all replays. Dedicated per-agent handling routes require IAM and explicit `allow_triage` for edits. Current handling/history reads may contact the selected Core; indexed list/summary/detail queries do not fan out.

See the canonical [Core operator and acceptance guide](https://github.com/dbnz-io/opencdr/blob/main/docs/detection-handling.md) in the multi-repository workspace. In standalone checkouts use the matching Core source release’s `docs/detection-handling.md`. The public release must package matching API/contract versions.

Every new edit supplies `expected_rev`, a stable 32-hex `request_id`, a reason and changes. Retry an uncertain request unchanged. Manual SIEM status remains unverified and independent of local handling. Fleet acceptance reports pending projection, not completed synchronization. No case cutover, live deployment or release acceptance is claimed.
