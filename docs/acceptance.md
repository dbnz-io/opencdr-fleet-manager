# Fleet engine acceptance and handoff

The [12 November handoff guide](../../opencdr-deploy/docs/handoff-2026-11-12.md) is the
runnable candidate procedure. Use installed Deploy with pinned artifacts and IAM;
legacy API keys are an explicit migration path, not the default. P0–P7 isolated
engine evidence is recorded. Independent owner results and public release remain
separate. Web/mobile/hosted application checks are P10.

The owner deferred the100000-record/10-reader stress workload. Use sequential
foreground checks; no quota request is needed for this handoff. Keep other limits,
prior failed evidence and actual new failures visible.

1. Verify account/region/stage and release/runtime hashes. Review the fresh Add-only
   plan, IAM-only endpoints, retained data, encrypted queues/DLQs and schedules.
   The pinned Fleet template has7tables (Library, Case, Detection, Rollout, Registry,
   Status, Configuration) and14functions split by permission/worker role. Inspect
   actual template resources; do not rely on the former three-table checklist.
2. Install Fleet paused first, then Core with this Fleet's exact role principals.
   Activate Core after the guarded drain/backfill. Register the exact Core identity
   with IAM and writes/triage disabled. Registration does not transfer case/Library
   ownership or grant case access.
3. Verify status and bounded configuration snapshots; preserve missing/stale states.
   A single real member proves one-member integration, not100deployed accounts.
   A second separately scoped member is needed for cross-account isolation tests;
   record NOT_RUN if absent rather than inventing a second deployed account.
4. Test unsigned/forbidden requests and scoped case grants, stale revisions and
   unknown outcomes. A distinct restricted IAM profile is needed to prove IAM
   least privilege; selecting an observer endpoint with admin credentials is narrower
   API evidence only. Save requests and inspect explicit denial codes.
5. Verify Fleet case/Library storage independently of Core member availability.
   Follow the kit's inert create/note/version/replay/cleanup steps. Restore original
   principal scopes with revision checks; preserve immutable history/evidence.
6. Keep health/configuration and detection polling distinct. Enable detection only
   through a reviewed release after Core activation/consumer reconciliation. Compare
   source commit, persisted IDs, pending receipt, generation, ACK and lag. Do not
   manually wake queues or reset consumers to manufacture schedule/catch-up results.
7. Use reviewed inert jobs for configuration/distribution. Freeze actual membership,
   bound preparation and verify stored/evaluator states separately. Changed
   registration, revocation, cancellation and unknown effects must stay explicit.
8. Measure relevant CloudWatch/queue/API evidence with exact UTC windows. Test
   retention/recovery against isolated data through Deploy. Keep physical storage,
   claims and evidence intact; the cache is not an account backup.
9. Disable only fixture registrations/policies, restore grants, close cases and
   archive drafts. Retire temporary compute only with a reviewed Deploy update
   that preserves retained data/logs and protected recovery mappings.

Production Fleet and Control Tower remain outside the handoff fixture. After the
11 November cleanup,15functions remained in the Fleet account. A new Fleet handoff
installation temporarily adds14; the installer does not silently recreate the
retired p1/p7 stages. Record remaining infrastructure until reviewed cleanup completes.

Use [owner workflows](../../opencdr-deploy/docs/owner-workflows.md),
[recovery](../../opencdr-deploy/docs/fleet-storage-recovery.md),
[KPI measurements](../../opencdr-deploy/docs/engine-kpis.md), and the
[owner worksheet](../../opencdr-deploy/docs/engine-acceptance-worksheet.json).
