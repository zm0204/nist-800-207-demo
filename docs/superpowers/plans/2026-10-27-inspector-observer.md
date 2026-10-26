# Inspector → Observer Integration Plan

**Goal:** Update the existing Alice/Bob cache from an authorized Intruder experiment using verified PE audit identity, preserving independent workload identity and evidence-only coloring.

**Architecture:** Return a server-private publisher from `attach_portal`; call it only after the existing authorized Inspector job completes. Use matching PE audit claims/source to classify, never decode an unverified caller-provided JWT. Reuse the receiving sidecar model; direct Intruder traffic bypasses Gateway/Frontend. An ambiguous native rejection appears as Native authorization, without inventing a DENY-rule match.

**Constraints:** No new public mutation route, policy changes, tracing, credential/session/DB resets, or Profile writes. Existing serial jobs and 2-second cache polling remain. Unknown identity cannot replace either employee's result. Public details expose allowlisted subject/workload fields only.

- [x] Add failing tests for private publication, audit correlation, no secret leakage, public injection rejection, independent latest snapshots, and direct caller/native refusal rendering.
- [x] Implement the small cache hook and presentation changes; run targeted tests.
- [x] Validate Alice own read, Alice forbidden read, Intruder with Alice JWT, Bob normal read in `kind-zta-portal-p0`; query actual Journal and logs. Preserve existing credentials; use existing test authenticator only.
- [x] Run Python/Node regressions, inspect the real browser, review the diff, document evidence; deliver on `feature/employee-portal-p0`.

Execution ledger: Base `587e1c8`; worktree clean. User explicitly requests direct execution and push. Missing PE identity audit leaves the existing snapshots unchanged rather than attributing an unverified subject. Native DENY vs unmatched ALLOW remains distinct when Envoy cannot distinguish them. No cluster deployment is required for host-only changes.

Validation ledger: RED observed for backend publication and direct-caller model; GREEN 32 targeted Python, then 174 full Python (one upstream deprecation warning). All 14 Node tests pass, including actual renderer/Journals. Real E2E: 23 checks passed, both existing test credentials signed genuine WebAuthn ceremonies; no enrollment or salary writes. Live Chrome verified green PE branch, red native enforcement, gray unobserved checks, independent Bob snapshot, and queried empty Journal evidence. Independent review found no important/critical issues. Only the Portal host process and its owned forwarding children were reloaded; existing clusters and persisted state were not redeployed or reset.
