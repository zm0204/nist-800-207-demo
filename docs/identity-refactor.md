# Identity-aware refactor — implementation and evidence ledger

Authority: user-provided, reviewed 207 + 207A architecture (2026-10-22).
Execution: modify the existing isolated `zta-207a` worktree on
`refactor/207a-identity-aware`; preserve original 207 deployment and all data.

Baseline: d879d73; clean worktree; PR #3 head matches local branch; 86 tests
passed with `.venv/Scripts/python -m pytest -q --basetemp=.tmp/baseline-unrestricted`.
Sandbox asyncio socketpair is blocked; ASGI/gRPC tests require unrestricted local
execution. Docker was initially stopped; live validation followed in Stage 4.

## Stage 0 audit findings

| Existing component | Finding and implementation decision |
|---|---|
| Original 207 Identity / PA / PE / Context / Envoy | Preserve actual WebAuthn, device mTLS, continuous Session evaluation and SQLite data; extend identity schema additively and add the scoped token bridge |
| PR #3 Istio mesh / ServiceAccounts / gRPC adapter | Preserve real SPIFFE and ext_authz mechanisms; add user JWT verification, receiving-side default deny and all-backend-port CUSTOM coverage |
| Existing workload-only request examples | Insufficient for user ownership, role, freshness and persistent behavioral risk; add resource authorization and atomic per-subject state |
| Old mesh console | Workload experiments alone cannot demonstrate integrated user flow; replace default UI with real login, device Session/JWT, bounded experiments and evidence-based stage cards |
| Existing tests and deployment | Keep original regressions; use a separate branch, isolated cluster/PKI/PVCs and real positive, denial, fault and zero-execution verification |

## Implementation order

- [x] Stage 1: `app/user_tokens.py`, PA exchange, additive identity migration;
  `app/mesh_identity.py`, frontend and resource JWT validation; mesh policies.
  Verify real WebAuthn → introspection → device-bound session → RS256 JWT;
  missing/expired/forged/wrong audience tokens and ownership denial.
- [x] Stage 2: separate dynamic resource policy and persistent subject/device
  context; real ext_authz → PE request. Count by subject, persist quarantine,
  require fresh WebAuthn for short salary-write scopes, audit before ALLOW.
  Verify dependency failure never executes resource; step-up never clears risk.
- [x] Stage 3: trusted event source and attempt/request correlation;
  `console/` Security Inspector with Demo/Inspector views. Only producer evidence
  establishes stage outcomes. Missing logs remain NOT_OBSERVED.
- [x] Stage 4: isolated startup, real integration runner, regression suite,
  deployment policy coverage, architecture/sequence diagrams and Windows guide.
- [ ] Stage 5: deferred until Stage 4 passes; no multi-location claim.

## Security boundaries / review focus

Compromised frontend includes its sidecar. Receiving sidecars and independent PE
remain authoritative for workload restrictions. Applications verify RS256 JWT
against configured public keys, never identity headers. No token-selected key URLs.
Only PA sees signing material. Session and device context are checked at exchange;
dynamic PE reads current state for each request. Audit failure denies execution.
CUSTOM executes before DENY/ALLOW, and covers all backend application-port traffic.
Attempt IDs are correlation labels, never authorization proof. No absence-of-log
inference. Only test authenticator code generates software credentials.

## Verification ledger — historical snapshot 2026-10-22

Stage 0 complete: baseline 86 passed. Original data untouched.

Stage 1–4 core implementation and automated acceptance complete. Python suite:
**139 passed** (one upstream Starlette deprecation warning). Real isolated identity
mesh: **26 integration checks passed**, including exact missing-device-certificate
TLS alert, wrong-device forged XFCC, receiving JWT validation, ownership, illegal
workload with a legal user JWT, persistent HR quarantine, distinct genuine signed
WebAuthn step-up, PE/adapter/audit outages, independent zero-execution queries,
recovery, current device compromise, 11 public workload certificates and all-port
CUSTOM coverage. Original 207 isolated Compose regression: **9 groups passed**.
Original `zta-demo` worktree remains clean. No original data or deployment deleted.

Windows `.cmd --no-browser` was actually executed successfully; all 12 isolated
workloads are ready. Inspector UI request/response and evidence-reread flows were
checked in a browser. Independent review has no remaining confirmed P1/P2; its
cleanup-ledger finding is fixed and failure-tested. The final evidence-ledger
cleanup change is covered by the 139-test suite; application image is unchanged.

Evidence snapshots: [identity mesh](evidence/2026-10-22/identity-e2e.json) and
[original 207 regression](evidence/2026-10-22/compose-verification.json). Reports
record the actual run revision plus source digest (working-tree changes included),
image ID, timestamps and producer evidence; no report is relabeled as remote CI.

Manual acceptance remains: physical Windows Hello / hardware security key, and a
full Windows reboot cold-start. New GitHub Actions workflow is supplied but has
not been pushed or run remotely. No HA / production-load / rotation soak test.
Phase 2 / multi-location remains explicitly NOT_IMPLEMENTED. No merge or push.

2026-10-23 follow-up: [CI transport repair and current manual acceptance checklist](ci-transport-2026-10-23.md).
