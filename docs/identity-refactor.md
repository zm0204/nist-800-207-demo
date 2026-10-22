# Identity-aware refactor — implementation and evidence ledger

Authority: user-provided, reviewed 207 + 207A architecture (2026-10-22).
Execution: modify the existing isolated `zta-207a` worktree on
`refactor/207a-identity-aware`; preserve original 207 deployment and all data.

Baseline: d879d73; clean worktree; PR #3 head matches local branch; 86 tests
passed with `.venv/Scripts/python -m pytest -q --basetemp=.tmp/baseline-unrestricted`.
Sandbox asyncio socketpair is blocked; ASGI/gRPC tests require unrestricted local
execution. Docker was initially stopped. No live cluster validation yet.

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
- [ ] Stage 4: isolated startup, real integration runner, regression suite,
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

## Verification ledger

Stage 0 complete: baseline 86 passed. Original data untouched.

Stage 1–3 implemented. Python suite: 127 passed. Real identity mesh: 23 integration checks passed, including HR quarantine, genuine signed WebAuthn step-up, PE/adapter/audit outages, zero execution queries, restoration, public certificates and CUSTOM coverage. Original 207 isolated Compose regression: 9 groups passed. Independent review: no confirmed P1/P2 findings. Stage 4 cold-start/launcher and final evidence refresh pending; hardware authenticator interaction remains manual acceptance. Phase 2 deferred.
