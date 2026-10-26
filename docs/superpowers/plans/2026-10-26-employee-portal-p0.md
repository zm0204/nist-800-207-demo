# Employee Portal P0 Implementation Plan

**Goal:** Implement the user's approved Portal, paired Observer and real API isolation on 542fee9.
**Architecture:** Extend the existing loopback FastAPI operator, retaining one global serial job slot. Keep human tokens, PA sessions and JWTs server-side; employee cookies authorize only fixed read operations. An independent local operator capability protects every legacy management API. Observer reads sanitized, bounded in-memory attempt snapshots only.
**Tech Stack:** Existing FastAPI, WebAuthn, Envoy, Istio, Python and plain HTML/CSS/JS; no new infrastructure.
**Spec:** User's P0 request and subsequent minimal professional UI requirements in this chat.

## Global Constraints

- Never reset, delete or overwrite existing credentials, PKI, sessions, databases, volumes or PVCs.
- Preserve Inspector at /inspector; no Profile mutation or Phase 2 additions.
- Fixed Alice/Bob diagrams; CUSTOM → DENY → ALLOW; missing evidence stays unknown.
- Destructive/intrusive acceptance runs only in a separately named test cluster.

## Review Focus

- Employee cookie or public CSRF token cannot authorize legacy management calls.
- Verified Identity subject, never browser owner/subject fields, selects Observer attribution.
- PA rejection and transport failure retain Attempt IDs and never invent a PE denial.
- Empty journal is meaningful only when actually queried; no secrets in Observer.
- Polling is cache-only and preserves the other person's last attempt.

### Task 1: Boundaries and read API

- [x] Add failing boundary/login/access tests using real WebAuthn signatures with an isolated Identity DB.
- [x] Add server-side employee sessions, fixed normal read API and shared serial job admission.
- [x] Protect all legacy APIs with independent operator capability; retain CSRF separately.
- [x] Verify API tests and existing regression suite.

### Task 2: Evidence and UI

- [x] Add failing classification tests for PE denial, native denial, unknown journal and transport errors.
- [x] Add safe Observer summary/detail projections and fixed paired diagrams with clickable node evidence.
- [x] Add minimal employee login, service cards, owner selection and actual result rendering.
- [x] Verify browser behavior and regression suite.

### Task 3: Acceptance and delivery

- [x] Provision a separate acceptance cluster/state and run actual WebAuthn→mTLS→PA→JWT→services through Portal APIs.
- [x] Verify Alice ownership, bounded Bob access, cache polling, management isolation and preserved old workspace.
- [x] Document commands, URLs, limitations and evidence; run full tests, inspect diff and independent review.

## Execution ledger

- Workspace: sibling zta-portal-p0, feature/employee-portal-p0; native app worktree creation unavailable because chat root is a non-repo project mirror, used git worktree fallback.
- User explicitly opted out of further design/approval discussions. Execute inline using existing stack.

### Task 4: Authorized salary stage after verified P0

- [x] Implement same-subject real WebAuthn Step-Up with ceremony/session binding and one-use server-held token.
- [x] Send actual salary:write exchange and protected salary adjustment; preserve PA-vs-PE denial attribution.
- [x] Verify Bob Alice mutation/read-back, Bob Carol denial and Alice PA denial in the dedicated environment; no Profile mutation.

### Verified execution results

- P0 committed as b7b64a4 after 155 Python + 1 Node tests and 12 actual read combinations passed.
- Independent P0 review found cached-session false-current-pass and expiry UI recovery bugs; both fixed with RED-to-GREEN tests and green full suite.
- Salary stage: 159 Python + 2 Node tests pass; actual software-authenticator WebAuthn -> mTLS -> PA -> JWT -> Istio/PE -> SQLite mutation and read-back pass.
- Independent salary review found no important/critical bug; added negative tests for wrong user, switched session, replay, stale assurance and token absence.
- Ruling: keep ambiguous native RBAC rejection attributed to native_policy, not a fabricated DENY rule match; UNKNOWN detail stays available.
- Ruling: keep all work on feature/employee-portal-p0 and leave the independent environment running for review; do not merge, push or replace the existing 18081 environment.
- Hardware Windows Hello interaction remains user-operated; automated tests sign real ceremonies with test-only software authenticators, with no server bypass.
