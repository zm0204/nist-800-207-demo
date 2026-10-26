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

- [ ] Add failing boundary/login/access tests using real WebAuthn signatures with an isolated Identity DB.
- [ ] Add server-side employee sessions, fixed normal read API and shared serial job admission.
- [ ] Protect all legacy APIs with independent operator capability; retain CSRF separately.
- [ ] Verify API tests and existing regression suite.

### Task 2: Evidence and UI

- [ ] Add failing classification tests for PE denial, native denial, unknown journal and transport errors.
- [ ] Add safe Observer summary/detail projections and fixed paired diagrams with clickable node evidence.
- [ ] Add minimal employee login, service cards, owner selection and actual result rendering.
- [ ] Verify browser behavior and regression suite.

### Task 3: Acceptance and delivery

- [ ] Provision a separate acceptance cluster/state and run actual WebAuthn→mTLS→PA→JWT→services through Portal APIs.
- [ ] Verify Alice ownership, bounded Bob access, cache polling, management isolation and preserved old workspace.
- [ ] Document commands, URLs, limitations and evidence; run full tests, inspect diff and independent review.

## Execution ledger

- Workspace: sibling zta-portal-p0, feature/employee-portal-p0; native app worktree creation unavailable because chat root is a non-repo project mirror, used git worktree fallback.
- User explicitly opted out of further design/approval discussions. Execute inline using existing stack.
