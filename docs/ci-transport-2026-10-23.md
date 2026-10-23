# 2026-10-23 CI transport repair and manual acceptance

Scope: `refactor/207a-identity-aware`; no Phase 2 additions or cluster/data reset.

## Confirmed cause

The failed [Identity run 39778133279](https://github.com/zm0204/nist-800-207-demo/actions/runs/39778133279)
received the exact expected `TLSV13_ALERT_CERTIFICATE_REQUIRED`, then its shared
kubectl port-forward disappeared before the next `/session` request. The old
250 ms background restart and a preceding health request did not form a readiness
barrier: the prior connection error could finish asynchronously after that probe.

An independent Linux reproduction against the preserved local cluster confirmed
`broken pipe` followed by `lost connection to pod`, exit 1. The equivalent Windows
probe survived in this run, explaining why the earlier local acceptance missed the
Linux behavior. This is transport failure, not authorization failure.

The expected-failure TLS probe now uses its own dynamically allocated loopback
forward to the same real Device Gateway. It still verifies the server CA and must
observe the exact certificate-required TLS alert. That specific process is reaped
before a positive request proceeds. Shared Identity and Gateway tunnels both need
real application readiness; Gateway readiness uses a valid device certificate.
No Session/application POST is retried, no TLS validation is disabled, and no
transport exception is counted as a security PASS. Readiness polling is bounded
and condition-based, with kubectl stdout/stderr saved under `artifacts/port-forwards`.
Shutdown cancellation prevents a restarting supervisor from leaving a child alive.

Lifecycle tests use real child processes and HTTP endpoints: listener-before-ready,
non-ready HTTP, transport refusal, stderr/exit, ownership cleanup, and cancellation
during restart. Full local and remote results are reported with their actual run
URLs in the delivery message. Historical 2026-10-22 evidence remains unchanged.

## Windows Hello / hardware Passkey — MANUAL, NOT EXECUTED BY THIS REPAIR

1. Use Chrome or Edge at **http://localhost:18081/**. An existing account should
   use its existing Passkey. To add a key, select the subject and use the protected
   registration invitation flow; never clear SQLite, Volumes or old credentials.
2. Select Alice, click Passkey login, and personally complete the Windows Security
   PIN/biometric or hardware-key prompt. Do not share the PIN, credential private
   key or bearer tokens. Verify the UI shows Alice, device-a, ACTIVE Session and
   issued short JWT. Inspector claims must come from a real PE audit.
3. Alice own Salary/Profile: 200. Alice requests Bob: 403 with ownership reason
   and a successful independent execution-journal query returning zero.
4. Cancel a login prompt: no successful new login/Session should be shown. Retry
   using the existing key; do not delete enrollment to recover from cancellation.
5. Bob: assigned Alice access is allowed; Carol is denied. Complete another real
   Passkey prompt for salary Step-Up; salary:write lasts at most 30 seconds and
   requires auth_time within 60 seconds. Demonstrate that Step-Up does not remove
   behavioral quarantine. Recovery is a distinct protected operator action.
6. Record browser, authenticator type, timestamp, Attempt IDs and observed results.
   A software-authenticator CI pass is not a Windows Hello/hardware PASS.

## Docker Desktop restart / cold start

This is distinct from rebooting Windows. Before restarting Desktop, finish active
experiments. Existing Sessions may fail closed or expire; re-login afterwards.

1. Record both kind container IDs, Docker Volume names, identity PVC UIDs and
   credential/counter state. Keep `.tmp/identity`, signing key, CA and kubeconfig.
2. Restart Docker Desktop normally (never Reset, prune, delete cluster, or down -v).
3. Wait for Docker Engine readiness, then run `scripts\start_identity.cmd --no-browser`.
   The launcher exports the current kubeconfig for an existing cluster, reuses
   PKI/Secrets/PVCs and waits for rollouts. It does not recreate existing kind nodes.
4. Confirm 12/12 workloads ready, Identity health and certificate-verified Device
   Gateway readiness. The Inspector should show the actual cluster state.
5. Compare container IDs, Volume names, PVC UIDs and credential/counter state with
   the snapshot. Complete an existing Passkey login manually to prove enrollment
   remains usable. Persistent records must not be deleted to make startup pass.
6. A Desktop restart result does not establish full Windows reboot acceptance;
   report those separately. The final delivery states which was actually executed.

## Dashboard acceptance

Check all three sidebar links, deep-link reload, browser back/forward, and manual
scroll in both directions. Demo Mode shows the main flow. Inspector Mode reveals
raw evidence, claims, policies and public certificates at the bottom. Verify a
real invalid-JWT 401, producer-based rejection state, and zero-execution query;
unobserved stages must remain unknown. Hardware login steps remain manual above.

## Remaining boundaries

No HA/load/rotation soak test, no full Windows reboot claim, and no Phase 2 or
multi-location implementation. Application/network authorization remains fail-closed.
