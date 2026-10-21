# 207A verification evidence

## Interactive console added on 2026-10-21

- Full Python suite: **86 passed** (one existing Starlette/AnyIO deprecation warning).
- All **8 individual scenarios** were clicked and passed in the actual browser against
  the existing local Kubernetes cluster; [captured results](evidence/2026-10-21/console-scenarios.json).
- The browser's full verification button ran the actual external verifier: **23/23 passed**,
  followed by the parent operator's policy/replica restoration; all 9 Deployments ready.
  [Fresh verifier evidence](evidence/2026-10-21/mesh-external.json).
- The certificate button displayed all 8 current public SPIFFE identities; the PE audit
  panel read actual service decision events from Context.
- Disposable fault-injection QA on a separate loopback port returned two consecutive
  polling 503s: the page resumed the original job and showed PASS with exactly one
  operation, without resubmitting it. A subsequent status-read failure cleared the old
  green security/workload snapshot and displayed its last observation time.
- An independent read-only review identified timeout recovery, token-free GET actions,
  abandoned polling, stale status, and route-label issues. These were addressed; recovery,
  locking and GET boundaries have failing-then-passing Python regression tests, and the
  polling/status fixes were exercised in the browser as above.
- Desktop visual QA passed. Responsive CSS is included; this host's browser viewport
  override did not actually change the DOM width, so narrow-screen visual QA is **not claimed**.

The new controller is host-side and loopback-only; mesh application images/manifests and
the original 207 flow are unchanged. [Console operation and recovery guide](207a-console.md).

## Deployed again on 2026-10-20

The Windows host now runs the dedicated `zta-207a` kind cluster with PE external
authorization enabled. Fresh checks passed: base **14/14**, external **23/23**,
Python **69/69**, isolated original Compose PE/PA regression **9/9**, and all three
localhost preview routes returned **200**. Tested application revision remains
`30e8911dbfeb7404464ee06c7405c1ea6d9ecc40`; the follow-up changes add deployment
documentation and evidence only. See the [deployment handoff](207a-deployment-2026-10-20.md)
and [committed JSON evidence](evidence/2026-10-20/mesh-external.json).

Environment: Windows / Docker Desktop Linux engine 29.8.2, Python 3.12.
Reference base: `d629f859c24b471934c1517714fc676cdd618e42`.

## Completed local checks (2026-10-15)

- Existing main baseline: **34 passed**.
- Full suite with mesh dependencies: **69 passed**, including real gRPC transport
  and Envoy v3 protobuf requests. One pre-existing Starlette/AnyIO deprecation warning.
- New tests first failed against missing services, PE endpoint and gRPC adapter;
  the full suite passed after implementation.
- Separate mesh image `zta-207a:local` built successfully, running application UID 10001.
- Original Compose demo rebuilt on this branch and verified in an independent project
  `zta207a-regression`, using localhost **18080 / 18443**. The user's existing project
  on 8080 / 8443 was not stopped or modified. **All 9 grouped actual Envoy/mTLS checks passed**:
  normal access; least privilege; compromise revocation; high-risk IP; abnormal behavior;
  bypass isolation; certificate/session binding and forgery; active SSE termination;
  PE outage fail closed. Machine-readable evidence: `artifacts/compose-verification.json`.
- Mesh YAML documents parsed, script compiled, CLI help rendered, and Git whitespace checked.

## Live Kubernetes checks

Tested implementation revision: `de2b2ca4e4f6b4e11363983fe57b65843eacd19d`.
Both GitHub Actions workflows succeeded on that exact revision:

- [207A base and external mesh, PR run](https://github.com/zm0204/nist-800-207-demo/actions/runs/38702248252)
- [Original 207 Compose regression, PR run](https://github.com/zm0204/nist-800-207-demo/actions/runs/38702248296)
- [Download the mesh JSON/status/log evidence](https://github.com/zm0204/nist-800-207-demo/actions/runs/38702248252/artifacts/11956214384)

Actual Kubernetes **v1.35.0**, Istio **1.31.1**, kind **v0.33.0**:

| Mode | Result |
|---|---|
| Base: probe → frontend → two backends plus negative paths | **14/14 passed** locally and in CI |
| External: base checks plus protected PE, ConfigMap reload, adapter/PE/audit outages and restoration | **23/23 passed** locally and in CI |
| Certificate identity, validity and lifetime | All required injected workloads inspected; **3720 seconds** (1h + 2min issuer backdating) |

The native Sidecar is a Kubernetes restartable init container in this environment;
the verifier supports both that format and the classic extra-container format.
The first CI attempt caught the original verifier's classic-only assumption; an
8-test evidence regression suite now covers both formats and certificate validity.
Independent review also caught the need to configure agent `SECRET_TTL` as well as
the CA default; both are now set and verified against actual public certificates.

Direct Pod IP returned 503; a subsequent normal service call returned 200. This is
evidence of unsuccessful direct access, not attribution to a particular rejection
layer: routing, TLS, or RBAC can all produce that result. Wrong-SA service requests
and forged-header requests returned 403; plaintext returned a connection error.
The frontend outbound salary cluster was separately inspected: its transport socket
was `envoy.transport_sockets.tls` and `maxConnectionDuration` was `1800s`.

The verifier records actual runtime versions, active public certificate SPIFFE SANs
and expiry, each HTTP result, and overall success in `artifacts/mesh-base.json` and
`artifacts/mesh-external.json`. It never writes raw Envoy secrets or private keys.
CI uploads these files and non-secret status/proxy logs as `mesh-verification-results`.

Known non-failing diagnostics: Istio analyze warns that the wildcard DestinationRule
host does not match a concrete Service name; the applied outbound cluster was checked
as above. Istio reports the legacy injection annotation as deprecated; the pinned
release injects successfully. CI also reports upstream GitHub Action Node runtime
deprecations, and the Python suite reports the existing Starlette/AnyIO warning.
No failed tests are hidden by these warnings.

## Deliberate limits

- No enforcing-CNI NetworkPolicy result on default kindnet.
- No multi-cluster/cloud, trust federation or east-west gateway test.
- No end-user JWT propagation or bridge from the original Passkey/device sessions.
- No long-duration certificate rotation, enterprise monitoring, production HA or NIST certification claim.

See [deployment, architecture and negative test matrix](207a-mesh.md).
