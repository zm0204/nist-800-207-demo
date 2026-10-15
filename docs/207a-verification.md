# 207A verification evidence

Environment: Windows / Docker Desktop Linux engine 29.8.2, Python 3.12.
Reference base: `d629f859c24b471934c1517714fc676cdd618e42`.

## Completed local checks (2026-10-15)

- Existing main baseline: **34 passed**.
- Full suite with mesh dependencies: **61 passed**, including real gRPC transport
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

The versioned setup and verification are in `scripts/mesh_demo.py`; the independent
`Verify 207A Mesh` GitHub Actions workflow runs both base and optional external modes.
Live Kubernetes/sidecar results are pending while the first local kind node image downloads.
Unit tests and a successful Docker build alone do not establish live mesh behavior.

The verifier records actual runtime versions, active public certificate SPIFFE SANs
and expiry, each HTTP result, and overall success in `artifacts/mesh-base.json` and
`artifacts/mesh-external.json`. It never writes raw Envoy secrets or private keys.
CI uploads these files and non-secret status/proxy logs as `mesh-verification-results`.

## Deliberate limits

- No enforcing-CNI NetworkPolicy result on default kindnet.
- No multi-cluster/cloud, trust federation or east-west gateway test.
- No end-user JWT propagation or bridge from the original Passkey/device sessions.
- No long-duration certificate rotation, enterprise monitoring, production HA or NIST certification claim.

See [deployment, architecture and negative test matrix](207a-mesh.md).
