# 架構與流程（SP 800-207）

```mermaid
flowchart TB
  Browser[Human / Browser Passkey] --> Agent
  subgraph edge[Edge / Device Agent]
    Agent[Dashboard + Device Agent\nX.509 device-a]
  end
  subgraph control[Control Plane - internal Docker network]
    ID[Identity / WebAuthn RP]
    PA[Policy Administrator / FastAPI]
    PE[Policy Engine / FastAPI]
    Context[Context Service]
    CDM[Device Posture / CDM]
    TI[Threat Intelligence]
    DB[(Policy DB / SQLite)]
    Logs[(Telemetry / Activity Logs)]
    PE --> Context
    Context --> CDM & TI & DB & Logs
    PA --> ID
    PA -->|evaluate / grant-deny-revoke| PE
    Agent -->|WebAuthn ceremony proxy| ID
    Agent -->|local simulation console| Context
  end
  PEP[Envoy PEP\nGateway]
  Agent -->|mTLS / human token then scoped session| PEP
  PEP -->|ext_authz every request| PA
  PA -->|authorization / revocation| PEP
  subgraph data[Data Plane - internal Docker network]
    Resource[Protected FastAPI Resource\nNo host port / upstream mTLS]
  end
  PEP -->|ALLOW only / dedicated PEP certificate| Resource
  Resource -.->|resource-only mTLS callback via PEP| PA
```

Envoy 同時連接 edge/control/data；它是受信任的 gateway，不是 sidecar。PE/PA 是分開的 process 與 service；PDP 是兩者的邏輯組合。Diagram 中 CDM/TI/Policy DB/Logs 是 Context service 的邏輯模組，沒有假稱為獨立產品。

```mermaid
sequenceDiagram
  participant H as Human / Browser
  participant A as Device Agent
  participant I as Identity
  participant G as Envoy PEP
  participant PA as PA
  participant PE as PE
  participant C as Context / Policy / Logs
  participant R as Resource
  H->>I: Registration / assertion through Dashboard
  I->>I: Verify challenge, origin, RP ID, UV, signature, counter
  I-->>H: Short-lived human identity token
  H->>A: Request session for resource
  A->>G: mTLS + human token + scope
  G->>PA: /session + verified certificate SAN
  PA->>I: Introspect human token
  PA->>PE: Identity + Device + Request
  PE->>C: Policy, posture, threat, recent activity
  PE-->>PA: ALLOW / DENY + risk/trust/reasons
  PA-->>A: Scoped, device-bound session or DENY
  A->>G: Resource request + session over mTLS
  G->>PA: ext_authz, sanitized device identity
  PA->>PE: Reevaluate scope and request
  PA-->>G: Permit + subject/session headers or 403
  G->>R: Authorized request over upstream mTLS
  R-->>H: Resource data via PEP and Agent
  C->>C: Compromise / risk / policy change
  loop background continuous evaluation
    PA->>PE: Active session scope + current inputs
    PE-->>PA: REVOKE
    PA->>PA: Persist REVOKED state, audit action
  end
  A->>G: Subsequent request
  G->>PA: ext_authz
  PA-->>G: 403 - session revoked
  G-->>A: Blocked
  R->>G: Stream session-state callback (resource cert)
  G->>PA: /status/session
  PA-->>R: REVOKED via PEP
  R-->>H: revoked event, stream ends
```

## 與 NIST 對齊

| SP 800-207 概念 | 本 Demo |
|---|---|
| §3.1 PE 最終 grant/deny/revoke decision | `app/pe.py` + `app/trust.py` |
| §3.1 PA 建立/停止路徑，執行 PE 決策 | `app/pa.py` scoped session lifecycle + Envoy ext_authz |
| §3.1 PEP 建立、監控、終止存取 | Device agent + Envoy gateway；逐請求 gate 與 stream cooperative termination |
| §3.2.1 Device Agent/Gateway | Agent 持 device private key，Gateway 在 Resource 前 |
| Control/Data plane | separate internal Docker networks，只有 PEP 跨接 |
| §3.3 Trust algorithm | necessary conditions + score，讀取 identity/device/policy/threat/history |
| Dynamic policy / continuous evaluation | 每請求 + periodic session evaluation；新訊號與政策即時影響決策 |
| Least privilege | exact method/path grants + session scope |

必要條件：human token 有效、device managed 且未 compromised、scope 在 grants 中。Risk weights：OS outdated 30、high-risk IP 70、abnormal 60，累計上限 100；trust=100-risk，預設門檻60。Compromised 是 hard gate，可能 trust=100 仍 REVOKE，因 score 不能蓋過必要條件。數值是展示用策略，不是 NIST 規定。

Source: [NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf), [Envoy ext_authz](https://www.envoyproxy.io/docs/envoy/v1.33.2/configuration/http/http_filters/ext_authz_filter), [py_webauthn](https://duo-labs.github.io/py_webauthn/).
