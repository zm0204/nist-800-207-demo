# NIST SP 800-207 Zero Trust Architecture Demo

以 **SP 800-207 本身**為藍本的 Device Agent/Gateway 展示，非 800-207A service mesh。Human 用 Passkey/WebAuthn、Device 用 X.509/mTLS；PDP = 分開的 PE + PA，Envoy 是 gateway PEP。

> **實際 Docker 驗證已通過**：[GitHub Actions Run #3](https://github.com/zm0204/nist-800-207-demo/actions/runs/37464773674)，包含 Compose 啟動、真正 Envoy/mTLS 與六個展示情境，另外驗證憑證綁定、串流撤銷與 PE 停機 fail closed。34 個本機測試也通過。詳細證據见 [docs/verification.md](docs/verification.md)。

## 快速啟動（Windows / Linux / macOS）

需要 Docker Desktop（Linux containers）或 Docker Engine + Compose v2，Python 3.12，支援 WebAuthn 的 Chrome / Edge 與 Windows Hello、Touch ID、安全金鑰或可用 Passkey provider。請用 **http://localhost:8080**；RP ID 固定 localhost，不能改用 LAN IP。

在本專案根目錄：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe scripts/init.py
docker compose config --quiet
docker compose run --rm --no-deps pep envoy --mode validate -c /etc/envoy/envoy.yaml
docker compose up --build -d --wait --wait-timeout 180
docker compose ps
```

Linux/macOS：使用 `.venv/bin/python` 取代 `.\.venv\Scripts\python.exe`，其他命令相同。請用一般使用者執行初始化，勿用 sudo；`.env` 的 ENVOY_UID 對齊私鑰擁有者，Envoy 保持非 root。Windows bind mounts 權限由 Docker Desktop 處理。憑證生成不需要 OpenSSL，也不需要匯入到系統憑證庫：裝置私鑰由 agent 保管。

開啟 [Dashboard](http://localhost:8080)。沒有帳號密碼輸入框，alice 是預先配置的 subject；Windows Hello 可能要求本機 PIN/生物辨識，這是 Passkey 的 user verification，不是輸入伺服器帳密。

## 展示流程

1. 點 **建立 Passkey**，完成瀏覽器 enrollment。alice 只允許首次註冊，避免其他人覆蓋公鑰。這是本機 demo bootstrap，不代表 production 身分核驗。
2. 點 **使用 Passkey 驗證**。Identity 真正檢查 challenge、origin、RP ID、UV、signature、counter；發出 15 分鐘 human token。
3. Resource 選 `/api/salary`，點 **建立 Session**，再 **正常 GET**。Agent 經 device-a mTLS → Envoy → PA → PE；ALLOW 後才轉送 Resource。
4. 看 Subject、Device、Request、Context、Trust Score、PE Decision、PA Action、PEP State 及右侧日志。

| 情境 | 操作 | 預期 |
|---|---|---|
| 1 正常 | Reset Signals → 建立 Session → GET | trust100、ALLOW、AUTHORIZE_REQUEST、FORWARD、Resource200 |
| 2 Least privilege | 已有 salary GET session → POST /salary | DENY_REQUEST / 403；原 GET scope 仍可用 |
| 3 Compromised device | 正常 session → Compromise Device，等待重評估 → GET | PE REVOKE、PA REVOKE_SESSION、PEP BLOCKED / 403 |
| 4 High-risk IP | Reset → 新 session → High-risk IP | risk70、trust30、REVOKE；新 session DENY |
| 5 Abnormal behavior | Reset → 新 session → Abnormal Traffic，或送出14次請求 | risk60、trust40、REVOKE；真實請求達12次/10秒也觸發 |
| 6 Bypass PEP | 跑 `scripts/verify.py` 網路探測，檢查 compose ports | Resource 無 host port、agent 不在 data network、直接連線失敗 |

Reset Signals 只重設訊號、政策與 demo history，**不會復活撤銷的 session**。每次風險情境前重設並新建 session。Outdated OS 扣30分、trust70，門檻60仍 ALLOW；把門檻改80再更新 Policy 即撤銷。移除 Alice 權限展示 dynamic least privilege policy。Revoke Session 是管理者主動撤銷。

持續存取：Resource 選 `/api/stream` → 建立 Session → 開啟持續串流 → Compromise Device 或 Revoke Session。串流發出 revoked event 後終止；已完成的 HTTP 回應無法追回。背景重評估每輪後等1秒，實際延遲還包括服務回應與 session 數量，非硬性1秒保證。

## 架構與實作

詳見 [Mermaid 架構/序列圖與 NIST mapping](docs/architecture.md) 及 [設計](docs/design.md)。

```text
app/identity.py   WebAuthn RP, credential/challenge/token SQLite
app/context.py    CDM、Threat Intel、Policy DB、Telemetry SQLite
app/trust.py      Necessary conditions + risk score
app/pe.py         Policy Engine（只決策）
app/pa.py         Policy Administrator（session/continuous evaluation）
app/resource.py   Protected APIs + revocable SSE stream
app/dashboard.py Browser console + device agent / mTLS client
static/          Dashboard HTML/CSS/JS（無外部 CDN）
envoy/           Gateway PEP、ext_authz、mTLS、stream status callback
scripts/init.py  本機 CA / 憑證 / random service key（不覆蓋現有 PKI）
scripts/verify.py 真實 Compose/Envoy end-to-end verification
scripts/local_smoke.py 本機 HTTP+TLS integration verification
tests/           加密協定、政策、session、fail-closed、stream與網路配置測試
```

PE/PA/Identity/Context 不公開 host port。Resource 只在 data network 上、無 host port，還要求 dedicated upstream-client CA 簽發的 PEP certificate。主 PEP listener:8443 接受 device CA；callback listener:9444 只接受 resource SAN。Envoy 清除偽造 x-zta headers，再讓 PA 設定授權身分；XFCC 由 SANITIZE_SET 替換為已驗證憑證 SAN。Host 僅綁127.0.0.1的8080與8443。

Policy DB、CDM、threat context 與 logs 以 Context service 的獨立邏輯模組展示；不是宣稱已接入企業 IdP/CDM/SIEM。High-risk IP 是可信操作台設定的模擬 context，**不採信客戶端自行輸入的 X-Forwarded-For**。PA session綁定 human token與device certificate，再限制method/path。Audit記錄session雜湊參照，不記bearer token；PA狀態DB與本機console含session憑證，屬privileged demo資料。

## 測試

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/local_smoke.py
```

要測真正 Envoy/Docker，在**全新的獨立 demo stack**、還沒有用瀏覽器註冊 Passkey時執行：

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
```

它用 test-only software authenticator 產生真正的 WebAuthn 簽章（server無bypass），透過真正mTLS/Envoy驗證六情境、憑證不匹配、偽造標頭、無憑證、SSE撤銷與PE停機fail closed。此腳本會操作模擬訊號、註冊alice測試憑證、暫停再重啟PE，請勿在正在展示的browser stack上執行。

為避免測試 enrollment占用browser的alice，可另開project：

```powershell
docker compose -p zta-verification up --build -d --wait
.\.venv\Scripts\python.exe scripts/verify.py
docker compose -p zta-verification down -v
```

上例需要原本展示stack已停止（host ports相同），且設定 `$env:COMPOSE_PROJECT_NAME='zta-verification'` 後再跑 verify.py，讓它內部的docker命令指向相同project；或直接在乾淨的預設project跑。`down -v` 會永久刪除該project的demo DB/Passkey enrollment。

## 停止、重新開始與排錯

`docker compose down` 停止但保留 DB；重啟後 PA 重評估原 session。要**明確清除全部 demo identity/policy/session/log DB**再註冊新Passkey，用 `docker compose down -v`。憑證與`.env`仍保留；換CA需先停止、明確移除certs再初始化，舊裝置憑證將失效。不要提交私鑰/DB。

- 找不到docker：安裝/啟動Docker Desktop，確認Linux containers與Compose v2；本專案不自動安裝系統服務。
- Envoy錯誤：先執行上述`--mode validate`，再查看`docker compose logs pep`。
- Certificate permission denied（Linux）：確認`.env` ENVOY_UID等於私鑰檔案擁有者uid，且不是0；不要放寬私鑰成world-readable。
- 503/403：查看`docker compose logs pa pe context identity`及Dashboard事件；服務不可用時本設計fail closed。
- browser WebAuthn NotAllowedError：確認localhost、支援的authenticator、已設定Windows Hello，並允許在使用者點擊後操作。不要用`127.0.0.1`替代localhost登入。
- 已註冊但無可用Passkey：這個精簡demo沒有credential recovery；明確清除demo volumes再enroll。

## 展示與 production 差異

這是可執行的教學架構，非NIST認證/完整企業部署。首次enrollment、模擬CDM/threat signals與localhost管理console有意簡化。Control plane在internal Docker network用random service key進行HTTP，production應使用服務mTLS、真正IdP/enrollment/admin授權、credential recovery/rotation、HA、受保護集中式log与real feeds。Docker network隔離不限制擁有Docker daemon/root權限的host管理員；他們屬本示範信任邊界之外。

[NIST SP 800-207 原文](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf) §3.1、§3.2.1、§3.3；Risk weights和threshold是本專案策略，不是標準規定。
