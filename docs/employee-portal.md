# 員工服務與存取監控

新版以 `542fee9` 為基底，保留原 Inspector。員工頁只提供 Salary／Profile 讀取，所有資料與拒絕均來自原有受保護服務；沒有前端 ownership 模擬，也沒有驗證 bypass。

## 本次可開啟的獨立環境

- 員工頁：http://localhost:18091/portal
- 監控頁：http://localhost:18091/observer
- 說明頁：http://localhost:18091/about
- 原 Inspector 路由：http://localhost:18091/inspector（管理 API 另外驗證本機管理憑證）

`scripts/portal_demo.py` 固定指向 **kind-zta-portal-p0**，使用獨立 image `zta-portal-p0:local`、工作樹內 `.tmp/portal-p0` PKI／kubeconfig 與該叢集自己的 PVC。Namespace 仍為 `zta-identity`，因此既有 SPIFFE／接收端政策完全沿用。Identity／Gateway tunnels 使用 19082／19443；不會占用既有展示的 18081／18082／18443。

從本工作樹執行（Windows，這次沿用相鄰原工作樹的 Python 環境；不修改其中的程式）：

```powershell
..\zta-207a\.venv\Scripts\python.exe scripts/portal_demo.py deploy
..\zta-207a\.venv\Scripts\python.exe scripts/portal_demo.py serve
# 另一個終端，僅針對上述專屬驗收環境
..\zta-207a\.venv\Scripts\python.exe scripts/portal_demo.py verify
```

首次以 Windows Hello／硬體 Passkey 操作此新環境時，需要新增自己的金鑰。管理者在本機執行下列命令，選 Alice／Bob，再使用保留 Inspector 的「註冊 Passkey」；這只新增憑證，不刪除已註冊公鑰。之後回到員工頁登入。

```powershell
..\zta-207a\.venv\Scripts\python.exe scripts/open_inspector.py --isolated
```

管理憑證放在本工作樹忽略的 `.tmp/portal-p0/operator.key`，透過 URL fragment 交給 Inspector，讀取後立即移除 fragment，只留在該頁記憶體；不寫入瀏覽器 localStorage／sessionStorage，不透過公開 API 提供。重新整理 Inspector 後請重新執行上述 helper。它代表本機操作者，**不是 Bob 的 HR 身分**。本機 OS／Docker 管理者仍在本展示信任邊界之外。

既有一般環境的命令仍是 `scripts/security_inspector.py`（18081）及 `scripts/open_inspector.py`，但本次未替換正在執行的舊環境。新 Portal 使用相同既有 WebAuthn origin；獨立驗收環境則明確使用 localhost:18091。

## UI／API contract

此 contract 供後續 UI 協作沿用，前端不持有 human token、PA Session 或 JWT。

| 方法／路由 | 輸入與結果 |
|---|---|
| GET `/api/portal/session` | `{subject: null\|alice\|bob, csrf}`；CSRF 不授予身分或管理權限 |
| POST `/api/portal/login/options` | `{subject: alice\|bob}`；回傳原 Identity challenge，綁定 HttpOnly login ceremony cookie |
| POST `/api/portal/login/verify` | `{ceremony, credential}`；真正 WebAuthn 驗證及受保護 introspection 後，回傳 `{subject, csrf}` 並輪替 HttpOnly／SameSite=Strict 員工 cookie |
| POST `/api/portal/access` | 僅 `{resource: salary\|profile, owner: alice\|bob\|carol}`；回傳 202 `{id, state, attempt_id}` |
| GET `/api/portal/jobs/{id}` | 僅目前登入 session 自己的工作；完成結果含實際 HTTP、後端 synthetic data、Attempt／Request ID 及證據階段 |
| POST `/api/portal/logout` | `{}`；清除本機員工 session，登入逾期後也可登出 |
| GET `/api/observer/attempts` | 固定 `{alice: summary\|null, bob: summary\|null}`；另一人的最近請求持續保留 |
| GET `/api/observer/attempts/{attempt_id}` | 已快取的安全明細；不回傳薪資內容、JWT、Session、完整 claims 或私鑰 |

員工寫入 API 需要 `x-portal-csrf`；同時檢查同來源與 JSON。額外欄位、攻擊模式、任意 method／path／command 不接受。所有舊 `/api/identity`、`/api/agent`、`/api/inspector`、`/api/console` 路由，包括讀取管理 token，均要求獨立 `x-operator-key`；舊的 mutation CSRF 檢查仍保留。

全球仍一次一筆工作（員工與 Inspector 共用）。忙碌回傳 409，不會執行另一個保護資源請求。已接受的工作在建立 PA Session／交換 JWT **之前**分配 Attempt ID；PA 提前拒絕與傳輸錯誤也有可追查結果。每次 access 以 Identity introspection 確認真實 subject，再使用相同裝置 mTLS 建立／重用 PA Session、交換短效 JWT 並發出真正 GET。

Observer 每兩秒輪詢記憶體快取，明細只在 Attempt 變更後取得，不執行 kubectl。伺服器重啟後快取清空，畫面保持「尚無請求」，不載入歷史檔案偽裝成即時請求。最多保留 90 筆安全 Attempt 明細與 30 筆工作；Alice／Bob 最新快照保留到下一筆或程序重啟。

## 證據規則

- 綠線：該段有元件正向證據。既有 Session 的當次有效性只能由成功 PA exchange 的重新驗證建立，不能假造一次未執行的 `/session` 200。
- 紅線：該元件已觀測的拒絕。PA exchange 拒絕顯示在交換階段，不會捏造 PE DENY。
- 灰線：節點文字分別顯示「未到達」「未觀測」或「未知」；沒有來源不推論成成功／失敗。
- 接收端順序為 **CUSTOM → Native DENY → Native ALLOW**。CUSTOM 拒絕後 Native 保持未觀測；`rbac_access_denied` 只能確認原生授權拒絕，無法辨識命中 DENY 或缺少 ALLOW 時不強行細分。
- 只有真正成功查詢兩個後端 Journal 且該 Attempt 零筆，加上拒絕證據，才標記 Resource `NOT_REACHED`。查詢失敗維持未觀測。
- 傳輸失敗使用 `status: 0` 加上錯誤類別，UI 顯示連線失敗；不稱為 HTTP 403。
- Request／Attempt ID 用於關聯，不是授權證明；Envoy 可能重新產生各 hop 的 Request ID。Workload SPIFFE 與 Alice／Bob 的 end-user identity 各自驗證。

## 驗證方式與限制

```powershell
..\zta-207a\.venv\Scripts\python.exe -m pytest -q --basetemp=.tmp/portal-tests
node --test tests/portal_ui.test.cjs
```

真實整合驗收經過正在執行的 Portal HTTP、Identity WebAuthn signature 驗證、裝置 X.509／Envoy、PA Session／JWT、Istio receiving sidecar、PE 及 Resource Journal。測試專屬 software authenticator 只存在測試程式；伺服器沒有測試登入端點或驗證捷徑。此結果不代表已替使用者完成 Windows Hello／硬體金鑰的人工操作。

本次沒有增加 Profile 修改、NetworkPolicy／CNI、Egress、Vault、多叢集協調或完整 tracing。為保留可檢視的環境，不自動刪除測試叢集、PKI、測試金鑰或 PVC。
