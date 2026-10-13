# 驗證紀錄

## 2026-10-13：Dashboard 決策語義與請求對應

Dashboard 的 PDP 標籤顯示 PE + PA 的整體授權結果，另列 PE 政策決策、PA Session 授權與原因、PEP 執行結果。Salary Session 請求 Profile 時保留真實的 PE `ALLOW`，PA 顯示 `DENY_REQUEST`／`Session Scope Mismatch`，整體為 `DENY`／`403 BLOCKED`；原 Session 維持 `ACTIVE`，後續 Salary 仍成功。`app/trust.py` 的政策評估邏輯未修改。

每個 PA 動作保存 `action_id`、`operation`、`session_ref`、請求與授權範圍、`policy_evaluation`、`pa_reason`、`pdp_decision`、`pep_state`。事件的舊 `decision` 欄位仍代表真正的 PE 結果；手動／fail-closed 撤銷的 `policy_evaluation` 是 `null`，不宣稱 PE 回傳 REVOKE。Session 的舊 `last` 保留既有狀態／callback 相容性，不能當作最近請求結果。

主畫面從目前 Session 的 `last_action` 讀取完整動作，`last_request_action` 另保存最近資源請求。背景 ALLOW 只更新持續評估，不取代動作；背景撤銷明確標示來源，保留最近請求。其他 Session 的事件與最近 100 筆事件的保留上限不影響主畫面。舊 Session 在產生新動作前顯示缺少可對應紀錄；控制平面失聯時明確標示為上次紀錄。

`http_status` 是 **PA 授權回應**，`200 FORWARD` 只表示允許轉送，實際資源 HTTP 由「資源回應」顯示。背景／管理者撤銷沒有請求 HTTP。被拒絕的裝置／已撤銷 Session 嘗試使用 `request_rejected` 事件，不增加既有已授權請求流量訊號。活動紀錄仍不保存 bearer secrets。

本機 Windows／Docker Desktop 驗證：

- `python -m pytest -q`：**42 passed**；仍有一項既有 Starlette/AnyIO deprecation warning。
- `node --test tests/test_ui_decisions.cjs`：**9 passed**；CI 同步執行此測試。
- `node --check static/app.js`、`git diff --check`：通過。
- `scripts/verify.py`：獨立 Docker Compose + 真實 Envoy + mTLS，**11 groups passed**，涵蓋 scope mismatch／背景 tick／Salary 恢復、政策 DENY、背景與手動 REVOKE、SSE 撤銷、PE 停機 fail closed、憑證綁定與 Resource 隔離。
- 真實 Edge 使用測試用虛擬 WebAuthn 認證器操作 Dashboard：Passkey、ALLOW、scope mismatch、Salary 恢復、policy DENY、手動／背景撤銷通過；1440px 桌面與390px手機畫面已檢視，無水平溢出或前端例外。瀏覽器保留設定的 localhost:8080 origin，測試路由將所有流量轉至隔離環境，不操作既有展示服務。

CI 補驗捕捉到 PE 停機的兩種合法順序：請求先遇到 outage 而撤銷，或背景先撤銷、後續請求回報 `session_revoked`。整合測試分別核對持續撤銷原因與最近動作；新增 deterministic regression，避免把背景原因強加給後續請求。

以下為先前版本的歷史驗證紀錄。

日期：2026-10-06（Asia/Taipei）。實際 Docker/Envoy 已在 GitHub Actions Linux runner 驗證通過。

## 實際 Docker / Envoy 證據

[成功 Run #3](https://github.com/zm0204/nist-800-207-demo/actions/runs/37464773674)，commit `7ca2021b722210c7ffcc19a30f6eeb34c7553740`，2026-10-06 20:39（Asia/Taipei）。Job `verify` 所有步驟成功：unit/service tests、PKI、Compose configuration、Envoy --mode validate、Compose up --build --wait、real scenarios、artifact與cleanup。

`scripts/verify.py` 输出 **9 groups passed**：

1. Normal ALLOW -> 真正 Protected Resource 200。
2. Least privilege DENY -> PEP 403。
3. Compromise -> 自主背景 REVOKE -> PEP blocked。
4. High-risk IP -> REVOKE。
5. Abnormal behavior -> REVOKE。
6. Resource 無 host published port，非data agent不能直連 bypass。
7. Certificate/session binding、spoofed XFCC、missing certificate均拒絕。
8. Active SSE stream 在 REVOKE 後終止。
9. PE unavailable -> fail closed與session撤銷。

前兩次CI正常存取時得到upstream503。經sanitized log確認PE/PA為ALLOW，根因是Uvicorn預設TLSv1 cipher selector與Envoy upstream預設TLS1.2套件不相交。已先以本機限定TLS1.2握手重現RED，再明確設定ECDHE-RSA AES-GCM套件。TLS1.2/1.3本機握手通過，Run #3完整通過；没有降低或關閉certificate verification。

## 已實際完成

- Python 3.12，本機 `python -m pytest -q`：**34 passed**。一個來自 Starlette/AnyIO 的 deprecation warning，未影響結果。
- `python scripts/local_smoke.py`：**10 checks passed**。啟動真正的 Identity、Context、PE、PA、Resource、Dashboard HTTP process，WebAuthn cryptographic ceremony、正常/least privilege、compromise/high-risk/abnormal 的自主週期重評估、outdated trust70、dynamic policy、cross-origin console rejection，以及真正的 TLS handshake（Resource 接受 PEP cert、拒絕持 device cert 加偽造身分標頭者）。
- Python compileall、Dashboard JS syntax check：通過。
- Compose YAML/topology tests、certificate EKU/SAN/CA 與 initializer idempotence：通過。
- Stream unit tests：REVOKE 與控制服務 unavailable 均終止 generator。
- 獨立 read-only review 找出 Envoy router 的 header removal 會刪除 ext_authz 新增的授權標頭。已改為 ext_authz 之前的 Lua sanitization，並加入 RED→GREEN regression test。
- Activity logs 不保存 human/session bearer secrets 的 regression test：通過。

## 驗證環境的區別

這台本機Windows執行環境 `docker` 不存在；因此上述Docker證據來自真正啟動容器的GitHub Actions Linux runner，不是本機Docker Desktop。local smoke 的 PA check 明確由 test 注入 trusted PEP certificate metadata；不能獨自證明Envoy或Docker隔離，這兩項由Run #3補驗。

提供 `.github/workflows/verify.yml` 與 `scripts/verify.py`，會真正執行：

1. Compose config / Envoy `--mode validate`。
2. `docker compose up --build -d --wait`。
3. 六個展示情境，Resource200、PEP403、continuous revoke。
4. Host Resource 無 published port、非data agent無法直連。
5. Device/session mismatch、spoofed XFCC、missing certificate。
6. 既有 SSE stream 在 revoke 後終止。
7. PE 停機時 fail closed。

後續程式變動仍應以對應commit的CI為準，不以早先通過或單元測試取代。

## 範圍與限制

Risk weights是demo策略；首次enrollment為local bootstrap；CDM/TI模擬。PA serial evaluation 每輪後等待一秒，但 session 數量與逾時會影響反應延遲。Control plane使用internal Docker HTTP+service key，非production service mTLS。SSE採resource合作終止，未實作任意TCP reset或已送出資料追回。Host Docker admin可以控制內部網路，超出示範威脅模型。
