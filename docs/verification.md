# 驗證紀錄

日期：2026-10-06（Asia/Taipei）。請以後續 CI 的 commit/run 結果確認 Docker 狀態。

## 已實際完成

- Python 3.12，本機 `python -m pytest -q`：**34 passed**。一個來自 Starlette/AnyIO 的 deprecation warning，未影響結果。
- `python scripts/local_smoke.py`：**10 checks passed**。啟動真正的 Identity、Context、PE、PA、Resource、Dashboard HTTP process，WebAuthn cryptographic ceremony、正常/least privilege、compromise/high-risk/abnormal 的自主週期重評估、outdated trust70、dynamic policy、cross-origin console rejection，以及真正的 TLS handshake（Resource 接受 PEP cert、拒絕持 device cert 加偽造身分標頭者）。
- Python compileall、Dashboard JS syntax check：通過。
- Compose YAML/topology tests、certificate EKU/SAN/CA 與 initializer idempotence：通過。
- Stream unit tests：REVOKE 與控制服務 unavailable 均終止 generator。
- 獨立 read-only review 找出 Envoy router 的 header removal 會刪除 ext_authz 新增的授權標頭。已改為 ext_authz 之前的 Lua sanitization，並加入 RED→GREEN regression test。
- Activity logs 不保存 human/session bearer secrets 的 regression test：通過。

## 尚須實際 Docker/Envoy 確認

這台執行環境 `docker` 不存在，標準 Docker Desktop 路徑也不存在；沒有宣稱 Compose 已啟動。local smoke 的 PA check 明確由 test 注入 trusted PEP certificate metadata，不是 Envoy；它不能證明 Envoy routing/configuration 正確，也不能證明 Docker host network isolation。

提供 `.github/workflows/verify.yml` 與 `scripts/verify.py`，會真正執行：

1. Compose config / Envoy `--mode validate`。
2. `docker compose up --build -d --wait`。
3. 六個展示情境，Resource200、PEP403、continuous revoke。
4. Host Resource 無 published port、非data agent無法直連。
5. Device/session mismatch、spoofed XFCC、missing certificate。
6. 既有 SSE stream 在 revoke 後終止。
7. PE 停機時 fail closed。

CI通過後可用該次run作為實際Docker驗證證據。若CI失敗，應先查看log修復，不以單元測試取代。

## 範圍與限制

Risk weights是demo策略；首次enrollment為local bootstrap；CDM/TI模擬。PA serial evaluation 每輪後等待一秒，但 session 數量與逾時會影響反應延遲。Control plane使用internal Docker HTTP+service key，非production service mTLS。SSE採resource合作終止，未實作任意TCP reset或已送出資料追回。Host Docker admin可以控制內部網路，超出示範威脅模型。
