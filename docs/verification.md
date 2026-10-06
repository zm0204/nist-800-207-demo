# 驗證紀錄

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
