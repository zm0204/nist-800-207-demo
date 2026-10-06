# NIST SP 800-207 Demo 設計

使用者已指定並授權建立 Docker Compose、Envoy PEP、分離的 FastAPI PE/PA、Resource，以及 Identity、CDM、Threat Intelligence、Telemetry 與 Policy DB。本文件將該範圍具體化，不引入 800-207A service mesh。

## 元件與信任邊界
Dashboard 同時是本機示範裝置的 agent。瀏覽器透過 localhost 的 WebAuthn API 建立、驗證 Passkey；Identity 驗證 challenge、origin、RP ID、簽章、user verification 與 counter，發出短效 opaque human token。Agent 以 device-a X.509 憑證與 Envoy 做 mTLS，將 human token 換成 PA 建立的 device-bound session。Envoy 清除偽造的身分標頭，使用驗證過的憑證 SAN 透過 ext_authz 向 PA 詢問每一次請求的授權。

PE 讀取 Context service 提供的 identity/device/context/policy/history 快照；Policy DB 與 telemetry 分別持久化到 SQLite。必要條件為有效且未過期 human identity、受管理且未 compromised device、method/path 的 least privilege。風險為 outdated OS 30、high-risk IP 70、異常行為 60；trust=100-risk，policy threshold 預設 60。必要條件失敗或低於門檻：新存取 DENY、已授權範圍 REVOKE。其他路徑的 least-privilege DENY 不撤銷原本合法 scope。

PA 每輪結束後等待一秒，再重評估 active session，更新 session lifecycle，Envoy 後續 ext_authz 即拒絕 revoked session。控制服務逾時與 session 數量會增加延遲，不能視為一秒內保證。Resource 的示範 SSE stream 每秒經 PEP 的 resource-only mTLS callback 詢問 PA 狀態，收到撤銷或控制服務失聯即結束串流。已完成的回應無法追回；這不是任意 TCP 連線撤銷實作。

## 網路
edge: agent/Envoy；control (internal): Envoy/PA/PE/Identity/Context/Dashboard；data (internal): Envoy/Resource。Resource 無 host port、只接受 Envoy 的 upstream mTLS 憑證；resource callback listener 只接受 resource 憑證。Host 僅公開 localhost:8080 Dashboard 與 localhost:8443 PEP。

## 簡化邊界
預先指定 alice 與 device-a；首次 passkey enrollment 是本機 Demo bootstrap，非真實身分查核。Dashboard 的 simulation endpoints 是本機操作台。CDM/threat feeds 為模擬；abnormal 除按鈕也能由真實請求數觸發。Control plane HTTP 在 internal Docker network 上以 service key 控制；production 須加服務 mTLS、獨立 enrollment/admin 授權、credential recovery、HA 與集中式 log protection。

## 驗收
真實 Passkey ceremony 和軟體 authenticator 的加密協定測試；正常 ALLOW、POST salary least privilege DENY、compromise continuous REVOKE、IP risk、abnormal、host bypass 失敗；額外覆蓋過期、重播、偽造身分、無憑證、policy change 與 fail closed。Docker 無法使用時必須標註 compose 未驗證，不以替代測試宣稱容器成功。
