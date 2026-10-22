# 207A 服務存取實驗台

> 歷史版本說明：目前 mesh_console.py 已改為整合式 [Zero Trust Security Inspector](identity-inspector.md)。下列固定情境與操作頁屬於重構前版本；現在請依新文件啟動 kind-zta-identity。

本機入口：**http://localhost:18081/**。這次新增中文操作頁；Kubernetes 內原本的
frontend、salary、profile、Istio 和 PE 繼續使用原有部署，原 207 Compose Demo 不變。

## 怎麼展示

1. 選「讀取薪資」，按「執行此情境」。probe 會在叢集裡呼叫 frontend，frontend
   再呼叫 salary；畫面顯示真正的 HTTP 200 和薪資測試資料。
2. 選「換一個服務身分」。intruder 同樣持有合法 mesh 憑證，但沒有薪資權限，
   應收到 403。這時 PASS 的意思是「拒絕符合預期」。
3. 再試「跳過 frontend」、「改成 POST」、「改變資源路徑」、「偽造身分標頭」
   和「不用 mTLS 連線」。左側標記與右側回應都來自本次實際請求。
4. 下方「操作紀錄」可點選回看，並匯出 JSON。頁面重新整理會重新讀取目前伺服器
   的紀錄；控制程式重啟後，記憶體中的紀錄會清空，最多保留 40 次。
5. 「環境與身分」讀取即時 Deployment readiness、sidecar、ServiceAccount
   和已套用政策。按「讀取憑證」會從代理公開憑證取得 SPIFFE URI 和到期時間。
6. 展開「PE 最近的決策紀錄」，讀取 Context 裡真正的服務決策事件。這是獨立的
   稽核串流，沒有把相近時間的事件冒充為某一次操作的精確追蹤。

完整驗證另外提供 23 項檢查，涵蓋動態政策撤銷、adapter／PE／audit 停機與恢復。
開始前會顯示影響說明，測試會暫時拒絕存取；不要在測試中關閉控制程式，或同時
從 CLI 執行其他 mesh verifier。所有網頁操作由同一個執行鎖序列化。

## 啟動

先啟動 Docker Desktop，確認已完成 [207A external authorization 部署](207a-mesh.md)。
在 repo 根目錄執行：

```powershell
.\.venv\Scripts\python.exe scripts/mesh_console.py
```

預設綁定 `127.0.0.1:18081`，沒有公開 host 選項。`--kind`、`--kubectl`、`--istioctl`
與 `--kubeconfig` 可以指定路徑；預設優先尋找本 repo 旁 `.tools` 中的 kind／istioctl，
其次使用 PATH。Linux/macOS 使用 `.venv/bin/python`。

此 Windows 專案位置：

```powershell
Set-Location -LiteralPath 'C:\Users\user\.codex\.chatgpt-projects\g-p-6a93da7c3a3c81919224b886e5145181\zta-207a'
.\.venv\Scripts\python.exe scripts/mesh_console.py
```

若 18081 已被占用，先查看是否是舊的 frontend port-forward 或已運行的實驗台，
不要終止不明程序。也可使用 `--port 18082` 並開啟對應網址。
現在的 18081 由本機實驗台提供，不需要再開 frontend 的 18081 port-forward。
原 `/api/salary`、`/api/profile` 本機連結會安全地導向對應情境；按下執行才發送請求。
Kubernetes frontend 本身的 JSON API 沒有變更。

## 邊界

這是持有本機 kubeconfig 的操作員工具。控制程式留在 Windows，沒有把 kubeconfig、
kubectl、測試控制權或管理 token 放進 Kubernetes frontend。

- 固定 scenario ID 對應固定 caller、service、method、path；網頁不能提供任意命令、URL 或資源名稱。
- 只有具本次頁面 token 的 POST 才能啟動操作；限制 Host、Origin，沒有開放 CORS，並限制 frame/script 來源。
- 此保護針對其他網站誤觸與一般瀏覽器攻擊。可直接執行本機程式的使用者已擁有 kubeconfig，仍在本示範信任邊界之外。
- 一般 403 不冒充已知的拒絕層，畫面不僅憑狀態碼宣稱是 native RBAC 或 PE 拒絕。
- 不把「政策 YAML 已套用」當作每次請求的 mTLS／授權證據；憑證與實際請求另外讀取。
- 叢集或控制程式無法連線時不保留綠色即時狀態。短暫輪詢失敗會保留同一 job ID 繼續追蹤，不會自動重送測試。
- 原 207 的 Passkey／PA session 與 mesh 仍是分開的流程；這次新增操作介面，沒有宣稱跨 hop 的使用者身分已串接。

## 完整驗證的恢復

開始前會保存 demo ConfigMap 的 policy data 和三個依賴 Deployment 的 replicas，
要求 context、pe、mesh-authz 都為 1 replica，且沒有其他 `temporary-revoke`。
正常完成、失敗或超時都會嘗試恢復 policy、清理測試 DENY、恢復 replicas 並等待 rollout。
超時會先停止 verifier 和其子程序，再恢復環境，避免尚未結束的 kubectl 繼續修改資料。
若任一步恢復無法完成，控制程式鎖定後續操作，不把環境當成已恢復。

恢復失敗時，先確保 Docker 與 Kubernetes 已可連線，再檢查：

```powershell
kubectl --kubeconfig .tmp/mesh-kubeconfig --context kind-zta-207a -n zta-207a get deploy
kubectl --kubeconfig .tmp/mesh-kubeconfig --context kind-zta-207a -n zta-207a get authorizationpolicy temporary-revoke --ignore-not-found
kubectl --kubeconfig .tmp/mesh-kubeconfig --context kind-zta-207a -n zta-207a get configmap service-policy
```

在這個專用 demo namespace，可使用既有部署腳本恢復標準 external 模式，再重新啟動控制程式：

```powershell
# 僅清除 verifier 固定名稱的暫時 DENY；不要對其他 namespace 執行。
kubectl --kubeconfig .tmp/mesh-kubeconfig --context kind-zta-207a -n zta-207a delete authorizationpolicy temporary-revoke --ignore-not-found
.\.venv\Scripts\python.exe scripts/mesh_demo.py --kind ..\.tools\kind.exe --istioctl ..\.tools\istioctl\istioctl.exe --external-authz up
```

強制結束整個控制程式、主機斷電或 Docker 停機可能阻止任何自動恢復；這不是常駐高可用管理服務。

## 驗證

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.tmp/pytest-console
```

測試覆蓋固定操作與真實結果判定、來源／token 邊界、GET 不執行操作、單一執行鎖、
過期驗證證據拒絕、超時恢復、恢復失敗鎖定，以及只輸出憑證公開身分資料。
單元測試不取代實際 Kubernetes 與瀏覽器端測試。
