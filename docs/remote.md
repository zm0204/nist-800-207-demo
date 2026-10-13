# 實驗室筆電免安裝的 HTTPS 展示

## 模式與限制

本機 Docker 繼續執行，實驗室筆電只需要 Chrome／Edge。採 Cloudflare protected Quick Tunnel：**先以指定 Email 的一次性驗證碼進入操作台，再以 Demo 的 Passkey 驗證 Alice**。外層 Email 是展示操作台的進入限制，不能當作 Demo 的 Human identity 或裝置認證。

- 不需要 Cloudflare 帳號或網域，必須使用支援 `--allowed-mail` 的 cloudflared。
- 每次建立通道換網址。WebAuthn RP ID／Origin 精確對應該 HTTPS hostname，必須為新網址重新註冊 Passkey。
- 每個 hostname 使用不同 Compose project 與資料 volumes，保留原本 localhost 的 Passkey／政策／紀錄。
- Quick Tunnel 不支援 SSE；遠端模式停用串流 UI 與 API，原 localhost 串流保留。正常存取、最小權限、入侵、高風險 IP、異常行為與繞過 PEP 六情境仍可展示。
- 電腦保持開機、Docker 運作、網路連線。臨時網址沒有可用性保證；長期使用或需要 SSE 時改成固定網域的 named tunnel。
- Device identity 仍代表本機 Dashboard/Agent 的 device-a，不能宣稱驗證了實驗室筆電。

## 準備

在原本的電腦完成 Docker 與憑證初始化。從 [Cloudflare 官方下載頁](https://developers.cloudflare.com/tunnel/downloads/) 下載 Windows amd64 executable，存為 `artifacts/tools/cloudflared.exe`。官方來源：https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe

PowerShell（專案根目錄）：

```powershell
./scripts/remote-start.ps1 -AllowedEmail 'your-email@example.com'
```

腳本拒絕沒有 `--allowed-mail` 的版本、Email wildcard 或已占用的 8081，避免開放無保護入口或連到未知服務。它先建立有 Email gate 的通道，取得 HTTPS hostname，再啟動獨立遠端 project。Docker Compose 必須支援 `!override`／`!reset`（使用更新版 Docker Desktop）。

如 Docker 或工具不在預設路徑，可加 `-Docker '完整路徑' -Cloudflared '完整路徑'`。

## 實驗室操作

1. 用腳本顯示的 `https://...trycloudflare.com` 網址進入。
2. 輸入被允許的 Email，收取並輸入驗證碼。
3. 首次在這個 hostname 點「建立 Passkey」，由你完成 Windows Hello／手機認證器操作。然後點「驗證身分」。
4. 建立 Session，正常存取，依序測最小權限與風險撤銷。
5. 每個風險情境前重設訊號並建立新 Session。

不能使用 `http://localhost:8081` 登入遠端模式；那是通道的本機來源，與公開 HTTPS Origin 不同。可用它做健康檢查，但 Passkey 必須在指定的 HTTPS 網址完成。

## 停止與回到本機

```powershell
./scripts/remote-stop.ps1
```

腳本只停止紀錄中的 cloudflared 與 `zta-remote-<hash>` project，不刪除 databases，也不影響 `nist-800-207-demo`。再次建立通道會換網址並建立新 project，先前資料保留。不要自行執行 `down -v`。

網址、Email gate 設定、PID、通道紀錄及 service key 在被 Git 忽略的 `artifacts/remote/`，工具在 `artifacts/tools/`。**不把它們、Passkey 私鑰、憑證或 .env 上傳 GitHub。** 遠端 Compose 沒有公開 Envoy port 或 Resource port，只綁定 localhost:8081 的 Dashboard。

若腳本中途失敗，通道會停止，`active.json` 保留供 stop 腳本清理該 project。若 PID 已被其他程序重用，stop 拒絕停止不相關程序。

## 來源與驗證

[Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)：Email gate、隨機 hostname、SSE 限制。

`tests/test_remote.py` 驗證真正的 HTTPS Origin WebAuthn ceremony、精確 Host 限制、錯誤 Origin 拒絕、拒絕不安全／不一致的 RP 設定，以及遠端 SSE API 停用。

具體通道、Email PIN 與 Windows Hello 需要另外在真實瀏覽器完成驗證，不能把單元測試當成已測過實驗室筆電。
