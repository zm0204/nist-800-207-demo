# 在 Chrome 註冊與登入真人 Passkey

2026-10-26 已確認：新環境只有 Alice、Bob 各一把自動驗收 software authenticator 憑證；兩把 ID 與測試私鑰檔案的 ID 一致，沒有真人金鑰。因此直接在 Portal 登入，Chrome 的 allowCredentials 找不到自己的 Passkey，可能只顯示插入安全性金鑰。

程式沒有設定 USB-only 或 cross-platform attachment。已修正新註冊為 discoverable Passkey（residentKey required、requireResidentKey true），保留 UV required，提供 client-device 偏好、不強制 authenticatorAttachment；註冊回傳的 transports 會保存並用於後續 allowCredentials／excludeCredentials。舊憑證沒有 transports 時保持未知，不偽造為 USB 或 internal。

RP ID 固定 `localhost`，新 Portal Origin 為 `http://localhost:18091`。新環境的 Passkey user handle 使用獨立 `portal-p0` namespace，Chrome 顯示帳號 `alice@portal-p0`／`bob@portal-p0`，避免與原 localhost 展示重複 user handle 而覆蓋密碼管理員裡的舊金鑰；既有伺服器公鑰不改寫。

## 真人操作

1. 雙擊工作樹的 `scripts/register_portal_passkey.cmd`。它讀取本機管理憑證，在 **Chrome** 開啟受權 Inspector；不是直接貼上未授權的 `/inspector` 網址。
2. 點左側 **「02 身分與存取」**。在 **「登入帳號」** 選 **「Alice · 一般員工」**，按 **「註冊 Passkey」**。
3. Chrome 詢問儲存位置時選 **Google Password Manager／Google 密碼管理工具**，確認帳號為 `alice@portal-p0`，依畫面完成 Google Password Manager PIN 或可用的裝置驗證。無須 USB Security Key。不要選「使用安全性金鑰」。
4. 頁面顯示 `PASSKEY ENROLLED` 後，到 **http://localhost:18091/portal**，選 Alice，按 **「使用 Passkey 登入」**，選剛新增的 Alice Passkey。
5. 回到受權 Inspector，在「登入帳號」選 **「Bob · 指定範圍 HR」**，按「註冊 Passkey」，同樣將 `bob@portal-p0` 存入 Google Password Manager，再回 Portal 選 Bob 登入。

每次按「註冊 Passkey」都由受權管理 API 建立五分鐘一次性邀請，Identity 再將它換成兩分鐘註冊 challenge；不需要手動複製邀請。若取消或逾時，重新按「註冊 Passkey」取得新邀請。不需刪除憑證或重設資料。重新整理 Inspector 後，本機管理憑證不留在網頁儲存空間，請重新雙擊啟動檔開啟。

若畫面顯示「此頁未取得本機管理員授權」，表示尚未進入 WebAuthn／Google Password Manager 階段。請重新雙擊啟動檔，使用**新開啟的分頁**，再選 Bob。未授權頁現在會停用註冊與管理操作，並直接說明重新開啟的方式，不再只顯示 `operator_authorization_required`。

Chrome 請使用你原本已登入 Google 帳號的正常個人資料視窗。Google 官方說明確認 Windows 版 Chrome 支援將 Passkey 存在 Google Password Manager；網站不能替使用者選取或解鎖密碼管理員。[Google 支援環境](https://developers.google.com/identity/passkeys/supported-environments)

## 保留與驗證

- 僅更新 `kind-zta-portal-p0` 的 Identity，沒有重啟 Portal／PA，也沒有操作原 207／207A 叢集。
- 資料庫僅 additive 新增 transports 欄位。部署前後的兩把 credential ID、公鑰、counter 與 8 筆 token 記錄一致；沒有清空或重設 Session。
- 162 項 Python 回歸、2 項 Node UI 行為測試通過；涵蓋原公鑰繼續登入、追加新金鑰、transports 往返、跨帳號拒絕、錯誤簽章／Origin／UV 拒絕及舊資料庫 migration。
- [線上 options 檢查](evidence/2026-10-26/passkey-options-repair.json) 僅建立短效邀請／challenge，沒有再註冊任何測試金鑰。**真人 Google Password Manager 註冊及 PIN 確認待本人操作，未宣稱已完成。**
