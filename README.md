# safe-sudo

Hermes Agent 插件：在 Telegram Mini App 的 HTTPS 遮罩表單輸入 sudo 密碼，逐次授權任意 root 指令。密碼不以聊天訊息送出，也不傳給模型。

## 安裝

適用 Linux、Python 3.10+，需有 Hermes Agent、sudo、rootless Podman，以及可連線的 Telegram Bot。先設定 Hermes 的 Telegram 私訊整合；sudo 帳號必須原本就有執行目標指令的權限。插件不修改 sudoers。

```bash
git clone https://github.com/puremars2015/safe-sudo.git ~/.hermes/plugins/safe-sudo
hermes plugins enable safe-sudo
hermes plugins doctor ~/.hermes/plugins/safe-sudo --ci
```

Gateway 的執行環境必須設定：

```bash
export SAFE_SUDO_TELEGRAM_USER_ID="你的 Telegram 數字 user ID"
```

此設定僅從 process environment 讀取；systemd 服務請設定該服務的 Environment，再重啟。未設定時拒絕啟動請求。Bot token 從 `TELEGRAM_BOT_TOKEN` 環境變數或 active `HERMES_HOME/.env` 讀取；若讀取該檔，檔案必須由目前帳號持有且沒有 group/other 權限。不要將 token 寫入此倉庫。

確認沒有進行中的操作，再執行 `hermes gateway restart`，並開啟新對話。

## 工具

```json
{"command":"/usr/bin/id -u","reason":"測試本次 sudo 授權"}
```

呼叫工具名稱為 **`sudo_command`**。指定管理者的 Telegram 私訊與表單都會顯示完整指令／用途；核對後在表單輸入本機 sudo 密碼，每次重新授權。表單五分鐘有效、僅嘗試一次；錯誤密碼必須建立新請求。指令最多 1400 字，用途最多 400 字；超限拒絕、不截斷。

執行方式為 root `/bin/bash --noprofile --norc -c <command>`，工作目錄 `/`、固定 PATH/LANG、無互動 stdin。sudo 密碼只送入 `sudo -k -S` stdin，隨即關閉；不保存作未來使用。stdout/stderr 丟棄以避免洩密，Telegram 最終只回報 shell 結束碼；exit 0 不代表業務驗證成功。

`safe_sudo({"action":"identity"})` 保留固定 `id -u` 驗證。程式包含來源版本的 legacy Ymir 固定部署介面／回歸測試，但此公開版本的部署 pin 為 `None`，**不提供可執行的部署 action 或部署腳本**；請使用 `sudo_command`。

## 安全限制

- **任意 root 指令等同完整管理權限**，可刪除資料、洩露秘密、建立持續權限或停用此防護。必須人工逐字核對。核對指令不會鎖定被引用腳本／檔案的內容。
- HTTPS 使用短命 Cloudflare Quick Tunnel；TLS 在 Cloudflare 終止，**不是端對端加密**，Cloudflare 是可見明文的受信任代理。需信任主機、同帳號程序、裝置、Telegram 客戶端與載入的前端腳本。
- 驗證 Telegram signed initData、指定 user ID、有效時間、Origin/Host 與一次性票券；HTTP 不能覆寫已綁定的 command。插件不保護已遭入侵的主機。
- 不設任意指令執行逾時。只使用會結束的前景、非互動指令，勿啟動背景工作或持續 shell。長時間執行會占用單一請求鎖。
- `waiting`／`accepted` 不代表完成。中斷或 `execution_unconfirmed` 時，root 工作可能仍在執行，需管理者檢查，不可直接重試。不保證取消已受理工作，也不宣稱殺掉 sudo/broker 等於停止 root 子工作。
- 不宣稱 Python 記憶體可立即安全抹除；停用 core dump／broker dumpability，不列印 HTTP request、密碼或原始錯誤內容。
- 執行狀態／鎖檔／快取不納入 Git。不得將密碼放入 command、reason、聊天或工具參數。

## 驗證

```bash
python3 -m unittest discover -s tests -q
node --check web/app.js
hermes plugins doctor . --ci
```

自動測試使用假密碼、假 executor；不是正式 Telegram／sudo 成功證據。首次請以 `id -u` 人工驗證完整流程。
