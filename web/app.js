'use strict';
const tg = window.Telegram && window.Telegram.WebApp;
const statusNode = document.getElementById('status');
const input = document.getElementById('password');
const button = document.getElementById('submit');
const nonce = new URLSearchParams(window.location.search).get('request');
history.replaceState(null, '', '/');
if (!tg || !tg.initData || !nonce) {
  statusNode.textContent = '請從原 Telegram 私人對話中的「安全輸入 sudo 密碼」按鈕開啟。一般瀏覽器無法授權。';
} else {
  tg.ready();
  tg.expand();
  input.disabled = false;
  button.disabled = false;
  statusNode.textContent = '請確認操作內容，再於遮罩欄位輸入密碼。';
}
document.getElementById('form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!tg || !tg.initData || !nonce || button.disabled) return;
  button.disabled = true;
  input.disabled = true;
  statusNode.textContent = '正在驗證本次 sudo 操作…';
  let password = input.value;
  input.value = '';
  try {
    const body = JSON.stringify({nonce, init_data: tg.initData, password});
    password = '';
    const response = await fetch('/submit', {method: 'POST', headers: {'Content-Type': 'application/json'}, body, cache: 'no-store', credentials: 'omit', redirect: 'error'});
    const result = await response.json();
    if (response.status === 202 && result.ok === true && result.status === 'accepted') {
      statusNode.textContent = result.action === 'ymir_deploy_4b8a3af'
        ? '部署已受理，請回 Telegram 等結果。受理不代表部署完成；不要重送密碼。'
        : '操作已受理，請回 Telegram 等結果。受理不代表執行完成；不要重送密碼。';
    } else if (result.ok && result.status === 'verified' && result.uid === 0) {
      statusNode.textContent = 'sudo 驗證成功（UID 0）。密碼未保存。可以關閉此視窗。';
    } else {
      statusNode.textContent = '未授權或 sudo 驗證失敗。此表單不會重試密碼；請關閉視窗並要求建立新表單。';
    }
  } catch (_) {
    statusNode.textContent = '連線失敗或表單已失效。請關閉視窗並要求建立新表單，不要將密碼傳到聊天。';
  } finally {
    password = '';
    input.value = '';
  }
});
window.addEventListener('pagehide', () => {input.value = '';});
