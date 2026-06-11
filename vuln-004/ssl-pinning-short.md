# SSL Pinning — Missing (Short)

**Severity:** Medium
**Scope:** All platforms (iOS, Android, Electron)

---

## Risk

No certificate pinning anywhere. Any CA-trusted MITM (rogue WiFi, corporate proxy, compromised CA) can intercept **all traffic**: TON/ETH/SOL RPCs, TonConnect Bridge, WalletConnect sessions, backend API.

## Key PoC

```bash
# mitmproxy on 8080, CA installed on device
mitmproxy --listen-port 8080

# Or automated capture
mitmproxy -s <(cat <<'SCRIPT')
from mitmproxy import http
def request(f):
    for h in ['mytonwallet.org','toncenter.com','infura.io','walletconnect.org']:
        if h in f.request.pretty_host:
            print(f"[CAPTURED] {f.request.method} {f.request.pretty_url}")
            if f.request.content: print(f"  BODY: {f.request.get_text()[:500]}")
SCRIPT
```

## Mitigation

**Electron** — `session.setCertificateVerifyProc()`:
```typescript
session.defaultSession.setCertificateVerifyProc((req, cb) => {
  const pins = ['sha256/AAAA=', 'sha256/BBBB='];
  cb(pins.includes(fingerprint(req.certificate)) ? 0 : -2);
});
```

**iOS** — ATS `NSPinnedDomains` in Info.plist.

**Android** — `network_security_config.xml` with `<pin-set>`.

## Validation

```bash
grep -r "setCertificateVerifyProc" src/electron/        # Electron
grep -r "NSPinnedDomains" mobile/ios/                    # iOS
grep -r "pin-set" mobile/android/                        # Android
```

If all three return empty — no pinning.
