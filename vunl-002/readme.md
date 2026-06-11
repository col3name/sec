Mnemonic Exposed as Plaintext in DOM (Medium)

- **Location**: `src/components/common/backup/SecretWordsList.tsx:47-51`
- **Confidence**: High
- **Type**: DOM exposure

### Description

Mnemonic words are rendered as plaintext `<li>` elements in the DOM:

```typescript
<ol className={styles.words}>
  {mnemonic?.map((word, i) => (
    <li key={i} className={styles.word}>{word}</li>  // Plaintext in DOM
  ))}
</ol>
```

### Impact

- Any browser extension with DOM access can read the words
- Malicious dApp with access to page DOM (via extension postMessage or iframe) can read them
- Developer tools inspection reveals full seed phrase
- Screen recording or screenshot captures the words
- The mnemonic remains in the DOM as long as the component is mounted

### Fix

Consider using character-by-character rendering with CSS masking, or at minimum warn users that the screen should not be observed.
