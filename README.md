# 🔑 Keymaker

<br/>

**Tired of worrying where your private files and notes end up?**

Keymaker locks down your sensitive information right in your browser — nothing ever leaves your device. Whether you're protecting confidential documents before sharing them, or storing personal notes you don't want synced to the cloud, Keymaker makes strong encryption effortless.

<p align=center>
<img width="800" alt="Keymaker" src="docs/hero.svg" />
</p>

<br/>

## ⚙️ Core features

- **Client-side encryption/decryption**: all cryptographic operations happen in your browser. Your files and secrets are never sent to a server.
- **Self-describing KEYM v1 container**: every encrypted payload carries an authenticated header (KDF, cipher, and parameters), so decryption needs no knobs — the format describes itself.
- **Argon2id key derivation**: memory-hard KDF (time cost, memory, and parallelism tunable) that resists GPU/ASIC password cracking — or classic PBKDF2 (1M iterations) for maximum speed and compatibility.
- **Cipher choice, including chaining**: AES-256-GCM (hardware-accelerated), ChaCha20-Poly1305, or **chained AES → ChaCha** with independent subkeys — an attacker must break both.
- **Password & key file protection**: secure your data with a strong password, an optional key file, or both. Generate a cryptographically secure key file in-app.
- **Dice entropy calculator** (Tools tab): computes how many physical dice rolls you need for 128/256 bits of entropy — because physical dice survive vendor RNG failures (the COLDCARD lesson). It computes bits; it does not generate seeds.
- **File & text support**: encrypted files use the `.keym` extension; encrypted text is prefixed `KEYM1:` so blobs are self-identifying. Optional filename obscuring (`keymaker-<random>.keym`).
- **Legacy IttyBitz import**: `.ibitz` files and bare IBTZ base64 blobs (v0 and v1) decrypt transparently, with a nudge to re-encrypt in Keymaker format.
- **QR code sharing & SeedQR export**: share encrypted text via QR; decrypted BIP-39 seed phrases are auto-detected and can be shown as a Standard SeedQR for hardware-wallet import (Coldcard, SeedSigner, Sparrow, Specter, Krux, Keystone, Jade).
- **Installable PWA with full offline support**: after the first visit Keymaker works with zero network connectivity — ideal for air-gapped machines.
- **Privacy-focused UI**: secret input and decrypted output are blurred by default, QRs are mount-gated until deliberately revealed, and the clipboard is auto-cleared after 60 seconds (best-effort).
- **No accounts required**: works entirely without user accounts or sign-ins.

<br/>

## 🥤 How to use Keymaker

At the top you'll find three tabs: **Encrypt**, **Decrypt**, and **Tools**.

- **Encrypt**: pick a file or enter text, set a strong password (24+ chars with mixed classes, or a 4+ word diceware-style passphrase), optionally open **Advanced** to choose Argon2id parameters, the cipher (AES / ChaCha / chained), a key file, and filename obscuring. Encrypted files download as `.keym`; encrypted text is prefixed `KEYM1:`.
- **Decrypt**: drop in a `.keym` or legacy `.ibitz` file (or paste a `KEYM1:` / base64 blob) with the same password and key file. Format and parameters are detected automatically and shown after decryption.
- **Tools**: the dice entropy calculator — set your dice sides, log your rolls, and track progress toward the 128-bit floor and 256-bit target.

<br/>

## 🛡️ Security

- **KDF**: Argon2id (recommended; configurable time/memory/parallelism) or PBKDF2-HMAC-SHA-256 with 1,000,000 iterations.
- **Ciphers**: AES-256-GCM, ChaCha20-Poly1305, or chained AES-256-GCM → ChaCha20-Poly1305 with HKDF-derived independent subkeys.
- **Authenticated settings**: the KEYM header (KDF/cipher/params/flags/salt/nonces) is passed as AAD to every AEAD layer, so tampering with any parameter fails decryption.
- **Entropy**: all randomness comes from `crypto.getRandomValues`; the password generator uses rejection sampling to avoid modulo bias.
- **Memory hygiene**: derived keys, key-file buffers, and intermediate ciphertexts are zero-filled after use (best-effort in JavaScript).
- **Threat model**: Keymaker protects data at rest. It cannot defend against a compromised device, malicious browser extensions, or weak passwords.

Report vulnerabilities via the contact in [SECURITY.md](SECURITY.md).

<br/>

## 💻 Run it locally

Requires Node.js 20+.

```bash
npm install
npm run dev        # development server on :9002
npm run build      # static export to out/ (includes CSP hash post-processing)
npm run test:keymaker  # crypto regression suite
npm run typecheck
```

The production build is a fully static export — serve `out/` from any static host, or open it offline.

<br/>

## 🧾 Attribution

Keymaker is a fork of [IttyBitz](https://github.com/seQRets/ittybitz) by seQRets, GPL-3. Crypto design influenced by Morpheus.

<br/>

## 📜 License

This project is licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE) for details.
