# Security

CertEncrypt encrypts files to a certificate so that only the holder of the matching private key can read them.

## Status: unaudited

The cryptography comes from well-reviewed libraries (Go standard library, `golang.org/x/crypto`,
`go-pkcs12`). No cipher or protocol primitive is implemented here. The way those pieces are
combined (file format, key wrapping, chunking) has **not** been reviewed by an independent
cryptographer. Treat it as suitable for personal files and learning. For secrets where a mistake
would be serious, prefer a long-reviewed tool such as `age` or GnuPG until this has had review.

## What it protects

- **Confidentiality** of file contents against anyone without the private key.
- **Integrity**: any change to a file, its header, its chunk order or its length is detected, and no
  plaintext is released from a file that fails verification.
- **Defense in depth**: data passes through two independent AEAD ciphers
  (XChaCha20-Poly1305, then AES-256-GCM) with independent keys.
- **Key at rest**: private keys made by `gen` are protected with Argon2id and XChaCha20-Poly1305.

## What it does not protect

- **A stolen private key plus its password** reads everything encrypted to it.
- **Lost private key**: data cannot be recovered. Back up the key.
- **Metadata**: file size, that a file is encrypted, and the recipient key ID are visible.
- **A compromised device**: malware, a keylogger, or live memory access can capture the
  password or key. Go cannot guarantee secrets are wiped from RAM.
- **Weak passphrases**: Argon2id slows guessing but cannot save a short or common passphrase.
  Use a long one.
- **Authenticity of the sender**: CertEncrypt does not sign files. Anyone with your certificate can
  encrypt a file to you.
- **Trust in the certificate or key**: it does not validate certificate chains, revocation or names, and a
  bare public key carries no identity or expiry at all. Make sure what you encrypt to really belongs to the
  intended recipient (compare the Key ID that the tool shows, over a channel you trust).
- **Local file safety**: files decrypted to disk are plaintext on that disk. `-replace` overwrites
  by renaming, not by securely wiping, so deleted data may remain recoverable on some storage.

## Supported keys

RSA (3072 bits or more) and ECDSA P-256, P-384, P-521. Ed25519, X25519 and Brainpool curves are
not supported.

## Good practice

- Use a separate key pair for encryption; do not reuse a signing key.
- Keep private keys out of synced or shared folders; protect the device with a lock and disk encryption.
- Verify downloads against `SHA256SUMS`, or build from source with
  `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`.
- Test restores: decrypt a copy before relying on a backup.

## Reporting a problem

Open an issue on the project page with steps to reproduce. For a suspected vulnerability, say so in
the title without posting working exploit details, and a private channel can be arranged.
