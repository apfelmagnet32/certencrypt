# CertEncrypt

Terminal tool that encrypts files **to a certificate**. Anyone with the
certificate can encrypt; only the holder of the matching **private key** can
decrypt. Interactive menu by default, plain commands for scripting.
Runs on Linux (Arch etc.), Windows, and Android via Termux.

> Status: unaudited. Built only from standard, well-reviewed primitives, but
> the combination has not had independent review. Do not rely on it for
> high-stakes secrets until it has.

## Use

    certencrypt                 # interactive menu
    certencrypt gen -type ec -cn alice -out alice      # alice.key (private) + alice.crt (public)
    certencrypt encrypt -cert alice.crt secret.pdf secret.pdf.enc
    certencrypt decrypt -key  alice.key secret.pdf.enc secret.pdf
    certencrypt encrypt -replace -cert alice.crt secret.pdf    # encrypt in place
    certencrypt decrypt -replace -key  alice.key secret.pdf    # decrypt in place

- `-cert` accepts X.509 certificates (PEM or DER: `.crt .pem .cer .der`), bare public keys (PEM `PUBLIC KEY` or
  `RSA PUBLIC KEY`, or DER: `.pub .pem .der`), or `.pfx/.p12` bundles. A bare public key has no name or expiry,
  so compare its Key ID with the owner. OpenSSH `.pub` lines (`ssh-ed25519 ...`) are not supported.
- `-key` accepts keys made by `gen`, unencrypted PEM keys (PKCS#8, PKCS#1, SEC1) or `.pfx/.p12`.
- RSA certificates must be >= 3072 bits. EC certificates: P-256, P-384, P-521.
- Never overwrites existing files, unless you ask: `-replace` (or "replace the original" in the menu) swaps the input file
  for the result in place, for both encrypt and decrypt. The result goes to a temp file first and replaces the original only
  after complete success, so a wrong key, wrong password or damaged file leaves the original untouched.

Non-interactive passwords (CI/scripts): `CERTENCRYPT_PASSPHRASE` (keys from `gen`),
`CERTENCRYPT_PFX_PASSWORD` (PFX files, may be empty). Prefer the prompts on shared machines.

## Design

    file key (64 random bytes per file)
      -> wrapped to the certificate: RSA-OAEP-SHA256, or ECDH + HKDF-SHA256 (fresh ephemeral key)
    data, in 1 MiB chunks:  XChaCha20-Poly1305  ->  AES-256-GCM   (independent keys)

- Two independent AEAD layers: a break in one cipher alone does not expose data.
- Header (including the wrapped key) and each chunk's counter and "final" flag are authenticated, so
  tampering, reordering and truncation are detected before any plaintext is released.
- Private keys from `gen` are stored with Argon2id (256 MiB, t=3) + XChaCha20-Poly1305, mode 0600.
- No custom cryptography: Go standard library + `golang.org/x/crypto`.

## Limits

- One recipient per file. No signatures (pair with certsign).
- No metadata hiding: file size and recipient key ID are visible.
- Lose the private key and the data is gone. Back it up.
- A PFX/PEM key on disk is only as safe as its password and file permissions.

## License

CertEncrypt is licensed under the **Use-Restriction-License** (see `LICENSE`, official page:
https://github.com/apfelmagnet32/use-restriction-license). It is not an open-source license:
personal, non-commercial use is allowed; redistribution and derivatives require a clearly visible link
to the original (see the license for exact terms). Third-party components keep their own licenses
(`THIRD_PARTY_NOTICES.md`).

## Build

    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o certencrypt .
    # cross: GOOS=windows|linux GOARCH=amd64|arm64

## File format (v1)

    "CEN1" | keytype(1) | keyid = SHA-256(SPKI)(32) | wraplen(2) | wrapped | xnonce(24) | gnonce(12)
    then frames: len(4) | AES-GCM( XChaCha20-Poly1305( chunk ) )   AAD = header | counter(8) | final(1)
