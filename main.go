// certencrypt: encrypt files to an X.509 certificate; only the matching private
// key can decrypt. Hybrid scheme, no custom primitives:
//
//	file key (64 random bytes) --wrapped to cert--> header
//	data: XChaCha20-Poly1305 (k1) then AES-256-GCM (k2), chunked, header as AAD
//	wrap: RSA-OAEP-SHA256 (RSA certs) or ECDH+HKDF-SHA256 (P-256/384/521 certs)
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var magic = []byte("CEN1")

const (
	chunkSize = 1 << 20
	ktRSA     = 1
	ktEC      = 2
	maxWrap   = 2048
	pemEncKey = "CERTENCRYPT ENCRYPTED PRIVATE KEY"
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------- symmetric chunk layer ----------------

func chunkNonce(base []byte, ctr uint64) []byte {
	n := append([]byte(nil), base...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], ctr)
	for i := 0; i < 8; i++ {
		n[len(n)-8+i] ^= c[i]
	}
	return n
}

func chunkAAD(hdr []byte, ctr uint64, final bool) []byte {
	aad := append([]byte(nil), hdr...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], ctr)
	aad = append(aad, c[:]...)
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}

func aeads(fileKey []byte) (cipher.AEAD, cipher.AEAD, error) {
	x, err := chacha20poly1305.NewX(fileKey[:32])
	if err != nil {
		return nil, nil, err
	}
	blk, err := aes.NewCipher(fileKey[32:64])
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(blk)
	return x, g, err
}

func sealStream(in io.Reader, out io.Writer, hdr, fileKey, xn, gn []byte) error {
	x, g, err := aeads(fileKey)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(in, chunkSize+1)
	buf := make([]byte, chunkSize)
	for ctr := uint64(0); ; ctr++ {
		n, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		_, pe := br.Peek(1)
		final := pe == io.EOF
		aad := chunkAAD(hdr, ctr, final)
		inner := x.Seal(nil, chunkNonce(xn, ctr), buf[:n], aad)
		outer := g.Seal(nil, chunkNonce(gn, ctr), inner, aad)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(outer)))
		if _, err := out.Write(l[:]); err != nil {
			return err
		}
		if _, err := out.Write(outer); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

func openStream(br *bufio.Reader, out io.Writer, hdr, fileKey, xn, gn []byte) error {
	x, g, err := aeads(fileKey)
	if err != nil {
		return err
	}
	maxFrame := uint32(chunkSize + chacha20poly1305.Overhead + g.Overhead())
	for ctr := uint64(0); ; ctr++ {
		var l [4]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return errors.New("truncated file")
		}
		fl := binary.BigEndian.Uint32(l[:])
		if fl > maxFrame {
			return errors.New("corrupt chunk length")
		}
		frame := make([]byte, fl)
		if _, err := io.ReadFull(br, frame); err != nil {
			return errors.New("truncated file")
		}
		_, pe := br.Peek(1)
		final := pe == io.EOF
		aad := chunkAAD(hdr, ctr, final)
		inner, err := g.Open(nil, chunkNonce(gn, ctr), frame, aad)
		if err != nil {
			return errors.New("authentication failed (file modified or truncated)")
		}
		plain, err := x.Open(nil, chunkNonce(xn, ctr), inner, aad)
		if err != nil {
			return errors.New("authentication failed (inner layer)")
		}
		if _, err := out.Write(plain); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

// ---------------- key wrapping ----------------

func pubFingerprint(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	s := sha256.Sum256(der)
	return s[:], nil
}

func ecdhKDF(shared, ephPub, recPub []byte) ([]byte, error) {
	salt := append(append([]byte(nil), ephPub...), recPub...)
	r := hkdf.New(sha256.New, shared, salt, []byte("certencrypt-v1-filekey"))
	k := make([]byte, 64)
	_, err := io.ReadFull(r, k)
	return k, err
}

// wrap returns keyType, wrapped blob, and the 64-byte file key.
func wrap(pub crypto.PublicKey) (byte, []byte, []byte, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if p.N.BitLen() < 3000 {
			return 0, nil, nil, errors.New("RSA key too small (need >= 3072 bits)")
		}
		fk := make([]byte, 64)
		if _, err := rand.Read(fk); err != nil {
			return 0, nil, nil, err
		}
		w, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, p, fk, []byte("certencrypt-v1"))
		return ktRSA, w, fk, err
	case *ecdsa.PublicKey:
		rp, err := p.ECDH()
		if err != nil {
			return 0, nil, nil, err
		}
		eph, err := rp.Curve().GenerateKey(rand.Reader)
		if err != nil {
			return 0, nil, nil, err
		}
		shared, err := eph.ECDH(rp)
		if err != nil {
			return 0, nil, nil, err
		}
		defer wipe(shared)
		fk, err := ecdhKDF(shared, eph.PublicKey().Bytes(), rp.Bytes())
		return ktEC, eph.PublicKey().Bytes(), fk, err
	}
	return 0, nil, nil, errors.New("unsupported certificate key type (use RSA or ECDSA P-256/384/521)")
}

func unwrap(priv crypto.PrivateKey, kt byte, w []byte) ([]byte, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if kt != ktRSA {
			return nil, errors.New("key type mismatch")
		}
		return rsa.DecryptOAEP(sha256.New(), nil, p, w, []byte("certencrypt-v1"))
	case *ecdsa.PrivateKey:
		if kt != ktEC {
			return nil, errors.New("key type mismatch")
		}
		rp, err := p.ECDH()
		if err != nil {
			return nil, err
		}
		ep, err := rp.Curve().NewPublicKey(w)
		if err != nil {
			return nil, errors.New("invalid ephemeral key")
		}
		shared, err := rp.ECDH(ep)
		if err != nil {
			return nil, err
		}
		defer wipe(shared)
		return ecdhKDF(shared, w, rp.PublicKey().Bytes())
	}
	return nil, errors.New("unsupported private key type")
}

// ---------------- file format ----------------
// magic(4) kt(1) fp(32) wlen(2) wrapped xNonce(24) gNonce(12)

func encryptFile(certPath, inPath, outPath string) error {
	cert, err := loadCert(certPath)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("certificate has expired")
	}
	fp, err := pubFingerprint(cert.PublicKey)
	if err != nil {
		return err
	}
	kt, w, fk, err := wrap(cert.PublicKey)
	if err != nil {
		return err
	}
	defer wipe(fk)
	xn := make([]byte, chacha20poly1305.NonceSizeX)
	gn := make([]byte, 12)
	rand.Read(xn)
	rand.Read(gn)
	var hb bytes.Buffer
	hb.Write(magic)
	hb.WriteByte(kt)
	hb.Write(fp)
	binary.Write(&hb, binary.BigEndian, uint16(len(w)))
	hb.Write(w)
	hb.Write(xn)
	hb.Write(gn)
	hdr := hb.Bytes()
	return withOutput(inPath, outPath, func(in io.Reader, out io.Writer) error {
		if _, err := out.Write(hdr); err != nil {
			return err
		}
		return sealStream(in, out, hdr, fk, xn, gn)
	})
}

func decryptFile(keyPath, inPath, outPath string) error {
	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	return withOutput(inPath, outPath, func(in io.Reader, out io.Writer) error {
		br := bufio.NewReader(in)
		fixed := make([]byte, 4+1+32+2)
		if _, err := io.ReadFull(br, fixed); err != nil || !bytes.Equal(fixed[:4], magic) {
			return errors.New("not a certencrypt v1 file")
		}
		kt := fixed[4]
		fp := fixed[5:37]
		wl := int(binary.BigEndian.Uint16(fixed[37:39]))
		if wl == 0 || wl > maxWrap {
			return errors.New("corrupt header")
		}
		rest := make([]byte, wl+24+12)
		if _, err := io.ReadFull(br, rest); err != nil {
			return errors.New("truncated header")
		}
		hdr := append(append([]byte(nil), fixed...), rest...)
		w, xn, gn := rest[:wl], rest[wl:wl+24], rest[wl+24:]
		myFp, err := pubFingerprint(publicOf(priv))
		if err != nil {
			return err
		}
		if !bytes.Equal(myFp, fp) {
			return errors.New("this file was not encrypted to this private key")
		}
		fk, err := unwrap(priv, kt, w)
		if err != nil || len(fk) != 64 {
			return errors.New("could not unwrap file key")
		}
		defer wipe(fk)
		return openStream(br, out, hdr, fk, xn, gn)
	})
}

func publicOf(priv crypto.PrivateKey) crypto.PublicKey {
	if s, ok := priv.(crypto.Signer); ok {
		return s.Public()
	}
	return nil
}

// allowReplace permits the output path to be the input file itself. The result is
// written to a temp file and only swapped in after complete, successful processing.
var allowReplace bool

func withOutput(inPath, outPath string, f func(io.Reader, io.Writer) error) error {
	if st, err := os.Stat(outPath); err == nil {
		inSt, err2 := os.Stat(inPath)
		if !(allowReplace && err2 == nil && os.SameFile(st, inSt)) {
			return fmt.Errorf("%s already exists; refusing to overwrite", outPath)
		}
	}
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".certencrypt-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	w := bufio.NewWriter(tmp)
	if err := f(in, w); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	in.Close() // Windows cannot replace a file that is still open
	if err := os.Rename(tmp.Name(), outPath); err != nil {
		return err
	}
	ok = true
	return nil
}

// ---------------- private key storage (passphrase-protected) ----------------

func passphrase(prompt string, confirm bool) ([]byte, error) {
	if p := os.Getenv("CERTENCRYPT_PASSPHRASE"); p != "" {
		return []byte(p), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no terminal; set CERTENCRYPT_PASSPHRASE")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		if len(p) < 12 {
			return nil, errors.New("passphrase must be at least 12 characters")
		}
		fmt.Fprint(os.Stderr, "Confirm: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil || !bytes.Equal(p, p2) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return p, nil
}

// blob = time(4) mem(4) threads(1) salt(32) nonce(24) ciphertext
func protectKey(der, pw []byte) []byte {
	salt := make([]byte, 32)
	nonce := make([]byte, 24)
	rand.Read(salt)
	rand.Read(nonce)
	var t, m uint32 = 3, 256 * 1024
	var th uint8 = 4
	k := argon2.IDKey(pw, salt, t, m, th, 32)
	defer wipe(k)
	a, _ := chacha20poly1305.NewX(k)
	var hb bytes.Buffer
	binary.Write(&hb, binary.BigEndian, t)
	binary.Write(&hb, binary.BigEndian, m)
	hb.WriteByte(th)
	hb.Write(salt)
	hb.Write(nonce)
	h := hb.Bytes()
	return append(append([]byte(nil), h...), a.Seal(nil, nonce, der, h)...)
}

func unprotectKey(blob, pw []byte) ([]byte, error) {
	if len(blob) < 4+4+1+32+24+16 {
		return nil, errors.New("corrupt key file")
	}
	t := binary.BigEndian.Uint32(blob[0:4])
	m := binary.BigEndian.Uint32(blob[4:8])
	th := blob[8]
	if t < 1 || t > 20 || m < 8 || m > 2*1024*1024 || th < 1 {
		return nil, errors.New("invalid KDF parameters")
	}
	h := blob[:9+32+24]
	salt, nonce := blob[9:41], blob[41:65]
	k := argon2.IDKey(pw, salt, t, m, th, 32)
	defer wipe(k)
	a, _ := chacha20poly1305.NewX(k)
	der, err := a.Open(nil, nonce, blob[65:], h)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupt key file")
	}
	return der, nil
}

func isPFX(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pfx", ".p12":
		return true
	}
	return false
}

func pfxPassword() (string, error) {
	if p, ok := os.LookupEnv("CERTENCRYPT_PFX_PASSWORD"); ok {
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal; set CERTENCRYPT_PFX_PASSWORD (may be empty)")
	}
	fmt.Fprint(os.Stderr, "PFX password: ")
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(p), err
}

// loadCert accepts PEM or DER certificates, or a PFX/P12 bundle (public part only).
func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isPFX(path) {
		pw, err := pfxPassword()
		if err != nil {
			return nil, err
		}
		_, cert, _, err := pkcs12.DecodeChain(b, pw)
		if err != nil {
			return nil, fmt.Errorf("cannot read PFX: %w", err)
		}
		return cert, nil
	}
	if blk, _ := pem.Decode(b); blk != nil {
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("PEM file is not a certificate")
		}
		return x509.ParseCertificate(blk.Bytes)
	}
	return x509.ParseCertificate(b) // DER
}

func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isPFX(path) {
		pw, err := pfxPassword()
		if err != nil {
			return nil, err
		}
		k, _, err := pkcs12.Decode(b, pw)
		if err != nil {
			return nil, fmt.Errorf("cannot read PFX (wrong password?): %w", err)
		}
		return k, nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("key file is not PEM or PFX")
	}
	if blk.Type != pemEncKey {
		// plain (unencrypted) PEM keys from other tools
		switch blk.Type {
		case "PRIVATE KEY":
			return x509.ParsePKCS8PrivateKey(blk.Bytes)
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		}
		return nil, fmt.Errorf("unsupported PEM type %q (encrypted legacy PEM: convert to PFX)", blk.Type)
	}
	pw, err := passphrase("Key passphrase: ", false)
	if err != nil {
		return nil, err
	}
	defer wipe(pw)
	der, err := unprotectKey(blk.Bytes, pw)
	if err != nil {
		return nil, err
	}
	defer wipe(der)
	return x509.ParsePKCS8PrivateKey(der)
}

func gen(kind, name, prefix string, days int) error {
	var priv crypto.Signer
	var err error
	var ku x509.KeyUsage
	switch kind {
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		ku = x509.KeyUsageKeyEncipherment
	case "ec":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		ku = x509.KeyUsageKeyAgreement
	default:
		return errors.New("type must be rsa or ec")
	}
	if err != nil {
		return err
	}
	for _, p := range []string{prefix + ".key", prefix + ".crt"} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s exists; refusing to overwrite", p)
		}
	}
	pw, err := passphrase("New key passphrase (min 12 chars): ", true)
	if err != nil {
		return err
	}
	defer wipe(pw)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     ku | x509.KeyUsageDigitalSignature,
	}
	crt, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	defer wipe(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemEncKey, Bytes: protectKey(der, pw)})
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt})
	if err := os.WriteFile(prefix+".key", keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(prefix+".crt", crtPEM, 0o644)
}

func main() {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  certencrypt                      (no arguments: interactive menu)
  certencrypt gen -type rsa|ec -cn NAME -out PREFIX [-days 3650]   -> PREFIX.key (private, passphrase-protected), PREFIX.crt
  certencrypt encrypt -cert CERT.crt|.pem|.cer|.pfx|.p12 IN OUT
  certencrypt decrypt -key  PREFIX.key|KEY.pem|ID.pfx|ID.p12 IN OUT
  add -replace and give only IN to overwrite the file in place (only after success)`)
		os.Exit(2)
	}
	if len(os.Args) < 2 {
		interactive()
		return
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	var err error
	switch os.Args[1] {
	case "gen":
		t := fs.String("type", "ec", "rsa|ec")
		cn := fs.String("cn", "certencrypt", "common name")
		out := fs.String("out", "", "output prefix")
		days := fs.Int("days", 3650, "validity days")
		fs.Parse(os.Args[2:])
		if *out == "" {
			usage()
		}
		err = gen(*t, *cn, *out, *days)
	case "encrypt":
		c := fs.String("cert", "", "certificate PEM")
		rep := fs.Bool("replace", false, "replace the input file with the result")
		fs.Parse(os.Args[2:])
		if *c == "" || (*rep && fs.NArg() != 1) || (!*rep && fs.NArg() != 2) {
			usage()
		}
		out := fs.Arg(0)
		if *rep {
			allowReplace = true
		} else {
			out = fs.Arg(1)
		}
		err = encryptFile(*c, fs.Arg(0), out)
	case "decrypt":
		k := fs.String("key", "", "private key")
		rep := fs.Bool("replace", false, "replace the input file with the result")
		fs.Parse(os.Args[2:])
		if *k == "" || (*rep && fs.NArg() != 1) || (!*rep && fs.NArg() != 2) {
			usage()
		}
		out := fs.Arg(0)
		if *rep {
			allowReplace = true
		} else {
			out = fs.Arg(1)
		}
		err = decryptFile(*k, fs.Arg(0), out)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
