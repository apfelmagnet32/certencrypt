package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var stdin = bufio.NewReader(os.Stdin)

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, err := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		fmt.Println()
		os.Exit(0) // EOF / Ctrl-D ends the session
	}
	if line == "" {
		return def
	}
	return line
}

func cleanPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(h, p[2:])
		}
	}
	return p
}

// pick lists files in the current directory with the given extensions and lets
// the user choose by number or type any path.
func pick(label string, exts ...string) string {
	var found []string
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		for _, x := range exts {
			if ext == x {
				found = append(found, e.Name())
			}
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		fmt.Printf("\n%s found in this folder:\n", label)
		for i, f := range found {
			fmt.Printf("  %d) %s\n", i+1, f)
		}
	}
	for {
		in := ask(label+" (number or path)", "")
		if n, err := strconv.Atoi(in); err == nil && n >= 1 && n <= len(found) {
			return found[n-1]
		}
		p := cleanPath(in)
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			fmt.Println("  not a readable file, try again")
			continue
		}
		return p
	}
}

func freeOutput(def string) string {
	for {
		out := cleanPath(ask("Output file", def))
		if _, err := os.Stat(out); err == nil {
			fmt.Printf("  %s already exists, choose another name\n", out)
			def = ""
			continue
		}
		return out
	}
}

func keyKind(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		kind := fmt.Sprintf("RSA %d bit", k.N.BitLen())
		if k.N.BitLen() < 3000 {
			kind += "  (TOO SMALL, needs >= 3072 for encryption)"
		}
		return kind
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	}
	return fmt.Sprintf("%T (not supported)", pub)
}

func certInfo(path string) error {
	r, err := loadRecipient(path)
	if err != nil {
		return err
	}
	fp, _ := pubFingerprint(r.pub)
	c := r.cert
	if c == nil {
		fmt.Printf("\n  Public key only (no certificate: no name, issuer or expiry to check)\n  Key:          %s\n  Key ID:       %x\n", keyKind(r.pub), fp[:16])
		fmt.Println("  Compare the Key ID with the owner to be sure it is theirs.")
		return nil
	}
	sum := sha256.Sum256(c.Raw)
	fmt.Printf("\n  Subject:      %s\n  Issuer:       %s\n  Key:          %s\n", c.Subject, c.Issuer, keyKind(r.pub))
	fmt.Printf("  Valid:        %s  ->  %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	fmt.Printf("  Key ID:       %x\n  Cert SHA-256: %x\n", fp[:16], sum[:16])
	return nil
}

func interactive() {
	fmt.Println("certencrypt - encrypt files to a certificate; only the private key can open them")
	for {
		fmt.Print(`
  1) Generate a new certificate + private key
  2) Encrypt a file   (needs the certificate)
  3) Decrypt a file   (needs the private key)
  4) Show certificate details
  5) Quit
`)
		var err error
		switch ask("Choose", "") {
		case "1":
			err = uiGen()
		case "2":
			err = uiEncrypt()
		case "3":
			err = uiDecrypt()
		case "4":
			p := pick("Certificate or public key", ".crt", ".pem", ".cer", ".pub", ".der", ".pfx", ".p12")
			err = certInfo(p)
		case "5", "q", "Q":
			return
		default:
			fmt.Println("  please enter 1-5")
			continue
		}
		if err != nil {
			fmt.Println("\n  ERROR:", err)
		}
	}
}

func uiGen() error {
	kind := ask("Key type: ec (fast, recommended) or rsa (4096, slow to generate)", "ec")
	name := ask("Name for the certificate (common name)", "certencrypt")
	prefix := cleanPath(ask("File name prefix (creates PREFIX.key and PREFIX.crt)", name))
	days, err := strconv.Atoi(ask("Valid for how many days", "3650"))
	if err != nil || days < 1 {
		return fmt.Errorf("invalid number of days")
	}
	fmt.Println("  generating...")
	if err := gen(kind, name, prefix, days); err != nil {
		return err
	}
	fmt.Printf("\n  Created %s.crt  (public: share this, used to ENCRYPT)\n", prefix)
	fmt.Printf("          %s.key  (private: keep secret + back it up, used to DECRYPT)\n", prefix)
	fmt.Println("  If you lose the private key, data encrypted to it cannot be recovered.")
	return nil
}

// chooseOutput asks whether to replace the original or write a new file.
func chooseOutput(in, def string, encrypting bool) string {
	allowReplace = false
	if encrypting {
		fmt.Println("\n  Replacing overwrites your readable original with the encrypted version.")
		fmt.Println("  Without the private key it is gone for good.")
	}
	if strings.ToLower(ask("Replace the original file with the result? (y/N)", "n")) == "y" {
		allowReplace = true
		return in
	}
	return freeOutput(def)
}

func uiEncrypt() error {
	cert := pick("Certificate or public key", ".crt", ".pem", ".cer", ".pub", ".der", ".pfx", ".p12")
	if err := certInfo(cert); err != nil {
		return err
	}
	in := pick("File to encrypt")
	out := chooseOutput(in, in+".enc", true)
	if err := encryptFile(cert, in, out); err != nil {
		return err
	}
	fmt.Println("\n  Encrypted ->", out)
	return nil
}

func uiDecrypt() error {
	key := pick("Private key", ".key", ".pem", ".pfx", ".p12")
	in := pick("File to decrypt", ".enc")
	def := strings.TrimSuffix(in, ".enc")
	if def == in {
		def = in + ".dec"
	}
	out := chooseOutput(in, def, false)
	if err := decryptFile(key, in, out); err != nil {
		return err
	}
	fmt.Println("\n  Decrypted ->", out)
	return nil
}
