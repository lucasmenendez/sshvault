package sshutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"sshvault/internal/vault"
)

// KeyInfo is derived, non-secret metadata about a stored key or certificate.
type KeyInfo struct {
	Fingerprint string    `json:"fingerprint"`
	Type        string    `json:"type"`
	Bits        int       `json:"bits"`
	Comment     string    `json:"comment"`
	Cert        *CertInfo `json:"cert,omitempty"`
}

// CertInfo describes an OpenSSH certificate.
type CertInfo struct {
	Fingerprint string    `json:"fingerprint"`
	KeyID       string    `json:"keyId"`
	CertType    string    `json:"certType"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"validAfter"`
	ValidBefore time.Time `json:"validBefore"`
	Serial      uint64    `json:"serial"`
	Expired     bool      `json:"expired"`
	NotYetValid bool      `json:"notYetValid"`
}

// Inspect derives fingerprints and certificate metadata from a vault key.
func Inspect(k *vault.Key) (KeyInfo, error) {
	info := KeyInfo{Comment: k.Comment}
	var pub ssh.PublicKey
	var comment string

	if strings.TrimSpace(k.PublicKey) != "" {
		p, c, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		if err != nil {
			return info, fmt.Errorf("public key: %w", err)
		}
		pub = p
		if comment == "" {
			comment = c
		}
	}
	if strings.TrimSpace(k.Certificate) != "" {
		p, c, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Certificate))
		if err != nil {
			return info, fmt.Errorf("certificate: %w", err)
		}
		cert, ok := p.(*ssh.Certificate)
		if !ok {
			return info, fmt.Errorf("certificate field does not contain an OpenSSH certificate")
		}
		info.Cert = certInfo(cert)
		if pub == nil {
			pub = cert.Key
		}
		if comment == "" {
			comment = c
		}
	}
	if pub == nil && strings.TrimSpace(k.PrivateKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(k.PrivateKey))
		if err == nil {
			pub = signer.PublicKey()
		} else if _, ok := err.(*ssh.PassphraseMissingError); !ok {
			return info, fmt.Errorf("private key: %w", err)
		}
	}
	if pub != nil {
		info.Fingerprint = ssh.FingerprintSHA256(pub)
		info.Type = pub.Type()
		info.Bits = keyBits(pub)
		if info.Type == ssh.CertAlgoED25519v01 || info.Type == ssh.CertAlgoRSAv01 || strings.Contains(info.Type, "-cert-") {
			if cert, ok := pub.(*ssh.Certificate); ok {
				info.Cert = certInfo(cert)
				info.Type = cert.Key.Type()
				info.Bits = keyBits(cert.Key)
			}
		}
	} else if info.Cert != nil {
		info.Fingerprint = info.Cert.Fingerprint
		info.Type = "certificate"
	}
	if comment != "" {
		info.Comment = comment
	}
	return info, nil
}

func certInfo(cert *ssh.Certificate) *CertInfo {
	now := time.Now()
	after := time.Unix(int64(cert.ValidAfter), 0)
	before := time.Unix(int64(cert.ValidBefore), 0)
	certType := "user"
	if cert.CertType == ssh.HostCert {
		certType = "host"
	}
	return &CertInfo{
		Fingerprint: ssh.FingerprintSHA256(cert),
		KeyID:       cert.KeyId,
		CertType:    certType,
		Principals:  append([]string(nil), cert.ValidPrincipals...),
		ValidAfter:  after,
		ValidBefore: before,
		Serial:      cert.Serial,
		Expired:     now.After(before),
		NotYetValid: now.Before(after),
	}
}

func keyBits(pub ssh.PublicKey) int {
	if c, ok := pub.(ssh.CryptoPublicKey); ok {
		switch k := c.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			return k.N.BitLen()
		case *ecdsa.PublicKey:
			return k.Curve.Params().BitSize
		case ed25519.PublicKey:
			return 256
		}
	}
	return 0
}

// PublicFromPrivate derives the authorized_keys line from a private key.
func PublicFromPrivate(privateKey, passphrase, comment string) (string, error) {
	var (
		signer ssh.Signer
		err    error
	)
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(privateKey))
	}
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		line += " " + comment
	}
	return line + "\n", nil
}

// Generate creates a new keypair in OpenSSH format.
func Generate(alg string, bits int, comment string) (privateKey, publicKey, fingerprint string, err error) {
	alg = strings.ToLower(strings.TrimSpace(alg))
	var signerKey any
	switch alg {
	case "", "ed25519":
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return "", "", "", gerr
		}
		signerKey = priv
	case "rsa":
		if bits == 0 {
			bits = 3072
		}
		if bits < 2048 || bits > 8192 {
			return "", "", "", fmt.Errorf("RSA size must be between 2048 and 8192 bits")
		}
		priv, gerr := rsa.GenerateKey(rand.Reader, bits)
		if gerr != nil {
			return "", "", "", gerr
		}
		signerKey = priv
	case "ecdsa":
		var curve elliptic.Curve
		switch bits {
		case 0, 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return "", "", "", fmt.Errorf("ECDSA size must be 256, 384 or 521")
		}
		priv, gerr := ecdsa.GenerateKey(curve, rand.Reader)
		if gerr != nil {
			return "", "", "", gerr
		}
		signerKey = priv
	default:
		return "", "", "", fmt.Errorf("unsupported key algorithm %q", alg)
	}

	block, err := ssh.MarshalPrivateKey(signerKey, comment)
	if err != nil {
		return "", "", "", err
	}
	privateKey = string(pem.EncodeToMemory(block))

	signer, err := ssh.NewSignerFromKey(signerKey)
	if err != nil {
		return "", "", "", err
	}
	publicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		publicKey += " " + comment
	}
	publicKey += "\n"
	fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	return privateKey, publicKey, fingerprint, nil
}

// ValidateMaterial parses whichever key material is present.
func ValidateMaterial(publicKey, privateKey, certificate string) error {
	if strings.TrimSpace(publicKey) != "" {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey)); err != nil {
			return fmt.Errorf("public key: %w", err)
		}
	}
	if strings.TrimSpace(certificate) != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
		if err != nil {
			return fmt.Errorf("certificate: %w", err)
		}
		if _, ok := pub.(*ssh.Certificate); !ok {
			return fmt.Errorf("certificate field does not contain an OpenSSH certificate")
		}
	}
	if strings.TrimSpace(privateKey) != "" {
		if _, err := ssh.ParsePrivateKey([]byte(privateKey)); err != nil {
			if _, ok := err.(*ssh.PassphraseMissingError); !ok {
				return fmt.Errorf("private key: %w", err)
			}
		}
	}
	return nil
}

// Kind returns the appropriate Key.Kind value for the supplied material.
func Kind(publicKey, privateKey, certificate string) string {
	switch {
	case strings.TrimSpace(certificate) != "":
		return vault.KeyKindCertificate
	case strings.TrimSpace(privateKey) != "":
		return vault.KeyKindKeypair
	default:
		return vault.KeyKindPublic
	}
}

// IsPrivateKey reports whether the text looks like a PEM private key.
func IsPrivateKey(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "-----BEGIN ") && strings.Contains(t, "PRIVATE KEY-----")
}

// IsPublicKey reports whether the text looks like an authorized_keys line.
func IsPublicKey(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t)); err == nil {
		return true
	}
	return false
}

// ParseCertificate returns certificate metadata from a cert line.
func ParseCertificate(line string) (*CertInfo, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate")
	}
	return certInfo(cert), nil
}
