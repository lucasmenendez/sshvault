package sshutil

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sshvault/internal/vault"
)

func TestGenerateEd25519AndInspect(t *testing.T) {
	priv, pub, fp, err := Generate("ed25519", 0, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(priv, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("unexpected private key format: %q", priv[:40])
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("unexpected public key: %q", pub)
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("unexpected fingerprint: %q", fp)
	}
	k := &vault.Key{
		Kind:       vault.KeyKindKeypair,
		PrivateKey: priv,
		PublicKey:  pub,
		Comment:    "test-key",
	}
	info, err := Inspect(k)
	if err != nil {
		t.Fatal(err)
	}
	if info.Fingerprint != fp {
		t.Fatalf("fingerprint = %q, want %q", info.Fingerprint, fp)
	}
	if info.Type != "ssh-ed25519" || info.Bits != 256 {
		t.Fatalf("info = %+v", info)
	}
}

func TestGenerateRSAAndECDSA(t *testing.T) {
	for _, tc := range []struct {
		alg  string
		bits int
	}{
		{"rsa", 2048},
		{"ecdsa", 256},
	} {
		priv, pub, _, err := Generate(tc.alg, tc.bits, "")
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if priv == "" || pub == "" {
			t.Fatalf("%s generated empty material", tc.alg)
		}
		if err := ValidateMaterial(pub, priv, ""); err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
	}
	if _, _, _, err := Generate("rsa", 1024, ""); err == nil {
		t.Fatal("expected error for weak RSA size")
	}
	if _, _, _, err := Generate("nope", 0, ""); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestPublicFromPrivate(t *testing.T) {
	priv, pub, _, err := Generate("ed25519", 0, "hello")
	if err != nil {
		t.Fatal(err)
	}
	derived, err := PublicFromPrivate(priv, "", "hello")
	if err != nil {
		t.Fatal(err)
	}
	p1, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	p2, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(derived))
	if err != nil {
		t.Fatal(err)
	}
	if comment != "hello" {
		t.Fatalf("comment = %q", comment)
	}
	if ssh.FingerprintSHA256(p1) != ssh.FingerprintSHA256(p2) {
		t.Fatal("public keys differ")
	}
}

func TestInspectCertificate(t *testing.T) {
	caPriv, _, _, err := Generate("ed25519", 0, "ca")
	if err != nil {
		t.Fatal(err)
	}
	userPriv, userPub, _, err := Generate("ed25519", 0, "user")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.ParsePrivateKey([]byte(caPriv))
	if err != nil {
		t.Fatal(err)
	}
	user, err := ssh.ParsePrivateKey([]byte(userPriv))
	if err != nil {
		t.Fatal(err)
	}
	_ = userPub
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             user.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "cert-id",
		ValidPrincipals: []string{"alice", "deploy"},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
		Serial:          42,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(cert))
	if _, err := ParseCertificate(line); err != nil {
		t.Fatal(err)
	}
	k := &vault.Key{
		Kind:        vault.KeyKindCertificate,
		PrivateKey:  userPriv,
		Certificate: line,
	}
	info, err := Inspect(k)
	if err != nil {
		t.Fatal(err)
	}
	if info.Cert == nil {
		t.Fatal("certificate metadata missing")
	}
	if info.Cert.KeyID != "cert-id" || info.Cert.CertType != "user" || info.Cert.Expired || info.Cert.NotYetValid {
		t.Fatalf("cert = %+v", info.Cert)
	}
	if len(info.Cert.Principals) != 2 {
		t.Fatalf("principals = %#v", info.Cert.Principals)
	}
}

func TestValidateMaterial(t *testing.T) {
	priv, pub, _, err := Generate("ed25519", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMaterial(pub, priv, ""); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMaterial("ssh-ed25519 garbage", "", ""); err == nil {
		t.Fatal("expected invalid public key error")
	}
	if err := ValidateMaterial("", "not a pem", ""); err == nil {
		t.Fatal("expected invalid private key error")
	}
}

func TestIsPrivateAndPublic(t *testing.T) {
	priv, pub, _, err := Generate("ed25519", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if !IsPrivateKey(priv) || IsPublicKey(priv) {
		t.Fatal("private key classification failed")
	}
	if !IsPublicKey(pub) || IsPrivateKey(pub) {
		t.Fatal("public key classification failed")
	}
	if IsPublicKey("hello") {
		t.Fatal("plain text classified as public key")
	}
}
