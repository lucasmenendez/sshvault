package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func testKDF() KDFParams {
	return KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte(`{"version":1,"keys":["secret"]}`)
	blob, key, salt, err := EncryptNew(plain, "correct horse battery", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) <= headerLen {
		t.Fatalf("blob is too short: %d", len(blob))
	}
	got, gotKey, gotSalt, params, err := DecryptBlob(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
	if !KeysEqual(key, gotKey) {
		t.Fatal("derived keys differ")
	}
	if !bytes.Equal(salt, gotSalt) {
		t.Fatal("salt differs")
	}
	if params != testKDF() {
		t.Fatalf("params = %+v", params)
	}
}

func TestWrongPassword(t *testing.T) {
	blob, _, _, err := EncryptNew([]byte("secret"), "password123", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err = DecryptBlob(blob, "password124")
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	blob, _, _, err := EncryptNew([]byte("secret"), "password123", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xff
	if _, _, _, _, err := DecryptBlob(blob, "password123"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
}

func TestTamperedHeader(t *testing.T) {
	blob, _, _, err := EncryptNew([]byte("secret"), "password123", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	blob[0] = 'X'
	if _, _, _, _, err := DecryptBlob(blob, "password123"); !errors.Is(err, ErrCorruptVault) {
		t.Fatalf("err = %v, want ErrCorruptVault", err)
	}
}

func TestTruncatedBlob(t *testing.T) {
	if _, _, _, _, err := DecryptBlob([]byte("short"), "password123"); !errors.Is(err, ErrCorruptVault) {
		t.Fatalf("err = %v, want ErrCorruptVault", err)
	}
}

func TestMaliciousKDFParams(t *testing.T) {
	blob, _, _, err := EncryptNew([]byte("secret"), "password123", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	fake := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(fake[14:18], 4*1024*1024) // 4 GiB in KiB
	if _, _, _, _, err := DecryptBlob(fake, "password123"); !errors.Is(err, ErrCorruptVault) {
		t.Fatalf("err = %v, want ErrCorruptVault", err)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	blob, key, salt, err := EncryptNew([]byte("secret"), "password123", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	_ = blob
	second, err := SealBlob([]byte("secret"), key, salt, testKDF())
	if err != nil {
		t.Fatal(err)
	}
	third, err := SealBlob([]byte("secret"), key, salt, testKDF())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(second, third) {
		t.Fatal("expected different nonces and ciphertexts")
	}
	if _, _, _, _, err := DecryptBlob(second, "password123"); err != nil {
		t.Fatal(err)
	}
}

func TestKDFParamsValidation(t *testing.T) {
	cases := []KDFParams{
		{Time: 0, Memory: 8 * 1024, Threads: 1},
		{Time: 1, Memory: 1024, Threads: 1},
		{Time: 1, Memory: 8 * 1024, Threads: 0},
		{Time: 11, Memory: 8 * 1024, Threads: 1},
	}
	for _, p := range cases {
		if _, _, _, err := EncryptNew([]byte("x"), "password123", p); err == nil {
			t.Fatalf("expected error for %+v", p)
		}
	}
}
