//go:debug rsa1024min=0

package dkim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

func rsaRecord(t *testing.T, bits int, pkcs1 bool) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if pkcs1 {
		der, err = x509.MarshalPKCS1PublicKey(&key.PublicKey), nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestParseRSA(t *testing.T) {
	for _, tt := range []struct {
		bits  int
		pkcs1 bool
	}{{512, false}, {1024, false}, {2048, false}, {2048, true}} {
		k, err := Parse(rsaRecord(t, tt.bits, tt.pkcs1))
		if err != nil || k.Bits != tt.bits || k.Type != "rsa" {
			t.Errorf("%d bits (pkcs1=%v): %+v, %v", tt.bits, tt.pkcs1, k, err)
		}
	}
}

func TestParseVariants(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ed := base64.StdEncoding.EncodeToString(pub)

	k, err := Parse("v=DKIM1; k=ed25519; p=" + ed)
	if err != nil || k.Bits != 256 || k.Type != "ed25519" {
		t.Errorf("ed25519: %+v %v", k, err)
	}
	k, err = Parse("v=DKIM1; p=")
	if err != nil || !k.Revoked {
		t.Errorf("revoked: %+v %v", k, err)
	}
	// Folded base64, no v= tag, testing flag.
	rec := rsaRecord(t, 1024, false)
	_, p, _ := strings.Cut(rec, "p=")
	folded := "k=rsa; t=y:s; p=" + p[:40] + " " + p[40:80] + "\t" + p[80:]
	k, err = Parse(folded)
	if err != nil || k.Bits != 1024 || !k.Testing {
		t.Errorf("folded: %+v %v", k, err)
	}
}

func TestParseInvalid(t *testing.T) {
	for txt, want := range map[string]string{
		"k=rsa; v=DKIM1; p=AAAA":     "v= must be first",
		"v=DKIM2; p=AAAA":            "v= must be first",
		"v=DKIM1; k=rsa":             "missing p=",
		"v=DKIM1; p=!!!":             "base64",
		"v=DKIM1; p=AAAA":            "not a valid RSA",
		"v=DKIM1; k=ed25519; p=AAAA": "want 32",
		"v=DKIM1; k=dsa; p=AAAA":     "unknown key type",
	} {
		_, err := Parse(txt)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want containing %q", txt, err, want)
		}
	}
}

func TestIsKey(t *testing.T) {
	for txt, want := range map[string]bool{
		"v=DKIM1; k=rsa; p=AAAA": true,
		"k=rsa; p=AAAA":          true,
		"v=DKIM1; p=":            true,
		"v=spf1 -all":            false,
		"some verification text": false,
	} {
		if IsKey(txt) != want {
			t.Errorf("IsKey(%q) != %v", txt, want)
		}
	}
}
