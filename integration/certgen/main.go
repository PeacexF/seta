// Command certgen writes the integration environment's test CA and server
// certificates (valid, expired) into the directory given as its argument.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: certgen <dir>")
	}
	dir := os.Args[1]
	// compose re-runs this for every "run"; servers already loaded the first certs.
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err == nil {
		return
	}
	now := time.Now()

	caKey := newKey()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seta Integration CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER := must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))
	ca := must(x509.ParseCertificate(caDER))
	write(dir, "ca.pem", "CERTIFICATE", caDER)

	leaf := func(name, file string, notBefore, notAfter time.Time) {
		key := newKey()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(now.UnixNano()),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der := must(x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey))
		write(dir, file+".pem", "CERTIFICATE", der)
		write(dir, file+".key", "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(key)))
	}
	leaf("mx-tls.int.test", "mx-tls", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	leaf("mx-expired.int.test", "mx-expired", now.Add(-60*24*time.Hour), now.Add(-24*time.Hour))
	leaf("mta-sts.tls.int.test", "mta-sts", now.Add(-time.Hour), now.Add(90*24*time.Hour))
}

func newKey() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)) }

func write(dir, name, typ string, der []byte) {
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		log.Fatal(err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
