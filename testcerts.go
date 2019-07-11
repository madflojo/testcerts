// Package testcerts enables users to create temporary x509 Certificates to use with testing.
//
// There are quite a few tools for creating certificates on the command like. This package is focued on creating certificates during testing. Rather than providing a command line interface, this package focuses on creating helper functions for generating certficates.
package testcerts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Pallinder/sillyname-go"
	"math/big"
	"time"
)

// GenerateCerts will create a temporary x509 Certificate and Key that can be used for testing.
//	cert, key, err := GenerateCerts()
//	if err != nil {
//		// do stuff
//	}
func GenerateCerts() ([]byte, []byte, error) {
	// Create a Certificate Authority Cert
	ca := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{sillyname.GenerateStupidName() + " Inc."},
		},
		SerialNumber:          big.NewInt(42),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create a Private Key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate rsa key - %s", err)
	}

	// Use CA Cert to sign a CSR and create a Public Cert
	csr := &key.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, ca, ca, csr, key)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate certificate - %s", err)
	}

	// Convert keys into []byte
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	k := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return c, k, nil
}
