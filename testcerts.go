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
	"math/big"
	"os"
	"time"
)

// GenerateCerts will create a temporary x509 Certificate and Key that can be used for testing.
//	cert, key, err := GenerateCerts()
//	if err != nil {
//		// do stuff
//	}
func GenerateCerts() ([]byte, []byte, error) {
	// Create certs and return as []byte
	c, k, err := genCerts()
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(c), pem.EncodeToMemory(k), nil
}

// GenerateCertsToFile will create a temporary x509 Certificate and Key files that can be used for testing.
func GenerateCertsToFile(certFile, keyFile string) error {
	// Create Certs
	c, k, err := genCerts()
	if err != nil {
		return err
	}

	// Write to Certificate File
	cfh, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer cfh.Close()
	err = pem.Encode(cfh, c)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write to Key File
	kfh, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer kfh.Close()
	err = pem.Encode(kfh, k)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	return nil
}

// genCerts will perform the task of creating a temporary Certificate and Key.
func genCerts() (*pem.Block, *pem.Block, error) {
	// Create a Certificate Authority Cert
	ca := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Never Use this Certificate in Production Inc."},
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

	// Convert keys into pem.Block
	c := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	k := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return c, k, nil
}
