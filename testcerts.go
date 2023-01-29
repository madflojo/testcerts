// Package testcerts enables users to create temporary x509 Certificates for testing.
//
// There are many Certificate generation tools out there, but most focus on being a CLI tool. This package is focused
// on providing helper functions for creating Certificates. These helper functions can be used as part of your unit
// and integration tests as per the example below.
//
//	func TestSomething(t *testing.T) {
//	  err := testcerts.GenerateCertsToFile("/tmp/cert", "/tmp/key")
//	  if err != nil {
//	    // do stuff
//	  }
//
//	  _ = something.Run("/tmp/cert", "/tmp/key")
//	  // do more testing
//	}
//
// The goal of this package, is to make testing TLS based services easier. Without having to leave the comfort of your
// editor, or place test certificates in your repo.
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

// GenerateCerts will create a temporary x509 Certificate and Key.
//
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

// GenerateCertsToFile will create a temporary x509 Certificate and Key. Writing them to the file provided.
//
//	err := GenerateCertsToFile("/path/to/cert", "/path/to/key")
//	if err != nil {
//	  // do stuff
//	}
//
// If the supplied files exist the contents will be overwritten with new certificate and key data.
func GenerateCertsToFile(certFile, keyFile string) error {
	// Create Certs
	c, k, err := GenerateCerts()
	if err != nil {
		return err
	}

	// Write to Certificate File
	cfh, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer cfh.Close()
	_, err = cfh.Write(c)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write to Key File
	kfh, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer kfh.Close()
	_, err = kfh.Write(k)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	return nil
}

// GenerateCertsToTempFile will create a temporary x509 Certificate and Key to a randomly generated file using the path provided.
//
//	cert, key, err := GenerateCertsToTempFile("/tmp/")
//	if err != nil {
//		// do something
//	}
//
// If no directory is specified the default directory for temporary files as returned by os.TempDir will be used.
func GenerateCertsToTempFile(dir string) (string, string, error) {
	// Create Certs
	c, k, err := GenerateCerts()
	if err != nil {
		return "", "", err
	}

	cfh, err := os.CreateTemp(dir, "*.cert")
	if err != nil {
		return "", "", fmt.Errorf("could not create temporary file - %s", err)
	}
	defer cfh.Close()
	_, err = cfh.Write(c)
	if err != nil {
		return cfh.Name(), "", fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write to Key File
	kfh, err := os.CreateTemp(dir, "*.key")
	if err != nil {
		return cfh.Name(), "", fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer kfh.Close()
	_, err = kfh.Write(k)
	if err != nil {
		return cfh.Name(), kfh.Name(), fmt.Errorf("unable to create certificate file - %s", err)
	}

	return cfh.Name(), kfh.Name(), nil
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
		return nil, nil, fmt.Errorf("could not generate rsa key - %s", err)
	}

	// Use CA Cert to sign a CSR and create a Public Cert
	csr := &key.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, ca, ca, csr, key)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate certificate - %s", err)
	}

	// Convert keys into pem.Block
	c := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	k := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return c, k, nil
}
