/*
Package testcerts provides a set of functions for generating and saving x509 test certificates to file.

This package can be used in testing and development environments where a set of trusted certificates are needed.
The main function, GenerateCertsToTempFile, generates an x509 certificate and key and writes them to a randomly
named file in a specified or temporary directory.

For example, to generate and save a certificate and key to a temporary directory:

	func TestSomething(t *testing.T) {
		certFile, keyFile, err := testcerts.GenerateCertsToTempFile("/tmp/")
		if err != nil {
			// do stuff
		}

		_ = something.Run(certFile, keyFile)
		// do more testing
	}

This will create a temporary certificate and key and print the paths to where the files were written.
*/
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

// GenerateCerts generates an x509 certificate and key.
// It returns the certificate and key as byte slices, and any error that occurred.
//
//	cert, key, err := GenerateCerts()
//	if err != nil {
//		// handle error
//	}
func GenerateCerts() ([]byte, []byte, error) {
	// Create certs and return as []byte
	c, k, err := genCerts()
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(c), pem.EncodeToMemory(k), nil
}

// GenerateCertsToFile creates an x509 certificate and key and writes it to the specified file paths.
//
//	err := GenerateCertsToFile("/path/to/cert", "/path/to/key")
//	if err != nil {
//		// handle error
//	}
//
// If the specified file paths already exist, it will overwrite the existing files.
func GenerateCertsToFile(certFile, keyFile string) error {
	// Create Certs
	c, k, err := GenerateCerts()
	if err != nil {
		return err
	}

	// Write Certificate
	cfh, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer cfh.Close()
	_, err = cfh.Write(c)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write Key
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

// GenerateCertsToTempFile will create a temporary x509 certificate and key in a randomly generated file using the
// directory path provided. If no directory is specified, the default directory for temporary files as returned by
// os.TempDir will be used.
//
//	cert, key, err := GenerateCertsToTempFile("/tmp/")
//	if err != nil {
//		// handle error
//	}
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
