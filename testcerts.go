/*
Package testcerts provides an easy-to-use suite of functions for generating x509 test certificates.

Stop saving test certificates in your code repos. Start generating them in your tests.

	func TestFunc(t *testing.T) {
		// Create and write self-signed Certificate and Key to temporary files
		cert, key, err := testcerts.GenerateToTempFile("/tmp/")
		if err != nil {
			// do something
		}
		defer os.Remove(key)
		defer os.Remove(cert)

		// Start HTTP Listener with test certificates
		err = http.ListenAndServeTLS("127.0.0.1:443", cert, key, someHandler)
		if err != nil {
			// do something
		}
	}

For more complex tests, you can also use this package to create a Certificate Authority and a key pair signed by that Certificate Authority for any test domain you want.

	func TestFunc(t *testing.T) {
		// Generate Certificate Authority
		ca := testcerts.NewCA()

		go func() {
			// Create a signed Certificate and Key for "localhost"
			certs, err := ca.NewKeyPair("localhost")
			if err != nil {
				// do something
			}

			// Write certificates to a file
			err = certs.ToFile("/tmp/cert", "/tmp/key")
			if err {
				// do something
			}

			// Start HTTP Listener
			err = http.ListenAndServeTLS("localhost:443", cert, key, someHandler)
			if err != nil {
				// do something
			}
		}()

		// Create a client with the self-signed CA
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: ca.CertPool(),
				},
			},
		}

		// Make an HTTPS request
		r, _ := client.Get("https://localhost:443")
	}

Simplify your testing, and don't hassle with certificates anymore.
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

// CertificateAuthority represents an x509 certificate authority.
type CertificateAuthority struct {
	cert       *x509.Certificate
	certPool   *x509.CertPool
	publicKey  *pem.Block
	privateKey *pem.Block
}

// KeyPair represents a pair of x509 certificate and private key.
type KeyPair struct {
	cert       *x509.Certificate
	publicKey  *pem.Block
	privateKey *pem.Block
}

// NewCA creates a new CertificateAuthority.
func NewCA() *CertificateAuthority {
	// Create a Certificate Authority Cert
	ca := &CertificateAuthority{cert: &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Never Use this Certificate in Production Inc."},
		},
		SerialNumber:          big.NewInt(42),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}}

	var err error

	// Generate KeyPair
	ca.publicKey, ca.privateKey, err = genKeyPair(ca.cert, ca.cert)
	if err != nil {
		// Should never error, but just incase
		return ca
	}

	// Crete CertPool
	ca.certPool = x509.NewCertPool()
	result := ca.certPool.AppendCertsFromPEM(ca.PublicKey())
	if !result {
		// if error set an empty pool
		ca.certPool = x509.NewCertPool()
	}

	return ca
}

// NewKeyPair generates a new KeyPair signed by the CertificateAuthority for the given domains.
// The domains are used to populate the Subject Alternative Name field of the certificate.
// Returns an error if any of the given domains are invalid.
func (ca *CertificateAuthority) NewKeyPair(domains ...string) (*KeyPair, error) {
	// Create a Certificate
	kp := &KeyPair{cert: &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Never Use this Certificate in Production Inc."},
		},
		DNSNames:              domains,
		SerialNumber:          big.NewInt(42),
		NotAfter:              time.Now().Add(2 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}}

	var err error
	kp.publicKey, kp.privateKey, err = genKeyPair(ca.cert, kp.cert)
	if err != nil {
		return kp, fmt.Errorf("could not generate keypair: %s", err)
	}
	return kp, nil
}

// CertPool returns a Certificate Pool of the CertificateAuthority Certificate
func (ca *CertificateAuthority) CertPool() *x509.CertPool {
	return ca.certPool
}

// PrivateKey returns the private key of the CertificateAuthority.
func (ca *CertificateAuthority) PrivateKey() []byte {
	return pem.EncodeToMemory(ca.privateKey)
}

// PublicKey returns the public key of the CertificateAuthority.
func (ca *CertificateAuthority) PublicKey() []byte {
	return pem.EncodeToMemory(ca.publicKey)
}

// ToFile saves the CertificateAuthority certificate and private key to the specified files.
// Returns an error if any file operation fails.
func (ca *CertificateAuthority) ToFile(certFile, keyFile string) error {
	// Write Certificate
	err := os.WriteFile(certFile, ca.PublicKey(), 0640)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write Key
	err = os.WriteFile(keyFile, ca.PrivateKey(), 0640)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	return nil
}

// ToTempFile saves the CertificateAuthority certificate and private key to temporary files.
// The temporary files are created in the specified directory and have random names.
func (ca *CertificateAuthority) ToTempFile(dir string) (*os.File, *os.File, error) {
	cfh, err := os.CreateTemp(dir, "*.cert")
	if err != nil {
		return &os.File{}, &os.File{}, fmt.Errorf("could not create temporary file - %s", err)
	}
	defer cfh.Close()
	_, err = cfh.Write(ca.PublicKey())
	if err != nil {
		return cfh, &os.File{}, fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write to Key File
	kfh, err := os.CreateTemp(dir, "*.key")
	if err != nil {
		return cfh, &os.File{}, fmt.Errorf("unable to create certificate file - %s", err)
	}
	defer kfh.Close()
	_, err = kfh.Write(ca.PrivateKey())
	if err != nil {
		return cfh, kfh, fmt.Errorf("unable to create certificate file - %s", err)
	}

	return cfh, kfh, nil
}

// PrivateKey returns the private key of the KeyPair.
func (kp *KeyPair) PrivateKey() []byte {
	return pem.EncodeToMemory(kp.privateKey)
}

// PublicKey returns the public key of the KeyPair.
func (kp *KeyPair) PublicKey() []byte {
	return pem.EncodeToMemory(kp.publicKey)
}

// ToFile saves the KeyPair certificate and private key to the specified files.
// Returns an error if any file operation fails.
func (kp *KeyPair) ToFile(certFile, keyFile string) error {
	// Write Certificate
	err := os.WriteFile(certFile, kp.PublicKey(), 0640)
	if err != nil {
		return fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write Key
	err = os.WriteFile(keyFile, kp.PrivateKey(), 0640)
	if err != nil {
		return fmt.Errorf("unable to create key file - %s", err)
	}

	return nil
}

// ToTempFile saves the KeyPair certificate and private key to temporary files.
// The temporary files are created in the specified directory and have random names.
func (kp *KeyPair) ToTempFile(dir string) (*os.File, *os.File, error) {
	cfh, err := os.CreateTemp(dir, "*.cert")
	if err != nil {
		return &os.File{}, &os.File{}, fmt.Errorf("could not create temporary file - %s", err)
	}
	defer cfh.Close()
	_, err = cfh.Write(kp.PublicKey())
	if err != nil {
		return cfh, &os.File{}, fmt.Errorf("unable to create certificate file - %s", err)
	}

	// Write to Key File
	kfh, err := os.CreateTemp(dir, "*.key")
	if err != nil {
		return cfh, &os.File{}, fmt.Errorf("unable to create key file - %s", err)
	}
	defer kfh.Close()
	_, err = kfh.Write(kp.PrivateKey())
	if err != nil {
		return cfh, kfh, fmt.Errorf("unable to create key file - %s", err)
	}

	return cfh, kfh, nil
}

// GenerateCerts generates an x509 certificate and key.
// It returns the certificate and key as byte slices, and any error that occurred.
//
//	cert, key, err := GenerateCerts()
//	if err != nil {
//		// handle error
//	}
func GenerateCerts(domains ...string) ([]byte, []byte, error) {
	ca := NewCA()

	// Returning CA for backwards compatibility
	if len(domains) == 0 {
		return ca.PublicKey(), ca.PrivateKey(), nil
	}

	// If domains exist return a regular cert
	kp, err := ca.NewKeyPair(domains...)
	if err != nil {
		return nil, nil, err
	}
	return kp.PublicKey(), kp.PrivateKey(), nil
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
	// Create Certs using CA for backwards compatibility
	return NewCA().ToFile(certFile, keyFile)
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
	// Create Certs using CA for backwards compatibility
	cert, key, err := NewCA().ToTempFile(dir)
	if err != nil {
		return "", "", err
	}

	return cert.Name(), key.Name(), nil
}

// genKeyPair will generate a key and certificate from the provided Certificate and CA.
func genKeyPair(ca *x509.Certificate, cert *x509.Certificate) (*pem.Block, *pem.Block, error) {
	// Create a Private Key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate rsa key - %s", err)
	}

	// Use CA Cert to sign a CSR and create a Public Cert
	certificate, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate certificate - %s", err)
	}

	// Convert keys into pem.Block
	c := &pem.Block{Type: "CERTIFICATE", Bytes: certificate}
	k := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return c, k, nil
}
