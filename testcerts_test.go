package testcerts

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertsUsage(t *testing.T) {
	// Generate CA
	ca := NewCA()
	if len(ca.PrivateKey()) == 0 || len(ca.PublicKey()) == 0 {
		t.Errorf("Unexpected key length from public/private key")
	}

	t.Run("Verify CertPool", func(t *testing.T) {
		cp := x509.NewCertPool()
		if cp.AppendCertsFromPEM(ca.PublicKey()) {
			if cp.Equal(ca.CertPool()) {
				return
			}
		}
		t.Errorf("certpool is not valid")
	})

	t.Run("Write to File", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatalf("Error creating temporary directory: %s", err)
		}
		defer os.RemoveAll(tempDir)

		certPath := filepath.Join(tempDir, "cert")
		keyPath := filepath.Join(tempDir, "key")

		err = ca.ToFile(certPath, keyPath)
		if err != nil {
			t.Fatalf("Error while generating certificates to files - %s", err)
		}

		// Check if Cert file exists
		_, err = os.Stat(certPath)
		if err != nil {
			t.Fatalf("Error while generating certificates to files file error - %s", err)
		}

		// Check if Key file exists
		_, err = os.Stat(keyPath)
		if err != nil {
			t.Fatalf("Error while generating certificates to files file error - %s", err)
		}
	})

	t.Run("Write to Invalid File", func(t *testing.T) {
		certPath := "/notValid/path/cert"
		keyPath := "/notValid/path/key"

		err := ca.ToFile(certPath, keyPath)
		if err == nil {
			t.Errorf("Unexpected success generating certificates to files")
		}

		// Check if Cert file exists
		_, err = os.Stat(certPath)
		if !os.IsNotExist(err) {
			t.Errorf("Unexpected success while generating certificates to files")
		}

		// Check if Key file exists
		_, err = os.Stat(keyPath)
		if !os.IsNotExist(err) {
			t.Errorf("Unexpected success while generating certificates to files")
		}
	})

	t.Run("Write to TempFile", func(t *testing.T) {
		cert, key, err := ca.ToTempFile("")
		if err != nil {
			t.Errorf("Error generating tempfile - %s", err)
		}

		_, err = os.Stat(cert.Name())
		if err != nil {
			t.Errorf("File does not exist - %s", cert.Name())
		}
		defer os.Remove(cert.Name())

		_, err = os.Stat(key.Name())
		if err != nil {
			t.Errorf("File does not exist - %s", key.Name())
		}
		defer os.Remove(key.Name())
	})

	t.Run("Write to Invalid TempFile", func(t *testing.T) {
		_, _, err := ca.ToTempFile("/notValidPath/")
		if err == nil {
			t.Errorf("Unexpected success with invalid tempfile directory")
		}
	})

	for _, domains := range [][]string{{"localhost", "127.0.0.1", "example.com"}, {}} {
		t.Run(fmt.Sprintf("Generate KeyPair with %d Domains", len(domains)), func(t *testing.T) {
			kp, err := ca.NewKeyPair(domains...)
			if err != nil {
				t.Errorf("NewKeyPair() returned error when generating with domains: %s", err)
			}

			t.Run("Validate Key Length", func(t *testing.T) {
				if len(kp.PrivateKey()) == 0 || len(kp.PublicKey()) == 0 {
					t.Errorf("Unexpected key length from public/private key")
				}
			})

			t.Run("Write to File", func(t *testing.T) {
				tempDir, err := os.MkdirTemp("", "")
				if err != nil {
					t.Fatalf("Error creating temporary directory: %s", err)
				}
				defer os.RemoveAll(tempDir)

				certPath := filepath.Join(tempDir, "cert")
				keyPath := filepath.Join(tempDir, "key")

				err = kp.ToFile(certPath, keyPath)
				if err != nil {
					t.Errorf("Error while generating certificates to files - %s", err)
				}

				// Check if Cert file exists
				_, err = os.Stat(certPath)
				if err != nil {
					t.Errorf("Error while generating certificates to files file error - %s", err)
				}

				// Check if Key file exists
				_, err = os.Stat(keyPath)
				if err != nil {
					t.Errorf("Error while generating certificates to files file error - %s", err)
				}
			})

			t.Run("Write to Invalid File", func(t *testing.T) {
				certPath := "/notValid/path/cert"
				keyPath := "/notValid/path/key"

				err := kp.ToFile(certPath, keyPath)
				if err == nil {
					t.Errorf("Unexpected success generating certificates to files")
				}

				// Check if Cert file exists
				_, err = os.Stat(certPath)
				if !os.IsNotExist(err) {
					t.Errorf("Unexpected success while generating certificates to files")
				}

				// Check if Key file exists
				_, err = os.Stat(keyPath)
				if !os.IsNotExist(err) {
					t.Errorf("Unexpected success while generating certificates to files")
				}
			})

			t.Run("Write to TempFile", func(t *testing.T) {
				cert, key, err := kp.ToTempFile("")
				if err != nil {
					t.Errorf("Error generating tempfile - %s", err)
				}

				_, err = os.Stat(cert.Name())
				if err != nil {
					t.Errorf("File does not exist - %s", cert.Name())
				}
				defer os.Remove(cert.Name())

				_, err = os.Stat(key.Name())
				if err != nil {
					t.Errorf("File does not exist - %s", key.Name())
				}
				defer os.Remove(key.Name())
			})

			t.Run("Write to Invalid TempFile", func(t *testing.T) {
				_, _, err := kp.ToTempFile("/notValidPath/")
				if err == nil {
					t.Errorf("Unexpected success with invalid tempfile directory")
				}
			})

		})
	}

}

func TestGeneratingCerts(t *testing.T) {
	_, _, err := GenerateCerts()
	if err != nil {
		t.Errorf("Error while generating certificates - %s", err)
	}
}

func TestGeneratingCertsToFile(t *testing.T) {
	t.Run("Test the happy path", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("Error creating temporary directory: %s", err)
		}
		defer os.RemoveAll(tempDir)

		certPath := filepath.Join(tempDir, "cert")
		keyPath := filepath.Join(tempDir, "key")

		err = GenerateCertsToFile(certPath, keyPath)
		if err != nil {
			t.Errorf("Error while generating certificates to files - %s", err)
		}

		// Check if Cert file exists
		_, err = os.Stat(certPath)
		if err != nil {
			t.Errorf("Error while generating certificates to files file error - %s", err)
		}

		// Check if Key file exists
		_, err = os.Stat(keyPath)
		if err != nil {
			t.Errorf("Error while generating certificates to files file error - %s", err)
		}
	})

	t.Run("Testing the unhappy path for cert files", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("Error creating temporary directory: %s", err)
		}
		defer os.RemoveAll(tempDir)

		certPath := filepath.Join(tempDir, "doesntexist", "cert")
		keyPath := filepath.Join(tempDir, "key")

		err = GenerateCertsToFile(certPath, keyPath)
		if err == nil {
			t.Errorf("Expected error when generating a certificate with a bad path got nil")
		}
	})

	t.Run("Testing the unhappy path for key files", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("Error creating temporary directory: %s", err)
		}
		defer os.RemoveAll(tempDir)

		certPath := filepath.Join(tempDir, "cert")
		keyPath := filepath.Join(tempDir, "doesntexist", "key")

		err = GenerateCertsToFile(certPath, keyPath)
		if err == nil {
			t.Errorf("Expected error when generating a key with a bad path got nil")
		}
	})

	t.Run("Testing the unhappy path for insufficient permissions", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "permission-test")
		if err != nil {
			t.Errorf("Error creating temp directory - %s", err)
		}
		defer os.RemoveAll(dir)

		// Change permissions of the temp directory so that it can't be written to
		err = os.Chmod(dir, 0444)
		if err != nil {
			t.Errorf("Error changing permissions of temp directory - %s", err)
		}

		certPath := filepath.Join(dir, "cert")
		keyPath := filepath.Join(dir, "key")

		err = GenerateCertsToFile(certPath, keyPath)
		if err == nil {
			t.Errorf("Expected error when generating certificate with insufficient permissions, got nil")
		}
	})
}

func TestGenerateCertsToTempFile(t *testing.T) {
	t.Run("Test the happy path", func(t *testing.T) {
		certFile, keyFile, err := GenerateCertsToTempFile("/tmp")
		if err != nil {
			t.Errorf("Error while generating certificates to temp files - %s", err)
		}

		// Check if Cert file exists
		_, err = os.Stat(certFile)
		if err != nil {
			t.Errorf("Error while generating certificates to temp files file error - %s", err)
		}
		_ = os.Remove(certFile)

		// Check if Key file exists
		_, err = os.Stat(keyFile)
		if err != nil {
			t.Errorf("Error while generating certificates to temp files file error - %s", err)
		}
		_ = os.Remove(keyFile)
	})

	t.Run("Testing the unhappy path when creating cert temp file", func(t *testing.T) {
		_, _, err := GenerateCertsToTempFile("/doesnotexist")
		if err == nil {
			t.Errorf("Expected error when generating a certificate with a bad directory path got nil")
		}
	})

	t.Run("Testing the unhappy path for insufficient permissions when creating temp file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "permission-test")
		if err != nil {
			t.Errorf("Error creating temp directory - %s", err)
		}
		defer os.RemoveAll(dir)

		// Change permissions of the temp directory so that it can't be written to
		err = os.Chmod(dir, 0444)
		if err != nil {
			t.Errorf("Error changing permissions of temp directory - %s", err)
		}

		_, _, err = GenerateCertsToTempFile(dir)
		if err == nil {
			t.Errorf("Expected error when generating a key with a bad directory path got nil")
		}
	})
}

// testUsingCerts is called by the two tests below. Both test setting up certificates and subsequently
// configuring the transport of the http.Client to use the generated certificate.
// One uses the own public key as part of the pool (self signed cert) and one uses the cert from the CA.
func testUsingCerts(t *testing.T, rootCAs func(ca *CertificateAuthority, certs *KeyPair) *x509.CertPool) {
	// Create a signed Certificate and Key for "localhost"
	ca := NewCA()
	certs, err := ca.NewKeyPair("localhost")
	if err != nil {
		t.Fatalf("Error generating keypair - %s", err)
	}

	// Write certificates to a file
	cert, key, err := certs.ToTempFile("")
	if err != nil {
		t.Fatalf("Error writing certs to temp files - %s", err)
	}

	// Create HTTP Server
	server := &http.Server{
		Addr: "0.0.0.0:8443",
	}
	defer server.Close()

	go func() {
		// Start HTTP Listener
		err = server.ListenAndServeTLS(cert.Name(), key.Name())
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Listener returned error - %s", err)
		}
	}()

	// Wait for Listener to start
	<-time.After(3 * time.Second)

	// Setup HTTP Client with Cert Pool
	certpool := rootCAs(ca, certs)
	if certpool == nil {
		t.Fatalf("Test configuration error: rootCAs arg function returned nil instead of a x509.CertPool")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		},
	}

	// Make an HTTPS request
	_, err = client.Get("https://localhost:8443")
	if err != nil {
		t.Errorf("Client returned error - %s", err)
	}
}

func TestUsingSelfSignedCerts(t *testing.T) {
	testUsingCerts(t, func(_ *CertificateAuthority, certs *KeyPair) *x509.CertPool {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(certs.PublicKey())
		return pool
	})
}

func TestUsingCertsWithCA(t *testing.T) {
	testUsingCerts(t, func(ca *CertificateAuthority, _ *KeyPair) *x509.CertPool {
		return ca.certPool
	})
}
