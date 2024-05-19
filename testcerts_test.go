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

type KeyPairConfigTestCase struct {
	name string
	cfg  KeyPairConfig
	err  error
}

func TestKeyPairConfig(t *testing.T) {
	tc := []KeyPairConfigTestCase{
		{
			name: "Happy Path - Simple Domain",
			cfg: KeyPairConfig{
				Domains: []string{"example.com"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Domains",
			cfg: KeyPairConfig{
				Domains: []string{"example.com", "example.org"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Domains with Wildcard",
			cfg: KeyPairConfig{
				Domains: []string{"example.com", "*.example.com"},
			},
			err: nil,
		},
		{
			name: "Empty Config",
			cfg:  KeyPairConfig{},
			err:  ErrEmptyConfig,
		},
		{
			name: "Happy Path - Valid IP",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Valid IPs",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "10.0.0.0"},
			},
			err: nil,
		},
		{
			name: "Happy Path - IPv6 Localhost",
			cfg: KeyPairConfig{
				IPAddresses: []string{"::1"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple IPv6 Addresses",
			cfg: KeyPairConfig{
				IPAddresses: []string{"::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Valid IP and Domain",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "10.0.0.0"},
				Domains:     []string{"example.com", "localhost"},
			},
			err: nil,
		},
		{
			name: "Invalid IP",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "not an IP"},
			},
			err: ErrInvalidIP,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			certs, err := NewCA().NewKeyPairWithConfig(c.cfg)
			if err != c.err {
				t.Fatalf("KeyPair Generation Failed expected %v got %v", c.err, err)
			}

			// Validate Key Length
			if err == nil {
				if len(certs.PrivateKey()) == 0 || len(certs.PublicKey()) == 0 {
					t.Errorf("Unexpected key length from public/private key")
				}
			}
		})
	}
}

func TestFullFlow(t *testing.T) {
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

	// Add handler
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Hello, World!"))
		if err != nil {
			t.Errorf("Error writing response - %s", err)
		}
	})

	// Wait for Listener to start
	<-time.After(3 * time.Second)

	t.Run("TestUsingCA", func(t *testing.T) {
		// Setup HTTP Client with Cert Pool
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: certs.ConfigureTLSConfig(ca.GenerateTLSConfig()),
			},
		}

		// Make an HTTPS request
		rsp, err := client.Get("https://localhost:8443")
		if err != nil {
			t.Errorf("Client returned error - %s", err)
		}

		// Check the response
		if rsp.StatusCode != http.StatusOK {
			t.Errorf("Unexpected response code - %d", rsp.StatusCode)
		}
	})

	t.Run("TestUsingSelfSigned", func(t *testing.T) {
		// Create new CertPool
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(certs.PublicKey())

		// Setup HTTP Client with Cert Pool
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			},
		}

		// Make an HTTPS request
		rsp, err := client.Get("https://localhost:8443")
		if err != nil {
			t.Errorf("Client returned error - %s", err)
		}

		// Check the response
		if rsp.StatusCode != http.StatusOK {
			t.Errorf("Unexpected response code - %d", rsp.StatusCode)
		}
	})
}

func ExampleNewCA() {
	// Generate a new Certificate Authority
	ca := NewCA()

	// Create a new KeyPair with a list of domains
	certs, err := ca.NewKeyPair("localhost")
	if err != nil {
		fmt.Printf("Error generating keypair - %s", err)
	}

	// Write the certificates to a file
	cert, key, err := certs.ToTempFile("")
	if err != nil {
		fmt.Printf("Error writing certs to temp files - %s", err)
	}

	// Create an HTTP Server
	server := &http.Server{
		Addr: "0.0.0.0:8443",
	}
	defer server.Close()

	go func() {
		// Start HTTP Listener
		err = server.ListenAndServeTLS(cert.Name(), key.Name())
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("Listener returned error - %s", err)
		}
	}()

	// Add handler
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Hello, World!"))
		if err != nil {
			fmt.Printf("Error writing response - %s", err)
		}
	})

	// Wait for Listener to start
	<-time.After(3 * time.Second)

	// Setup HTTP Client with Cert Pool
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: certs.ConfigureTLSConfig(ca.GenerateTLSConfig()),
		},
	}

	// Make an HTTPS request
	rsp, err := client.Get("https://localhost:8443")
	if err != nil {
		fmt.Printf("Client returned error - %s", err)
	}

	// Print the response
	fmt.Println(rsp.Status)

	// Output:
	// 200 OK
}
