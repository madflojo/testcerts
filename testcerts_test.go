package testcerts

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertsUsage(t *testing.T) {
	// Generate CA
	ca := NewCA()
	if len(ca.PrivateKey()) == 0 || len(ca.PublicKey()) == 0 {
		t.Errorf("Unexpected key length from public/private key")
	}

	t.Run("Verify Cert",
		func(t *testing.T) {
			if cert := ca.Cert(); cert == nil {
				t.Fatalf("Expected certificate, got nil")
			} else if cert.SerialNumber.Cmp(big.NewInt(42)) != 0 {
				t.Errorf("Unexpected Serial Number, expected 42 got %v", cert.SerialNumber)
			} else if cert.Subject.Organization[0] != "Never Use this Certificate in Production Inc." {
				t.Errorf("Unexpected Organization, expected 'Never Use this Certificate in Production Inc.' got %v", cert.Subject.Organization[0])
			}
		},
	)

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

			t.Run("Verify Cert", func(t *testing.T) {
				if cert := kp.Cert(); cert == nil {
					t.Fatalf("Expected certificate, got nil")
				}
			})

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
		{
			name: "Happy Path - Serial Number provided",
			cfg: KeyPairConfig{
				Domains:      []string{"example.com"},
				SerialNumber: big.NewInt(123),
			},
			err: nil,
		},
		{
			name: "Happy Path - Common Name provided",
			cfg: KeyPairConfig{
				Domains:    []string{"example.com"},
				CommonName: "Example Common Name",
			},
			err: nil,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			certs, err := NewCA().NewKeyPairFromConfig(c.cfg)
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

	t.Run("Serial Number is correct in Key Pair", func(t *testing.T) {
		certs, err := NewCA().NewKeyPairFromConfig(KeyPairConfig{
			Domains:      []string{"example.com"},
			SerialNumber: big.NewInt(123),
		})
		if err != nil {
			t.Fatalf("KeyPair Generation Failed expected nil got %v", err)
		}

		if certs.cert.SerialNumber.Cmp(big.NewInt(123)) != 0 {
			t.Fatalf("Unexpected Serial Number expected 123 got %v", certs.cert.SerialNumber)
		}
	})

	t.Run("Common Name is correct in Key Pair", func(t *testing.T) {
		certs, err := NewCA().NewKeyPairFromConfig(KeyPairConfig{
			Domains:    []string{"example.com"},
			CommonName: "Example Common Name",
		})
		if err != nil {
			t.Fatalf("KeyPair Generation Failed expected nil got %v", err)
		}

		if certs.cert.Subject.CommonName != "Example Common Name" {
			t.Fatalf("Unexpected Common Name expected 'Example Common Name' got %v", certs.cert.Subject.CommonName)
		}
	})
}

type FullFlowTestCase struct {
	name       string
	listenAddr string
	domains    []string
	kpCfg      KeyPairConfig
	kpErr      error
	clientErr  error
}

func TestFullFlow(t *testing.T) {

	tc := []FullFlowTestCase{
		{
			name:       "Localhost Domain",
			listenAddr: "0.0.0.0",
			domains:    []string{"localhost"},
			kpCfg:      KeyPairConfig{},
			kpErr:      nil,
		},
		{
			name:       "Localhost IP",
			listenAddr: "0.0.0.0",
			kpCfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1"},
			},
			kpErr: nil,
		},
		{
			name:       "Localhost IP and Domain",
			listenAddr: "0.0.0.0",
			kpCfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "::1"},
				Domains:     []string{"localhost"},
			},
			kpErr: nil,
		},
		{
			name:       "Localhost IP, Domain, Serial Number, and Common Name",
			listenAddr: "0.0.0.0",
			kpCfg: KeyPairConfig{
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Domains:      []string{"localhost"},
				SerialNumber: big.NewInt(123),
				CommonName:   "Example Common Name",
			},
			kpErr: nil,
		},
		{
			name:       "Expired certificate",
			listenAddr: "0.0.0.0",
			kpCfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1"},
				Expired:     true,
			},
			kpErr:     nil,
			clientErr: errors.New("failed to verify certificate: x509: certificate has expired or is not yet valid"),
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			var err error
			var cert, clientCert *KeyPair

			// Generate CA
			ca := NewCA()

			// Generate Server Cert if Domains are provided
			if len(c.domains) > 0 {
				cert, err = ca.NewKeyPair(c.domains...)
				if err != c.kpErr {
					t.Fatalf("KeyPair Generation Failed expected %v got %v", c.kpErr, err)
				}
				if err != nil {
					return
				}
			}

			// Generate Server Cert with Config
			if err = c.kpCfg.Validate(); err == nil {
				cert, err = ca.NewKeyPairFromConfig(c.kpCfg)
				if err != c.kpErr {
					t.Fatalf("KeyPair Generation Failed expected %v got %v", c.kpErr, err)
				}
				if err != nil {
					return
				}
			}

			if cert == nil {
				t.Fatalf("Test Conditions failure to generate server keypair - %s", err)
			}

			// Setup Server TLS Config
			serverTLSConfig, err := cert.ConfigureTLSConfig(ca.GenerateTLSConfig())
			if err != nil {
				t.Fatalf("Error configuring server TLS - %s", err)
			}

			// Require Valid Client Cert
			serverTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

			// Generate Client Cert
			clientCert, err = ca.NewKeyPair()
			if err != nil {
				t.Fatalf("Error generating client keypair - %s", err)
			}

			// Setup Client TLS Config
			clientTLSConfig, err := clientCert.ConfigureTLSConfig(ca.GenerateTLSConfig())
			if err != nil {
				t.Fatalf("Error configuring client TLS - %s", err)
			}

			// Setup HTTP Server
			server := &http.Server{
				Addr: c.listenAddr + ":8443",
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, err := w.Write([]byte("Hello, World!"))
					if err != nil {
						t.Errorf("Error writing response - %s", err)
					}
				}),
				TLSConfig: serverTLSConfig,
			}
			defer server.Close()

			// Write Certs to Temp Files
			certFile, keyFile, err := cert.ToTempFile("")
			if err != nil {
				t.Fatalf("Error writing certs to temp files - %s", err)
			}

			go func() {
				// Start HTTP Listener
				err = server.ListenAndServeTLS(certFile.Name(), keyFile.Name())
				if err != nil && err != http.ErrServerClosed {
					t.Errorf("Listener returned error - %s", err)
				}
			}()

			// Wait for Listener to start
			<-time.After(3 * time.Second)

			// Setup HTTP Client
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientTLSConfig,
				},
			}

			// Make an HTTPS request
			var addr []string
			addr = append(addr, c.domains...)
			addr = append(addr, c.kpCfg.Domains...)
			addr = append(addr, c.kpCfg.IPAddresses...)

			for _, a := range addr {
				t.Run("Client Request to "+a, func(t *testing.T) {
					rsp, err := client.Get("https://" + a + ":8443")

					if err != nil && c.clientErr == nil {
						t.Fatalf("client returned unexpected error: %v", err)
					}

					if c.clientErr != nil {
						if err == nil {
							t.Fatalf("expected client error %v, got nil", c.clientErr)
						}
						if !strings.Contains(err.Error(), c.clientErr.Error()) {
							t.Fatalf("client returned wrong error - expected substring %v got %v", c.clientErr, err)
						}
						return
					}

					if rsp == nil {
						t.Fatalf("client returned nil response without error")
					}
					defer rsp.Body.Close()

					if rsp.StatusCode != http.StatusOK {
						t.Fatalf("unexpected response code - %d", rsp.StatusCode)
					}
				})
			}
		})
	}
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

	// Setup Server TLS Config
	serverTLSConfig, err := certs.ConfigureTLSConfig(ca.GenerateTLSConfig())
	if err != nil {
		fmt.Printf("Error configuring server TLS - %s", err)
	}

	// Require Valid Client Cert
	serverTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	// Create an HTTP Server
	server := &http.Server{
		Addr: "0.0.0.0:8443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, err := w.Write([]byte("Hello, World!"))
			if err != nil {
				fmt.Printf("Error writing response - %s", err)
			}
		}),
		TLSConfig: serverTLSConfig,
	}
	defer server.Close()

	go func() {
		// Start HTTP Listener
		err = server.ListenAndServeTLS(cert.Name(), key.Name())
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("Listener returned error - %s", err)
		}
	}()

	// Wait for Listener to start
	<-time.After(3 * time.Second)

	// Client TLS Config
	clientTLSConfig, err := certs.ConfigureTLSConfig(ca.GenerateTLSConfig())
	if err != nil {
		fmt.Printf("Error configuring client TLS - %s", err)
	}

	// Setup HTTP Client with Cert Pool
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
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
