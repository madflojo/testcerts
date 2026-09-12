package testcerts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assertDirectoryEmpty(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("error reading directory %q: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files in %q, found %d", dir, len(entries))
	}
}

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
		t.Cleanup(func() {
			_ = os.RemoveAll(tempDir)
		})

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
		t.Cleanup(func() {
			_ = os.Remove(cert.Name())
		})

		_, err = os.Stat(key.Name())
		if err != nil {
			t.Errorf("File does not exist - %s", key.Name())
		}
		t.Cleanup(func() {
			_ = os.Remove(key.Name())
		})
	})

	t.Run("Write Missing Data to File", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatalf("Error creating temporary directory: %s", err)
		}
		t.Cleanup(func() {
			_ = os.RemoveAll(tempDir)
		})

		certPath := filepath.Join(tempDir, "cert")
		keyPath := filepath.Join(tempDir, "key")

		var emptyCA *CertificateAuthority
		err = emptyCA.ToFile(certPath, keyPath)
		if !errors.Is(err, ErrEmptyCertificateData) {
			t.Fatalf("expected ErrEmptyCertificateData, got %v", err)
		}
		if _, statErr := os.Stat(certPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected no certificate file, got %v", statErr)
		}
		if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected no key file, got %v", statErr)
		}
	})

	t.Run("Reject Invalid File Data", func(t *testing.T) {
		validCert := ca.PublicKey()
		validKey := ca.PrivateKey()
		for _, tc := range []struct {
			name     string
			certData []byte
			keyData  []byte
			wantErr  error
		}{
			{
				name:     "invalid cert",
				certData: []byte("not pem"),
				keyData:  validKey,
				wantErr:  ErrInvalidCertificateData,
			},
			{
				name:     "empty key",
				certData: validCert,
				keyData:  nil,
				wantErr:  ErrEmptyKeyData,
			},
			{
				name:     "invalid key",
				certData: validCert,
				keyData:  []byte("not pem"),
				wantErr:  ErrInvalidKeyData,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tempDir, err := os.MkdirTemp("", "")
				if err != nil {
					t.Fatalf("Error creating temporary directory: %s", err)
				}
				t.Cleanup(func() {
					_ = os.RemoveAll(tempDir)
				})

				err = writePairToFiles(
					tc.certData,
					filepath.Join(tempDir, "cert"),
					tc.keyData,
					filepath.Join(tempDir, "key"),
				)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
			})
		}
	})

	t.Run("Write to Invalid TempFile", func(t *testing.T) {
		_, _, err := ca.ToTempFile("/notValidPath/")
		if err == nil {
			t.Errorf("Unexpected success with invalid tempfile directory")
		}
	})

	t.Run("Write Missing Data to TempFile", func(t *testing.T) {
		tempDir := t.TempDir()

		var emptyCA *CertificateAuthority
		_, _, err := emptyCA.ToTempFile(tempDir)
		if !errors.Is(err, ErrEmptyCertificateData) {
			t.Fatalf("expected ErrEmptyCertificateData, got %v", err)
		}

		assertDirectoryEmpty(t, tempDir)
	})

	t.Run("Reject Invalid TempFile Data", func(t *testing.T) {
		validCert := ca.PublicKey()
		validKey := ca.PrivateKey()
		for _, tc := range []struct {
			name     string
			certData []byte
			keyData  []byte
			wantErr  error
		}{
			{
				name:     "invalid cert",
				certData: []byte("not pem"),
				keyData:  validKey,
				wantErr:  ErrInvalidCertificateData,
			},
			{
				name:     "empty key",
				certData: validCert,
				keyData:  nil,
				wantErr:  ErrEmptyKeyData,
			},
			{
				name:     "invalid key",
				certData: validCert,
				keyData:  []byte("not pem"),
				wantErr:  ErrInvalidKeyData,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tempDir := t.TempDir()

				_, _, err := writePairToTempFiles(tc.certData, tc.keyData, tempDir)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}

				assertDirectoryEmpty(t, tempDir)
			})
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
				t.Cleanup(func() {
					_ = os.RemoveAll(tempDir)
				})

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
				t.Cleanup(func() {
					_ = os.Remove(cert.Name())
				})

				_, err = os.Stat(key.Name())
				if err != nil {
					t.Errorf("File does not exist - %s", key.Name())
				}
				t.Cleanup(func() {
					_ = os.Remove(key.Name())
				})
			})

			t.Run("Remove Cert When Key Write Fails", func(t *testing.T) {
				tempDir, err := os.MkdirTemp("", "")
				if err != nil {
					t.Fatalf("Error creating temporary directory: %s", err)
				}
				t.Cleanup(func() {
					_ = os.RemoveAll(tempDir)
				})

				certPath := filepath.Join(tempDir, "cert")
				keyPath := filepath.Join(tempDir, "doesntexist", "key")

				err = kp.ToFile(certPath, keyPath)
				if err == nil {
					t.Fatalf("expected key write error, got nil")
				}
				if _, statErr := os.Stat(certPath); !os.IsNotExist(statErr) {
					t.Fatalf("expected certificate file cleanup, got %v", statErr)
				}
			})

			t.Run("Write to Invalid TempFile", func(t *testing.T) {
				_, _, err := kp.ToTempFile("/notValidPath/")
				if err == nil {
					t.Errorf("Unexpected success with invalid tempfile directory")
				}
			})

			t.Run("Write Missing Data to TempFile", func(t *testing.T) {
				tempDir := t.TempDir()

				var emptyKP *KeyPair
				_, _, err := emptyKP.ToTempFile(tempDir)
				if !errors.Is(err, ErrEmptyCertificateData) {
					t.Fatalf("expected ErrEmptyCertificateData, got %v", err)
				}

				assertDirectoryEmpty(t, tempDir)
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

	t.Run("Expired is false by default, NotAfter is in the future", func(t *testing.T) {
		certs, err := NewCA().NewKeyPairFromConfig(KeyPairConfig{
			Domains: []string{"example.com"},
		})
		if err != nil {
			t.Fatalf("KeyPair Generation Failed expected nil got %v", err)
		}

		if !certs.cert.NotAfter.After(time.Now()) {
			t.Fatalf("Expected NotAfter to be in the future, got %v", certs.cert.NotAfter)
		}
	})

	t.Run("Expired true produces a certificate with NotAfter in the past", func(t *testing.T) {
		certs, err := NewCA().NewKeyPairFromConfig(KeyPairConfig{
			Domains: []string{"example.com"},
			Expired: true,
		})
		if err != nil {
			t.Fatalf("KeyPair Generation Failed expected nil got %v", err)
		}

		if !certs.cert.NotAfter.Before(time.Now()) {
			t.Fatalf("Expected NotAfter to be in the past for expired cert, got %v", certs.cert.NotAfter)
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
	name      string
	domains   []string
	kpCfg     KeyPairConfig
	kpErr     error
	clientErr error
}

func TestFullFlow(t *testing.T) {

	tc := []FullFlowTestCase{
		{
			name:    "Localhost Domain",
			domains: []string{"localhost"},
			kpCfg:   KeyPairConfig{},
			kpErr:   nil,
		},
		{
			name: "Localhost IP",
			kpCfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1"},
			},
			kpErr: nil,
		},
		{
			name: "Localhost IP and Domain",
			kpCfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "::1"},
				Domains:     []string{"localhost"},
			},
			kpErr: nil,
		},
		{
			name: "Localhost IP, Domain, Serial Number, and Common Name",
			kpCfg: KeyPairConfig{
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Domains:      []string{"localhost"},
				SerialNumber: big.NewInt(123),
				CommonName:   "Example Common Name",
			},
			kpErr: nil,
		},
		{
			name: "Expired certificate",
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
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Error creating listener - %s", err)
			}
			t.Cleanup(func() {
				_ = listener.Close()
			})

			server := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if _, writeErr := w.Write([]byte("Hello, World!")); writeErr != nil {
						t.Errorf("Error writing response - %s", writeErr)
					}
				}),
				TLSConfig: serverTLSConfig,
			}
			t.Cleanup(func() {
				_ = server.Close()
			})

			// Write Certs to Temp Files
			certFile, keyFile, err := cert.ToTempFile("")
			if err != nil {
				t.Fatalf("Error writing certs to temp files - %s", err)
			}

			serverErrCh := make(chan error, 1)
			go func() {
				// Start HTTP Listener
				serverErrCh <- server.ServeTLS(listener, certFile.Name(), keyFile.Name())
			}()

			// Setup HTTP Client
			baseTransport := &http.Transport{
				TLSClientConfig: clientTLSConfig,
			}
			baseTransport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, listener.Addr().String())
			}
			client := &http.Client{
				Transport: baseTransport,
			}

			// Make an HTTPS request
			var addr []string
			addr = append(addr, c.domains...)
			addr = append(addr, c.kpCfg.Domains...)
			addr = append(addr, c.kpCfg.IPAddresses...)

			for _, a := range addr {
				t.Run("Client Request to "+a, func(t *testing.T) {
					host := a
					if strings.Contains(a, ":") {
						host = "[" + a + "]"
					}
					req, reqErr := http.NewRequest(http.MethodGet, "https://"+host, nil)
					if reqErr != nil {
						t.Fatalf("could not create request: %v", reqErr)
					}
					rsp, err := client.Do(req)

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
					t.Cleanup(func() {
						_ = rsp.Body.Close()
					})

					if rsp.StatusCode != http.StatusOK {
						t.Fatalf("unexpected response code - %d", rsp.StatusCode)
					}
				})
			}

			if closeErr := server.Close(); closeErr != nil {
				t.Errorf("error closing server: %v", closeErr)
			}
			if serveErr := <-serverErrCh; serveErr != nil && serveErr != http.ErrServerClosed {
				t.Errorf("Listener returned error - %s", serveErr)
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
		return
	}

	// Write the certificates to a file
	cert, key, err := certs.ToTempFile("")
	if err != nil {
		fmt.Printf("Error writing certs to temp files - %s", err)
		return
	}

	// Setup Server TLS Config
	serverTLSConfig, err := certs.ConfigureTLSConfig(ca.GenerateTLSConfig())
	if err != nil {
		fmt.Printf("Error configuring server TLS - %s", err)
		return
	}

	// Require Valid Client Cert
	serverTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	// Create an HTTP Server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("Error creating listener - %s", err)
		return
	}
	defer func() {
		_ = listener.Close()
	}()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, writeErr := w.Write([]byte("Hello, World!")); writeErr != nil {
				fmt.Printf("Error writing response - %s", writeErr)
			}
		}),
		TLSConfig: serverTLSConfig,
	}
	defer func() {
		_ = server.Close()
	}()

	serverErrCh := make(chan error, 1)
	go func() {
		// Start HTTP Listener
		serverErrCh <- server.ServeTLS(listener, cert.Name(), key.Name())
	}()

	// Client TLS Config
	clientTLSConfig, err := certs.ConfigureTLSConfig(ca.GenerateTLSConfig())
	if err != nil {
		fmt.Printf("Error configuring client TLS - %s", err)
		return
	}

	// Setup HTTP Client with Cert Pool
	transport := &http.Transport{
		TLSClientConfig: clientTLSConfig,
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, listener.Addr().String())
	}
	client := &http.Client{
		Transport: transport,
	}

	// Make an HTTPS request
	rsp, err := client.Get("https://localhost")
	if err != nil {
		fmt.Printf("Client returned error - %s", err)
		return
	}
	defer func() {
		_ = rsp.Body.Close()
	}()

	// Print the response
	fmt.Println(rsp.Status)
	_, _ = io.Copy(io.Discard, rsp.Body)

	if closeErr := server.Close(); closeErr != nil {
		fmt.Printf("Error closing server - %s", closeErr)
		return
	}
	if serveErr := <-serverErrCh; serveErr != nil && serveErr != http.ErrServerClosed {
		fmt.Printf("Listener returned error - %s", serveErr)
		return
	}

	// Output:
	// 200 OK
}
