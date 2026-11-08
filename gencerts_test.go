package testcerts

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGeneratingCerts(t *testing.T) {
	t.Run("No Domain", func(t *testing.T) {
		cert, key, err := GenerateCerts()
		if err != nil {
			t.Errorf("Error while generating certificates - %s", err)
		}

		if len(cert) == 0 || len(key) == 0 {
			t.Errorf("Cert %d or Key %d is empty", len(cert), len(key))
		}
	})

	t.Run("With Domain", func(t *testing.T) {
		cert, key, err := GenerateCerts("example.com")
		if err != nil {
			t.Errorf("Error while generating certificates - %s", err)
		}

		if len(cert) == 0 || len(key) == 0 {
			t.Errorf("Cert %d or Key %d is empty", len(cert), len(key))
		}
	})

	t.Run("With Many Domains", func(t *testing.T) {
		cert, key, err := GenerateCerts("example.com", "example.org", "example.net")
		if err != nil {
			t.Errorf("Error while generating certificates - %s", err)
		}

		if len(cert) == 0 || len(key) == 0 {
			t.Errorf("Cert %d or Key %d is empty", len(cert), len(key))
		}
	})
}

func TestGenerateCertsOutputKind(t *testing.T) {
	parse := func(t *testing.T, certPEM []byte) *x509.Certificate {
		t.Helper()
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("certificate is not valid PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("could not parse certificate - %s", err)
		}
		return c
	}

	t.Run("No Domain returns a CA certificate", func(t *testing.T) {
		cert, _, err := GenerateCerts()
		if err != nil {
			t.Fatalf("Error while generating certificates - %s", err)
		}
		c := parse(t, cert)
		if !c.IsCA {
			t.Error("expected a CA certificate")
		}
		if len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 {
			t.Errorf("expected no SANs, got %v %v", c.DNSNames, c.IPAddresses)
		}
	})

	t.Run("With Domains returns a leaf certificate with SANs", func(t *testing.T) {
		domains := []string{"example.com", "example.org"}
		cert, _, err := GenerateCerts(domains...)
		if err != nil {
			t.Fatalf("Error while generating certificates - %s", err)
		}
		c := parse(t, cert)
		if c.IsCA {
			t.Error("expected a leaf certificate, got a CA")
		}
		if len(c.DNSNames) != len(domains) || c.DNSNames[0] != domains[0] || c.DNSNames[1] != domains[1] {
			t.Errorf("DNSNames = %v, want %v", c.DNSNames, domains)
		}
	})
}

func TestGeneratingCertsToFile(t *testing.T) {
	t.Run("Test the happy path", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("Error creating temporary directory: %s", err)
		}
		t.Cleanup(func() {
			_ = os.RemoveAll(tempDir)
		})

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
		t.Cleanup(func() {
			_ = os.RemoveAll(tempDir)
		})

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
		t.Cleanup(func() {
			_ = os.RemoveAll(tempDir)
		})

		certPath := filepath.Join(tempDir, "cert")
		keyPath := filepath.Join(tempDir, "doesntexist", "key")

		err = GenerateCertsToFile(certPath, keyPath)
		if err == nil {
			t.Errorf("Expected error when generating a key with a bad path got nil")
		}
	})

	t.Run("Testing the unhappy path for insufficient permissions", func(t *testing.T) {
		if runtime.GOOS != "windows" && os.Geteuid() == 0 {
			// CAP_DAC_OVERRIDE can also bypass this in some rootless Linux containers.
			t.Skip("running as root bypasses directory permission checks")
		}
		dir, err := os.MkdirTemp("", "permission-test")
		if err != nil {
			t.Errorf("Error creating temp directory - %s", err)
		}
		t.Cleanup(func() {
			_ = os.RemoveAll(dir)
		})

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
		t.Cleanup(func() {
			_ = os.Remove(certFile)
		})

		// Check if Key file exists
		_, err = os.Stat(keyFile)
		if err != nil {
			t.Errorf("Error while generating certificates to temp files file error - %s", err)
		}
		t.Cleanup(func() {
			_ = os.Remove(keyFile)
		})
	})

	t.Run("Testing the unhappy path when creating cert temp file", func(t *testing.T) {
		_, _, err := GenerateCertsToTempFile("/doesnotexist")
		if err == nil {
			t.Errorf("Expected error when generating a certificate with a bad directory path got nil")
		}
	})

	t.Run("Testing the unhappy path for insufficient permissions when creating temp file", func(t *testing.T) {
		if runtime.GOOS != "windows" && os.Geteuid() == 0 {
			// CAP_DAC_OVERRIDE can also bypass this in some rootless Linux containers.
			t.Skip("running as root bypasses directory permission checks")
		}
		dir, err := os.MkdirTemp("", "permission-test")
		if err != nil {
			t.Errorf("Error creating temp directory - %s", err)
		}
		t.Cleanup(func() {
			_ = os.RemoveAll(dir)
		})

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
