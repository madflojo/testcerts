package testcerts

import (
	"os"
	"path/filepath"
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
