package testcerts

import (
	"os"
	"testing"
)

func TestGeneratingCerts(t *testing.T) {
	_, _, err := GenerateCerts()
	if err != nil {
		t.Errorf("Error while generating certificates - %s", err)
	}
}

func TestGeneratingCertsToFile(t *testing.T) {
	t.Run("Test the happy path", func(t *testing.T) {
		err := GenerateCertsToFile("/tmp/cert", "/tmp/key")
		if err != nil {
			t.Errorf("Error while generating certificates to files - %s", err)
		}

		// Check if Cert file exists
		_, err = os.Stat("/tmp/cert")
		if err != nil {
			t.Errorf("Error while generating certificates to files file error - %s", err)
		}
		_ = os.Remove("/tmp/cert")

		// Check if Key file exists
		_, err = os.Stat("/tmp/key")
		if err != nil {
			t.Errorf("Error while generating certificates to files file error - %s", err)
		}
		_ = os.Remove("/tmp/key")
	})

	t.Run("Testing the unhappy path for cert files", func(t *testing.T) {
		err := GenerateCertsToFile("/tmp/doesntexist/cert", "/tmp/key")
		if err == nil {
			t.Errorf("Expected error when generating a certificate with a bad path got nil")
		}
	})

	t.Run("Testing the unhappy path for key files", func(t *testing.T) {
		err := GenerateCertsToFile("/tmp/cert", "/tmp/doesntexist/key")
		if err == nil {
			t.Errorf("Expected error when generating a key with a bad path got nil")
		}
	})
}
