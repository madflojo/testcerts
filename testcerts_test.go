package testcerts

import (
	"testing"
)

func TestGeneratingCerts(t *testing.T) {
	cert, key, err := GenerateCerts()
	if err != nil {
		t.Errorf("Error while generating certificates - %s", err)
	}
	t.Logf("Cert - %s", cert)
	t.Logf("Key - %s", key)
}
