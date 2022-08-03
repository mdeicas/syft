package rekor

import (
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/stretchr/testify/assert"
)

func Test_verifyCert(t *testing.T) {
	tests := []struct {
		name        string
		certFile    string
		expectedErr string
	}{
		{
			name:        "self signed cert",
			certFile:    "test-fixtures/test-certs/self-signed-cert.pem",
			expectedErr: "x509: certificate signed by unknown authority",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certBytes, err := os.ReadFile(test.certFile)
			assert.NoError(t, err, "reading test data")
			cert, err := parsePEMCert(string(certBytes))
			assert.NoError(t, err, "parsing certificate")

			rekorClient := &client.Rekor{}

			err = verifyCert(rekorClient, cert)
			assert.ErrorContains(t, err, test.expectedErr)
		})
	}
}

func Test_parsePEMCert(t *testing.T) {
	tests := []struct {
		name          string
		inputCertFile string
		expectedErr   string
	}{
		{
			name:          "badly formatted cert",
			inputCertFile: "test-fixtures/test-certs/invalid-cert-format.txt",
			expectedErr:   "certificate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certBytes, err := os.ReadFile(test.inputCertFile)
			assert.NoError(t, err, "reading test data")

			_, err = parsePEMCert(string(certBytes))
			assert.Error(t, err)
		})
	}
}
