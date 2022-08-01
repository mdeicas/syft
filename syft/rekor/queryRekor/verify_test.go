package queryRekor

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

func Test_verifyAttestationHash(t *testing.T) {

	att1, err := os.ReadFile("test-fixtures/valid-attestation.txt")
	if err != nil {
		t.Fatal("reading test data")
	}

	intoto1 := &models.IntotoV001Schema{
		Content: &models.IntotoV001SchemaContent{
			PayloadHash: &models.IntotoV001SchemaContentPayloadHash{
				Algorithm: stringPointer("sha256"),
				Value:     stringPointer("323ae14b2df5cd94f9fe832b25a9be14f5cfd6ce4c76edd98694b8e20d51e963"),
			},
		},
	}

	intoto2 := &models.IntotoV001Schema{
		Content: &models.IntotoV001SchemaContent{
			PayloadHash: &models.IntotoV001SchemaContentPayloadHash{
				Algorithm: stringPointer("sha256"),
				Value:     stringPointer("323ae14b2df5cd94f9fe832b25a9be14f5cfd6ce4c76edd98694b8e20d51e964"),
			},
		},
	}

	tests := []struct {
		name             string
		inputAttestation string
		inputIntoto      *models.IntotoV001Schema
		expectedErr      string
	}{
		{
			name:             "hashes match up",
			inputAttestation: string(att1),
			inputIntoto:      intoto1,
		},
		{
			name:             "hashes do not match up",
			inputAttestation: string(att1),
			inputIntoto:      intoto2,
			expectedErr:      "does not equal",
		},
		{
			name:             "empty attestation string",
			inputAttestation: "",
			inputIntoto:      intoto1,
			expectedErr:      "does not equal",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifyAttestationHash(test.inputAttestation, test.inputIntoto)
			if test.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, test.expectedErr)
			}

		})
	}

}

func Test_verifyEntryTimestamp(t *testing.T) {

	certBytes, err := os.ReadFile("test-fixtures/valid-cert.der")
	if err != nil {
		t.Fatal("reading test data")
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal("reading test data")
	}

	tests := []struct {
		name        string
		cert        *x509.Certificate
		entry       models.LogEntryAnon
		errExpected bool
	}{
		{
			name:        "valid timestamp",
			cert:        cert,
			entry:       models.LogEntryAnon{IntegratedTime: int64Pointer(1656443102)},
			errExpected: false,
		},
		{
			name:        "invalid timestamp",
			cert:        cert,
			entry:       models.LogEntryAnon{IntegratedTime: int64Pointer(1656444102)},
			errExpected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifyEntryTimestamp(test.cert, &test.entry)
			if !test.errExpected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}

}
