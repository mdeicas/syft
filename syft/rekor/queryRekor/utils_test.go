package queryRekor

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

func int64Pointer(i int64) *int64 {
	return &i
}

func stringPointer(s string) *string {
	return &s
}

// does not modify s, only changes type
func b64StringToStrfmt(s string) (strfmt.Base64, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return strfmt.Base64(decoded), nil

}

func Test_parsePEMCert(t *testing.T) {

	cert, err := os.ReadFile("test-fixtures/valid-cert.pem")
	if err != nil {
		t.Fatal("reading test data")
	}

	// we need DER encoded cert to pass in to x509.ParseCertificate
	certBytes, err := os.ReadFile("test-fixtures/valid-cert.der")
	if err != nil {
		t.Fatal("reading test data")
	}

	tests := []struct {
		name            string
		inputCertString string
		certBytes       []byte
	}{
		{
			name:            "valid cert",
			inputCertString: string(cert),
			certBytes:       certBytes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			output, err := parsePEMCert(test.inputCertString)
			assert.NoError(t, err)

			expectedOutput, err := x509.ParseCertificate(certBytes)
			assert.NoError(t, err)
			assert.Equal(t, expectedOutput, output)
		})
	}
}

func Test_parseEntry(t *testing.T) {

	validEntryBody, err := os.ReadFile("test-fixtures/valid-entry-body.txt")
	if err != nil {
		t.Fatal("reading test data")
	}

	publicKeyString, err := os.ReadFile("test-fixtures/encoded-cert.txt")
	if err != nil {
		t.Fatal("reading test data")
	}
	// publicKeyString is already base64 encoded but we need a strfmt.Base64 value
	publicKeyStrfmt, err := b64StringToStrfmt(string(publicKeyString))
	if err != nil {
		t.Fatal("reading test data")
	}

	tests := []struct {
		name           string
		entry          *models.LogEntryAnon
		expectedOutput *models.IntotoV001Schema
	}{
		{
			name: "valid input",
			entry: &models.LogEntryAnon{
				Body:           string(validEntryBody),
				IntegratedTime: int64Pointer(1656443102),
				LogID:          stringPointer("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
				LogIndex:       int64Pointer(2790629),
			},
			expectedOutput: &models.IntotoV001Schema{
				Content: &models.IntotoV001SchemaContent{
					Hash: &models.IntotoV001SchemaContentHash{
						Algorithm: stringPointer("sha256"),
						Value:     stringPointer("6e692df76cd12ecde65c4421b4dd3bbd8865ca45f2b6f7b83df8eafa1f08bf22"),
					},
					PayloadHash: &models.IntotoV001SchemaContentPayloadHash{
						Algorithm: stringPointer("sha256"),
						Value:     stringPointer("323ae14b2df5cd94f9fe832b25a9be14f5cfd6ce4c76edd98694b8e20d51e963"),
					},
				},
				PublicKey: &publicKeyStrfmt,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := parseEntry(test.entry)
			assert.NoError(t, err)
			assert.Equalf(t, test.expectedOutput, output, "actual: \n%v\n\n\nexpected:\n%v", pprintStruct(output), pprintStruct(test.expectedOutput))
		})
	}
}
