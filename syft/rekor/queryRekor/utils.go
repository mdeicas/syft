package queryRekor

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvloader"
)

var trustedCertIdentities = []cosign.Identity{
	{Subject: "mdeicas@google.com", Issuer: "sigstore.dev"},
	{Subject: "mdeicas@google.com", Issuer: "sigstore"},
}

// TODO: identities list is not working. Needs to work to verify github action runs because they don't have an email field
var certCheckOpts = &cosign.CheckOpts{
	//Identities: trustedCertIdentities,
	//CertEmail: "mdeicas@google.com",

	// Why is there an option to prove sigVerifier?
	// addresses after SAN. what is this and should we check it

}

type digest struct {
	Sha256 string
}

type subject struct {
	Name   string
	Digest digest
}

type lumjjbSbomType struct {
	Format string
	Digest digest
	Uri    string
}

type buildMetadata struct {
	ArtifactSourceRepo             string `json:"artifact-source-repo"`
	ArtifactSourceRepoCommit       string `json:"artifact-source-repo-commit"`
	AttestationGeneratorRepo       string `json:"attestation-generator-repo"`
	AttestationGeneratorRepoCommit string `json:"attestation-generator-repo-commit"`
}

type lumjjbPredType struct {
	Sboms         []lumjjbSbomType
	BuildMetadata buildMetadata `json:"build-metadata"`
}

type inTotoAttestation struct {
	AttType       string `json:"_type"`
	PredicateType string
	Subject       []subject
	Predicate     lumjjbPredType
}

func pprintCert(cert *x509.Certificate) {

	s := fmt.Sprint(
		"\n*** certificate *** \n",
		"subject:", cert.Subject.CommonName,
		"\nsubject alternative name: email: ", cert.EmailAddresses,
		"\nissuer: ", cert.Issuer.CommonName,
		"\nnotBefore: ", cert.NotBefore.String(),
		"\nnotAfter: ", cert.NotAfter.String(),
		"\n*** certificate *** \n\n",
	)
	fmt.Println(s)
}

func pprintStruct(v any) {
	json, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(json))
}

// decode and parse certificate
func parseCert(decodedCert string) (*x509.Certificate, error) {

	pem, _ := pem.Decode([]byte(decodedCert))
	if pem == nil {
		return nil, errors.New("certificate could not be decoded")
	}

	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing x509 certificate: %w", err)
	}
	return cert, err
}

// decode and marshall log entry body
func parseEntry(entry *models.LogEntryAnon) (*models.IntotoV001Schema, error) {

	bodyEncoded, ok := entry.Body.(string)
	if !ok {
		return nil, errors.New("attempted to parse entry body as string, but failed")
	}

	bodyDecoded, err := base64.StdEncoding.DecodeString(bodyEncoded)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding body: %w", err)
	}

	var intoto *models.Intoto = new(models.Intoto)
	err = intoto.UnmarshalBinary(bodyDecoded)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json entry body to intoto: %w", err)
	}

	if *intoto.APIVersion != "0.0.1" {
		return nil, fmt.Errorf("intoto schema version %v not supported", *intoto.APIVersion)
	}

	specBytes, err := json.Marshal(intoto.Spec)
	if err != nil {
		return nil, fmt.Errorf("error marshaling intoto spec to json: %w", err)
	}

	intotoV001 := new(models.IntotoV001Schema)
	err = intotoV001.UnmarshalBinary(specBytes)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling intoto spec to intotoV001 schema: %w", err)
	}

	return intotoV001, nil
}

// parse the attestation and unmarshal json
func parseAndValidateAttestation(entry *models.LogEntryAnon) (*inTotoAttestation, error) {

	attAnon := entry.Attestation
	if attAnon == nil {
		return nil, errors.New("attestation is nil")
	}

	// this decodes the base64 string
	attDecoded := string(attAnon.Data)

	att := new(inTotoAttestation)
	err := json.Unmarshal([]byte(attDecoded), att)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling attestation to inTotoAttestation type", err)
	}

	if att.PredicateType == "" {
		return nil, errors.New("entry could not be parsed as an sbom entry: predicate type is nil")
	}
	if att.PredicateType != "http://lumjjb/sbom-documents" {
		return nil, errors.New("entry could not be parsed as an sbom entry: in-toto predicate type is not recognized by Syft")
	}

	if att.Predicate.Sboms == nil {
		return nil, errors.New("entry could not be parsed as an sbom entry: attestation has no sboms")
	}

	return att, nil

}

func parseSbom(spdxBytes []byte) (*spdx.Document2_2, error) {

	//remove all SHA512 hashes because spdx/tools-golang does not support
	// PR fix is filed but not merged

	regex, err := regexp.Compile("\n.*SHA512.*")
	if err != nil {
		return nil, fmt.Errorf("error compiling regex")
	}

	spdxBytes = regex.ReplaceAll(spdxBytes, nil)
	sbom, err := tvloader.Load2_2(bytes.NewReader(spdxBytes))
	if err != nil {
		return nil, fmt.Errorf("error loading sbomBytes into spdx.Document2_2 type: %w", err)
	}

	return sbom, nil
}

func getSbomData(sbom *spdx.Document2_2) string {
	return sbom.CreationInfo.DocumentNamespace
}
