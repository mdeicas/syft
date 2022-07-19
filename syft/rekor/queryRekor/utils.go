package queryRekor

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/anchore/syft/internal/log"
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
		return nil, errors.New("certificate could not be found")
	}

	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		log.Debug("Error parsing x509 certificate")
		return nil, err
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
		log.Debug("Error base64 decoding body")
		return nil, err
	}

	var intoto *models.Intoto = new(models.Intoto)
	err = intoto.UnmarshalBinary(bodyDecoded)
	if err != nil {
		log.Debug("Error unmarshaling json entry body to intoto")
		return nil, err
	}

	// TODO: validate
	if *intoto.APIVersion != "0.0.1" {
		log.Debug("Error parsing rekor entry body")
		err := fmt.Sprintf("intoto schema version %v not supported", *intoto.APIVersion)
		return nil, errors.New(err)
	}

	specBytes, err := json.Marshal(intoto.Spec)
	if err != nil {
		log.Debug("error marshaling intoto spec to json")
		return nil, err
	}

	intotoV001 := new(models.IntotoV001Schema)
	err = intotoV001.UnmarshalBinary(specBytes)
	if err != nil {
		log.Debug("Error unmarshaling intoto spec to intotoV001 schema")
		return nil, err
	}

	return intotoV001, err
}

// parse the attestation and unmarshal json
func parseAttestation(entry *models.LogEntryAnon) (*inTotoAttestation, error) {

	attAnon := entry.Attestation
	if attAnon == nil {
		log.Debug("Error parsing attestation")
		return nil, errors.New("log entry attestation is nil")
	}

	// this decodes the base64 string
	attDecoded := string(attAnon.Data)

	att := new(inTotoAttestation)
	err := json.Unmarshal([]byte(attDecoded), att)
	if err != nil {
		log.Debug("Error parsing attestation")
		return nil, err
	}

	if att.PredicateType == "" {
		log.Debug("Error parsing attestation")
		return nil, errors.New("attestation predicate type was not found")
	}
	if att.PredicateType != "http://lumjjb/sbom-documents" {
		log.Debug("Error parsing attestation")
		return nil, errors.New("in-toto predicate type is not recognized by Syft")
	}

	// If pred type does not match up with lumjjbPredType, will there be an error??

	return att, nil

}

func parseSbom(spdxBytes []byte) (*spdx.Document2_2, error) {

	//remove all SHA512 hashes because spdx/tools-golang does not support
	// PR fix is filed but not merged

	regex, err := regexp.Compile("\n.*SHA512.*")
	if err != nil {
		log.Debug("Error decoding sbom to syft type")
		return nil, err
	}

	spdxBytes = regex.ReplaceAll(spdxBytes, nil)

	os.WriteFile("original-sbom.spdx", spdxBytes, 0644)

	sbom, err := tvloader.Load2_2(bytes.NewReader(spdxBytes))
	if err != nil {
		log.Debug("Error loading sbom bytes into spdx type")
		return nil, err
	}

	return sbom, nil
}

func getSbomData(sbom *spdx.Document2_2) string {
	return sbom.CreationInfo.DocumentNamespace
}
