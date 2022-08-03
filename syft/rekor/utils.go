package rekor

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvloader"
)

var (
	//SbomPredicateType string = "google.com/sbom"
	GoogleSbomPredicateType string = "http://lumjjb/sbom-documents"
)

type digest struct {
	Sha256 string
}

type sbomEntry struct {
	Format string
	Digest digest
	Uri    string
}

type buildMetadata struct {
	ArtifactSourceRepo             string `json:"artifact-source-repo,omitempty"`
	ArtifactSourceRepoCommit       string `json:"artifact-source-repo-commit omitempty"`
	AttestationGeneratorRepo       string `json:"attestation-generator-repo,omitempty"`
	AttestationGeneratorRepoCommit string `json:"attestation-generator-repo-commit,omitempty"`
}

// Predicate type = "google.com/sbom"
type GoogleSbomPredicate struct {
	Sboms         []sbomEntry
	BuildMetadata buildMetadata `json:"build-metadata,omitempty"`
}

type InTotoAttestation struct {
	in_toto.StatementHeader
	Predicate GoogleSbomPredicate
}

type sbomWithDigest struct {
	sha1 string
	spdx *spdx.Document2_2
}

func pprintStruct(v any) string {
	//json, err := json.MarshalIndent(v, "", "\t")
	json, err := json.Marshal(v)
	if err != nil {
		fmt.Println(err)
	}
	return string(json)
}

func parsePEMCert(decodedCert string) (*x509.Certificate, error) {
	pem, _ := pem.Decode([]byte(decodedCert))
	if pem == nil {
		return nil, errors.New("certificate could not be decoded")
	}

	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing x509 certificate: %w", err)
	}
	return cert, nil
}

// parseEntry parses the entry body to a struct
//
// Precondition: entry is not nil
func parseEntry(entry *models.LogEntryAnon) (*models.IntotoV001Schema, error) {
	if entry.Body == nil {
		return nil, errors.New("entry body is nil")
	}
	bodyEncoded, ok := entry.Body.(string)
	if !ok {
		return nil, errors.New("attempted to parse entry body as string, but failed")
	}

	bodyDecoded, err := base64.StdEncoding.DecodeString(bodyEncoded)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding body: %w", err)
	}

	intoto := &models.Intoto{}
	err = intoto.UnmarshalBinary(bodyDecoded)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json entry body to intoto: %w", err)
	}

	if intoto.APIVersion == nil || *intoto.APIVersion != "0.0.1" {
		return nil, fmt.Errorf("intoto schema version %v not supported", *intoto.APIVersion)
	}

	specBytes, err := json.Marshal(intoto.Spec)
	if err != nil {
		return nil, fmt.Errorf("error marshaling intoto spec to json: %w", err)
	}

	intotoV001 := &models.IntotoV001Schema{}
	err = intotoV001.UnmarshalBinary(specBytes)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling intoto spec to intotoV001 schema: %w", err)
	}

	return intotoV001, nil
}

// parseAndValidateAttestation parses the entry's attestation to an attestation struct and validates the attestation predicate type
//
// Precondition: entry is not nil
func parseAndValidateAttestation(entry *models.LogEntryAnon) (*InTotoAttestation, error) {
	attAnon := entry.Attestation
	if attAnon == nil {
		return nil, errors.New("attestation is nil")
	}

	attDecoded := string(attAnon.Data)
	att := &InTotoAttestation{}
	err := json.Unmarshal([]byte(attDecoded), att)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling attestation to inTotoAttestation type: %w", err)
	}

	if att.PredicateType != GoogleSbomPredicateType {
		return nil, errors.New("entry could not be parsed as an sbom entry: in-toto predicate type is not recognized by Syft")
	}

	if att.Predicate.Sboms == nil {
		return nil, errors.New("entry could not be parsed as an sbom entry: attestation has no sboms")
	}

	return att, nil
}

func parseSbom(spdxBytes *[]byte) (*spdx.Document2_2, error) {
	// remove all SHA512 hashes because spdx/tools-golang does not support
	// PR fix is filed but not merged: https://github.com/spdx/tools-golang/pull/139

	regex, err := regexp.Compile("\n.*SHA512.*")
	if err != nil {
		return nil, fmt.Errorf("error compiling regex")
	}

	modifiedSpdxBytes := regex.ReplaceAll(*spdxBytes, nil)
	sbom, err := tvloader.Load2_2(bytes.NewReader(modifiedSpdxBytes))
	if err != nil {
		return nil, fmt.Errorf("error loading sbomBytes into spdx.Document2_2 type: %w", err)
	}

	return sbom, nil
}

// parseDigests takes a list of digests to an spdx.CheckSumAlgorithm : value map
func parseDigests(digests []file.Digest) map[spdx.ChecksumAlgorithm]string {
	hashes := make(map[spdx.ChecksumAlgorithm]string)
	for _, digest := range digests {
		alg := spdx.ChecksumAlgorithm(strings.ToUpper(digest.Algorithm))
		hashes[alg] = digest.Value
	}
	return hashes
}
