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

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
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

type spdxSbomWithMetadata struct {
	sbom        spdx.Document2_2
	packageName string
	namespace   string // i.e.  uri
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

// parse the attestation and validate that it fits the inTotoAttestation type
func parseAndValidateAttestations(entries []models.LogEntryAnon) ([]inTotoAttestation, error) {

	var atts []inTotoAttestation
	for _, entry := range entries {
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

		// validation the entry is an sbom entry is done by validating attestation struct
		if att.PredicateType == "" {
			log.Debugf("Rekor entry %v could not be parsed as an sbom entry", *entry.LogIndex)
			continue
		}
		if att.PredicateType != "http://lumjjb/sbom-documents" {
			log.Debugf("Rekor entry %v could not be parsed as an sbom entry", *entry.LogIndex)
			continue
		}
		if att.Predicate.Sboms == nil {
			log.Debugf("Rekor entry %v could not be parsed as an sbom entry", *entry.LogIndex)
			continue
		}

		atts = append(atts, *att)
	}

	return atts, nil
}

func parseSboms(spdxBytesList map[*inTotoAttestation][]byte) (map[*inTotoAttestation]spdx.Document2_2, error) {

	sboms := make(map[*inTotoAttestation]spdx.Document2_2)
	for att, spdxBytes := range spdxBytesList {
		//remove all SHA512 hashes because spdx/tools-golang does not support
		// PR fix is filed but not merged

		regex, err := regexp.Compile("\n.*SHA512.*")
		if err != nil {
			log.Debug("Error decoding sbom to syft type")
			return nil, err
		}

		spdxBytes = regex.ReplaceAll(spdxBytes, nil)
		sbom, err := tvloader.Load2_2(bytes.NewReader(spdxBytes))
		if err != nil {
			log.Debug("Error loading sbom bytes into spdx type")
			return nil, err
		}

		sboms[att] = *sbom
	}

	return sboms, nil
}

func formatSbomPackageName(att *inTotoAttestation) string {
	repo := att.Predicate.BuildMetadata.ArtifactSourceRepo
	commit := att.Predicate.BuildMetadata.ArtifactSourceRepoCommit
	if repo == "" {
		return ""
	}
	if commit == "" {
		return repo
	}
	return fmt.Sprintf("%v@%v", repo, commit)
}

func joinSbomsWithMetadata(sboms map[*inTotoAttestation]spdx.Document2_2) []spdxSbomWithMetadata {

	var sbomsWithMetadata []spdxSbomWithMetadata
	for att, sbom := range sboms {

		packageName := formatSbomPackageName(att)
		namespace := sbom.CreationInfo.DocumentNamespace

		if packageName == "" {
			packageName = namespace
		}
		if namespace == "" {
			log.Debugf("sbom from rekor entry is malformed (does not have a namespace)")
		} else {
			sbomsWithMetadata = append(sbomsWithMetadata, spdxSbomWithMetadata{sbom: sbom, namespace: namespace, packageName: packageName})
		}
	}

	return sbomsWithMetadata
}

// map a list of digests to a (sha1, sha256) tuple
func parseDigests(digests []file.Digest) (string, string) {
	var sha1 string
	var sha256 string
	if digests[0].Algorithm == "sha1" && digests[1].Algorithm == "sha256" {
		sha1 = digests[0].Value
		sha256 = digests[1].Value
	} else if digests[0].Algorithm == "sha256" && digests[1].Algorithm == "sha1" {
		sha256 = digests[0].Value
		sha1 = digests[1].Value
	} else {
		log.Debug("Unexpected digests")
		return "", ""
	}

	return sha1, sha256
}
