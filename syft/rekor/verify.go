package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
)

/*

TODOs
	- verify attestation signature, not hash
	- TODOs in code comments
	- make more robust
		- gracefully handle missing fields, make more robust, etc. structs, after marshalling, could have missing fields.
		- deal with different attestation and different predicate types
*/

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

type hash struct {
	Algorithm string
	Value     string
}

type rekorBody struct {
	ApiVersion string
	Kind       string
	Spec       struct {
		Content struct {
			Hash        hash
			PayloadHash hash
		}
		PublicKey string
	}
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

// verify the inclusion proof
func verifyLogEntry(ctx context.Context, rekorClient *client.Rekor, entry *models.LogEntryAnon) error {
	err := cosign.VerifyTLogEntry(ctx, rekorClient, entry)
	if err != nil {
		fmt.Println("Error verifying Rekor entry")
		return err
	}
	fmt.Println("\nLog entry verified")
	return nil
}

// decode and parse certificate
func parseCert(encodedCert string) (*x509.Certificate, error) {

	decodedCert, err := base64.StdEncoding.DecodeString(encodedCert)
	if err != nil {
		fmt.Println("Error decoding base64 encoded certificate")
		return nil, err
	}

	pem, _ := pem.Decode(decodedCert)
	if pem == nil {
		return nil, errors.New("certificate could not be found")
	}

	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		fmt.Println("Error parsing x509 certificate")
		return nil, err
	}
	return cert, err
}

// decode and marshall log entry body
func parseEntryBody(ctx context.Context, rekorClient *client.Rekor, entry *models.LogEntryAnon) (*rekorBody, error) {

	bodyEncoded, ok := entry.Body.(string)
	if !ok {
		return nil, errors.New("attempted to parse entry body as string, but failed")
	}

	bodyDecoded, err := base64.StdEncoding.DecodeString(bodyEncoded)
	if err != nil {
		fmt.Println("Error base64 decoding body")
		return nil, err
	}

	var body *rekorBody = new(rekorBody)
	err = json.Unmarshal(bodyDecoded, body)
	if err != nil {
		fmt.Println("Error unmarshaling json entry body to struct")
		return nil, err
	}

	return body, err
}

// verify the certificate
func verifyCert(
	ctx context.Context, rekorClient *client.Rekor, cert *x509.Certificate) error {

	certCheckOpts.RekorClient = rekorClient
	// this code is now in sigstore, not cosign. Will break when cosign dependency updates
	certCheckOpts.RootCerts = fulcioroots.Get()
	certCheckOpts.IntermediateCerts = fulcioroots.GetIntermediates()

	_, err := cosign.ValidateAndUnpackCert(cert, certCheckOpts)
	if err != nil {
		fmt.Println("certificate could not be verified")
		return err
	}

	// would use the verifier returned by the previous call to verify the signature over the attestation

	fmt.Println("\nCertificate verified")
	return nil
}

// parse the attestation and unmarshal json
func parseAttestation(
	ctx context.Context, rekorClient *client.Rekor, entry *models.LogEntryAnon) (*inTotoAttestation, error) {

	attAnon := entry.Attestation
	if attAnon == nil {
		fmt.Println("Error parsing attestation")
		return nil, errors.New("log entry attestation is nil")
	}

	// this decodes the base64 string
	attDecoded := string(attAnon.Data)

	att := new(inTotoAttestation)
	err := json.Unmarshal([]byte(attDecoded), att)
	if err != nil {
		fmt.Println("Error parsing attestation")
		return nil, err
	}

	if att.PredicateType == "" {
		fmt.Println("Error parsing attestation")
		return nil, errors.New("attestation predicate type was not found")
	}
	if att.PredicateType != "http://lumjjb/sbom-documents" {
		fmt.Println("Error parsing attestation")
		return nil, errors.New("in-toto predicate type is not recognized by Syft")
	}

	// If pred type does not match up with lumjjbPredType, will there be an error??

	return att, nil

}

// return an error if the log entry timestamp is not within the certificate valid time range
func verifyEntryTimestamp(cert *x509.Certificate, entry *models.LogEntryAnon) error {
	time := time.Unix(*entry.IntegratedTime, 0)
	fmt.Println("\nLog entry timestamp verifed")
	return cosign.CheckExpiry(cert, time)
}

// verify the attestation hash equals the hash in the rekor entry body.
// *** This does NOT verify any signature.
// No error means that the attestation we have and the attestation referenced in rekor are equal, NOT that it is what the user intended to upload ***
func verifyAttestationHash(entry *models.LogEntryAnon, entryBody *rekorBody) error {
	// TODO: clean up decoding and add verification of signature

	decodedAttString := string(entry.Attestation.Data)

	alg := entryBody.Spec.Content.PayloadHash.Algorithm
	if alg != "sha256" {
		fmt.Println("Error verifying attestation has")
		return errors.New("hash algorithm is not sha256")
	}

	expectedHash := entryBody.Spec.Content.PayloadHash.Value

	attBytes := []byte(decodedAttString)
	hasher := sha256.New()
	hasher.Write(attBytes)
	hash := hasher.Sum(nil)

	decodedHash := fmt.Sprintf("%x", hash)

	if decodedHash != expectedHash {
		return errors.New("the attestation hash could not be verified")
	}

	fmt.Println("\nAttestation hash verified")
	return nil
}

func verifySbom(sbomBytes []byte, expectedHash string) error {

	return nil
}

func getAndVerifySbom(att *inTotoAttestation) ([]byte, error) {

	// TODO: what to do with multiple SBOMs
	uri := att.Predicate.Sboms[0].Uri

	var emptyReader io.Reader

	req, err := http.NewRequest("GET", uri, emptyReader)
	if err != nil {
		fmt.Println("Error creating SBOM request")
		return nil, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making SBOM request")
		return nil, err
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading SBOM response")
		return nil, err
	}

	fmt.Printf("\nSBOM (%v bytes) retrieved \n", len(bytes))

	expectedHash := att.Predicate.Sboms[0].Digest.Sha256

	hasher := sha256.New()
	hasher.Write(bytes)
	hash := hasher.Sum(nil)
	decodedHash := fmt.Sprintf("%x", hash)

	if decodedHash != expectedHash {
		fmt.Println("SBOM hash and expected hash from attestation do not match")
		return nil, err
	}

	fmt.Println("\nSBOM hash verified")

	return bytes, nil

}

// verify the log entry is in Rekor, the certificate is valid, the log entry timestamp is valid, and the attestation hash is correct
func verify(ctx context.Context, rekorClient *client.Rekor, entry *models.LogEntryAnon) error {

	err := verifyLogEntry(ctx, rekorClient, entry)
	if err != nil {
		return err
	}

	entryBody, err := parseEntryBody(ctx, rekorClient, entry)
	if err != nil {
		return err
	}

	cert, err := parseCert(entryBody.Spec.PublicKey)
	if err != nil {
		return err
	}

	err = verifyCert(ctx, rekorClient, cert)
	if err != nil {
		return err
	}

	err = verifyEntryTimestamp(cert, entry)
	if err != nil {
		return err
	}

	att, err := parseAttestation(ctx, rekorClient, entry)
	if err != nil {
		return err
	}

	err = verifyAttestationHash(entry, entryBody)
	if err != nil {
		return err
	}

	_, err = getAndVerifySbom(att)
	if err != nil {
		return err
	}

	if err == nil {
		fmt.Println("\nVerification complete")
	}
	return nil
}
