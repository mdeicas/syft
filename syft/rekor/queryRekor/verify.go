package queryRekor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
)

/*

TODOs
	- TODOs in code comments
	- make more robust
		- gracefully handle missing fields, make more robust, etc. structs, after marshalling, could have missing fields.
		- deal with different attestation and different predicate types
*/

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

// verify the certificate
func verifyCert(rekorClient *client.Rekor, cert *x509.Certificate) error {

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

// return an error if the log entry timestamp is not within the certificate valid time range
func verifyEntryTimestamp(cert *x509.Certificate, entry *models.LogEntryAnon) error {
	time := time.Unix(*entry.IntegratedTime, 0)
	fmt.Println("\nLog entry timestamp verifed")
	return cosign.CheckExpiry(cert, time)
}

// verify the attestation hash equals the hash in the rekor entry body.
// *** This does NOT verify any signature.
// No error means that the attestation we have and the attestation referenced in rekor are equal, NOT that it is what the user intended to upload ***
func verifyAttestationHash(encounteredAttestation string, intotoV001 *models.IntotoV001Schema) error {

	// TODO: clean up decoding and add verification of signature

	attBytes := []byte(encounteredAttestation)
	hasher := sha256.New()
	hasher.Write(attBytes)
	hash := hasher.Sum(nil)
	encounteredHash := fmt.Sprintf("%x", hash)

	alg := *intotoV001.Content.Hash.Algorithm
	if alg != "sha256" {
		fmt.Println("Error verifying attestation has")
		return errors.New("hash algorithm is not sha256")
	}
	expectedHash := *intotoV001.Content.PayloadHash.Value

	if encounteredHash != expectedHash {
		return errors.New("the attestation hash could not be verified")
	}

	fmt.Println("\nAttestation hash verified")
	return nil
}

// verify the log entry is in Rekor, the certificate is valid, the log entry timestamp is valid, and the attestation hash is correct
func Verify(ctx context.Context, rekorClient *client.Rekor, entry *models.LogEntryAnon) error {

	err := verifyLogEntry(ctx, rekorClient, entry)
	if err != nil {
		return err
	}

	intotoV001, err := parseEntry(entry)
	if err != nil {
		return err
	}

	cert, err := parseCert(string(*intotoV001.PublicKey))
	if err != nil {
		return err
	}

	err = verifyCert(rekorClient, cert)
	if err != nil {
		return err
	}

	err = verifyEntryTimestamp(cert, entry)
	if err != nil {
		return err
	}

	err = verifyAttestationHash(string(entry.Attestation.Data), intotoV001)
	if err != nil {
		return err
	}

	if err == nil {
		fmt.Println("\nVerification complete")
	}

	return nil
}

func VerifySbomHash(att *inTotoAttestation, sbomBytes []byte) error {

	expectedHash := att.Predicate.Sboms[0].Digest.Sha256

	hasher := sha256.New()
	hasher.Write(sbomBytes)
	hash := hasher.Sum(nil)
	decodedHash := fmt.Sprintf("%x", hash)

	if decodedHash != expectedHash {
		fmt.Println("Error verifying Sbom hash")
		return errors.New("SBOM hash and expected hash from attestation do not match")
	}

	fmt.Println("\nSBOM hash verified")

	return nil

}
