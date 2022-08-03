package rekor

import (
	"context"
	"crypto"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spdx/tools-golang/spdx"
)

// getSbom attempts to retrieve the SBOM from the URI.
//
// Precondition: att is not nil and client is not nil
func getSbom(att *InTotoAttestation, client *http.Client) (*[]byte, error) {
	if len(att.Predicate.Sboms) > 1 {
		log.Info("Attestation found on Rekor with multiple SBOMS, which is not currently supported. Proceeding with the first SBOM.")
	}
	uri := att.Predicate.Sboms[0].Uri

	resp, err := client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("error making http request: %w", err)
	}

	if resp == nil {
		return nil, errors.New("http response body is nil")
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading http response: %w", err)
	}

	return &bytes, nil
}

// getUuids returns the uuids of the Rekor entries associated with an sha hash
//
// Precondition: client is not nil
func getUuids(sha string, client *client.Rekor) ([]string, error) {
	query := &models.SearchIndex{Hash: sha}
	var params *index.SearchIndexParams = index.NewSearchIndexParams().WithQuery(query)

	res, err := client.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("result of Rekor search is nil")
	}
	return res.Payload, nil
}

// Precondition: Client is not nil
func getRekorEntry(uuid string, client *client.Rekor) (models.LogEntry, error) {
	params := entries.NewGetLogEntryByUUIDParams().WithEntryUUID(uuid)
	res, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("result of Rekor query is nil")
	}
	return res.Payload, nil
}

// Precondition: client and its fields are not nil
func getAndVerifySbomFromUuid(uuid string, client *Client) (*sbomWithDigest, error) {
	logEntry, err := getRekorEntry(uuid, client.rekorClient)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Rekor entry by uuid %v: \n\t\t%w", uuid, err)
	}
	if len(logEntry) == 0 {
		return nil, fmt.Errorf("retrieved Rekor entry has no logEntryAnons")
	}

	// logEntry is a map from uuids to logEntryAnons
	var logEntryAnon models.LogEntryAnon
	for k := range logEntry {
		logEntryAnon = logEntry[k]
	}

	logIndex := *logEntryAnon.LogIndex
	log.Debugf("Rekor entry was retrieved \n\t\tlogIndex: %v ", logIndex)

	ctx := context.Background()
	err = verify(ctx, client.rekorClient, &logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("rekor log entry %v could not be verified: \n\t\t%w", logIndex, err)
	}

	log.Debugf("Verification of Rekor entry %v complete", logIndex)

	att, err := parseAndValidateAttestation(&logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("error parsing or validating rekor entry %v attestation: \n\t\t%w", logIndex, err)
	}

	sbomBytes, err := getSbom(att, client.httpClient)
	if err != nil {
		return nil, fmt.Errorf("error retrieving sbom from Rekor entry %v: \n\t\t%w", logIndex, err)
	}

	log.Debugf("SBOM (%v bytes) retrieved", len(*sbomBytes))

	err = verifySbomHash(att, sbomBytes)
	if err != nil {
		return nil, fmt.Errorf("could not verify retrieved sbom (from Rekor entry %v): \n\t\t%w", logIndex, err)
	}

	sbomSha1 := sha1.Sum(*sbomBytes)
	decodedHash := fmt.Sprintf("%x", sbomSha1)

	sbom, err := parseSbom(sbomBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing sbom from Rekor entry %v: %w", logIndex, err)
	}

	sbomWrapped := &sbomWithDigest{
		sha1: decodedHash,
		spdx: sbom,
	}

	return sbomWrapped, nil
}

// GetAndVerifySboms retrieves Rekor entries associated with an sha256 hash and verifies the entries and the sboms
//
// Precondition: client and its fields are not nil
func getAndVerifySbomsFromHash(sha string, client *Client) ([]*sbomWithDigest, error) {
	uuids, err := getUuids(sha, client.rekorClient)
	if err != nil {
		return nil, fmt.Errorf("error getting uuids on Rekor associated with hash \"%v\": %w", sha, err)
	}

	var sboms []*sbomWithDigest
	for _, uuid := range uuids {
		sbom, err := getAndVerifySbomFromUuid(uuid, client)
		if err != nil {
			log.Debug(err)
		} else {
			sboms = append(sboms, sbom)
		}
	}

	return sboms, nil
}

func getAndVerifySbomsFromResolver(resolver source.FileResolver, location source.Location, client *Client) ([]*sbomWithDigest, error) {
	closer, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("error getting reader from resolver: %w", err)
	}

	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256}
	digests, err := file.DigestsFromFile(closer, hashes)
	if err != nil {
		return nil, fmt.Errorf("error generating digests from file %v: %w", location.RealPath, err)
	}

	digestMap := parseDigests(digests)
	sha1, sha256 := digestMap[spdx.SHA1], digestMap[spdx.SHA256]

	log.Debugf("Rekor is being queried for \n\t\tLocation: %v \n\t\tSHA1: %v \n\t\tSHA256: %v", location.RealPath, sha1, sha256)

	sboms, err := getAndVerifySbomsFromHash(sha256, client)
	if err != nil {
		return nil, fmt.Errorf("error searching rekor in location %v: %w", location.RealPath, err)
	}

	return sboms, nil
}
