package queryRekor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/anchore/syft/internal/log"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spdx/tools-golang/spdx"
)

const (
	DefaultRekorAddr = "https://rekor.sigstore.dev"
)

// getSbom attempts to retrieve the SBOM from the URI.
// precondition of not nil attestation currently not enforced anywhere
func getSbom(att *InTotoAttestation) (*[]byte, error) {
	if len(att.Predicate.Sboms) > 1 {
		log.Info("Attestation found on Rekor with multiple SBOMS, which is not currently supported. Proceeding with the first SBOM.")
	}
	uri := att.Predicate.Sboms[0].Uri

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %w", err)
	}

	client := http.Client{}
	resp, err := client.Do(req)
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

func NewRekorClient() (*client.Rekor, error) {
	client, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		log.Debug("Error creating Rekor client")
		return nil, err
	}
	return client, nil
}

// Precondition: client is not nil
func getAndVerifySbomFromUuid(uuid string, client *client.Rekor) (*spdx.Document2_2, error) {
	logEntry, err := getRekorEntry(uuid, client)
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
	err = Verify(ctx, client, &logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("rekor log entry %v could not be verified: \n\t\t%w", logIndex, err)
	}

	log.Debugf("Verification of Rekor entry %v complete", logIndex)

	att, err := parseAndValidateAttestation(&logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("error parsing rekor entry %v attestation: \n\t\t%w", logIndex, err)
	}

	sbomBytes, err := getSbom(att)
	if err != nil {
		return nil, fmt.Errorf("error retrieving sbom from Rekor entry %v: \n\t\t%w", logIndex, err)
	}

	log.Debugf("SBOM (%v bytes) retrieved", len(*sbomBytes))

	err = VerifySbomHash(att, sbomBytes)
	if err != nil {
		return nil, fmt.Errorf("error verifying sbom hash from Rekor entry %v: \n\t\t%w", logIndex, err)
	}

	sbom, err := parseSbom(sbomBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing sbom from Rekor entry %v: %w", logIndex, err)
	}

	return sbom, nil
}

// GetAndVerifySboms retrieves Rekor entries associated with an sha256 hash and verifies the entries and the sboms
//
// Precondition: client is not nil
func GetAndVerifySboms(sha string, client *client.Rekor) ([]*spdx.Document2_2, error) {
	uuids, err := getUuids(sha, client)
	if err != nil {
		return nil, fmt.Errorf("error getting uuids on Rekor associated with hash %v: %w", sha, err)
	}

	var sboms []*spdx.Document2_2
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
