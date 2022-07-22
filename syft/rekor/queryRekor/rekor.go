package queryRekor

import (
	"context"
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

type entryData struct {
	entry       models.LogEntryAnon
	entryBody   models.IntotoV001Schema
	att         inTotoAttestation
	sbom        []byte
	namespace   string
	packageName string
}

func getSbom(att *inTotoAttestation) ([]byte, error) {
	// TODO: deal with multiple sboms
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

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading http response: %w", err)
	}

	return bytes, nil
}

// retrieve Rekor entries associated with an sha hash and return their UUIDS
func getUuids(sha string, client *client.Rekor) ([]string, error) {

	query := &models.SearchIndex{Hash: sha}
	var params *index.SearchIndexParams = index.NewSearchIndexParams().WithQuery(query)

	res, err := client.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	payload := res.Payload
	return payload, nil
}

// retrieve a Rekor entry by its UUID
func getRekorEntry(uuid string, client *client.Rekor) (models.LogEntry, error) {

	params := entries.NewGetLogEntryByUUIDParams().WithEntryUUID(uuid)
	res, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	var payload models.LogEntry = res.Payload
	return payload, nil

}

func NewRekorClient() (*client.Rekor, error) {
	client, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		log.Debug("Error creating Rekor client")
		return nil, err
	}
	return client, nil
}

func GetAndVerifySbom3(uuid string, client *client.Rekor) (*spdx.Document2_2, error) {

	logEntry, err := getRekorEntry(uuid, client)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Rekor entry by uuid %v: \n\t\t%w", uuid, err)
	}

	// logEntry is a map from strings to logEntryAnons
	var logEntryAnon models.LogEntryAnon
	for k, _ := range logEntry {
		logEntryAnon = logEntry[k]
	}

	logIndex := logEntryAnon.LogIndex
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

	log.Debugf("SBOM (%v bytes) retrieved", len(sbomBytes))

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

func GetAndVerifySbom(sha string, client *client.Rekor) (*spdx.Document2_2, error) {

	uuids, err := getUuids(sha, client)
	if err != nil {
		return nil, err
	}

	if len(uuids) == 0 {
		return nil, nil
	}

	logEntries, err := getRekorEntry(uuids[0], client)
	if err != nil {
		return nil, err
	}

	// TODO: only get SBOM entries
	var logEntry models.LogEntryAnon
	for k := range logEntries {
		logEntry = logEntries[k]
	}

	log.Infof("Rekor entry was retrieved \n\t\tlogIndex: %v ", logEntry.LogIndex)

	ctx := context.Background()

	err = Verify(ctx, client, &logEntry)
	if err != nil {
		return nil, nil
	}

	att, err := parseAndValidateAttestation(&logEntry)
	if err != nil {
		log.Debug("no error should occur here but one did")
		log.Debug("err")
		return nil, nil
	}

	sbomBytes, err := getSbom(att)
	if err != nil {
		return nil, nil
	}

	err = VerifySbomHash(att, sbomBytes)
	if err != nil {
		return nil, nil
	}

	sbom, err := parseSbom(sbomBytes)
	if err != nil {
		log.Debug(err)
		return nil, err
	}

	return sbom, nil

}
