package queryRekor

import (
	"context"
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

func getSbom(att *inTotoAttestation) ([]byte, error) {
	// TODO: deal with multiple sboms
	uri := att.Predicate.Sboms[0].Uri

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Debug("Error creating SBOM request")
		return nil, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("Error making SBOM request")
		return nil, err
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debug("Error reading SBOM response")
		return nil, err
	}

	log.Debugf("SBOM (%v bytes) retrieved", len(bytes))
	return bytes, nil
}

// retrieve Rekor entries associated with an sha hash and return their UUIDS
func getUuids(sha string, client *client.Rekor) ([]string, error) {
	// TODO: deal with no entries being returned
	// set up query
	query := &models.SearchIndex{Hash: sha}
	var params *index.SearchIndexParams = index.NewSearchIndexParams().WithQuery(query)

	res, err := client.Index.SearchIndex(params)
	if err != nil {
		log.Debug("error searching rekor by hash")
		return nil, err
	}
	payload := (*res).Payload
	return payload, nil
}

// retrieve a Rekor entry by its UUID
func getRekorEntry(uuid string, client *client.Rekor) (models.LogEntry, error) {
	// TODO: models.LogEntry is a map from strings to LogEntryAnon. In what case would there by multiple entries returned?

	params := entries.NewGetLogEntryByUUIDParams().WithEntryUUID(uuid)
	res, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		log.Debug("error getting rekor entry by uuid")
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

	att, err := parseAttestation(&logEntry)
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
