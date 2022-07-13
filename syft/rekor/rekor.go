package main

import (
	"fmt"

	"encoding/json"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
)

/*
TODOS
	- search through returned uuids to use only SBOM entries
	- make more robust (e.g. no entries found)
*/

const (
	DefaultRekorAddr = "https://rekor.sigstore.dev"
)

func pprintStruct(v any) {
	json, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(json))
}

// TODO: deal with no entries being returned
func getUuids(sha string, client *client.Rekor) ([]string, error) {

	// set up query
	query := &models.SearchIndex{Hash: sha}
	var params *index.SearchIndexParams = index.NewSearchIndexParams().WithQuery(query)

	res, err := client.Index.SearchIndex(params)
	if err != nil {
		fmt.Println("error searching rekor by hash")
		return nil, err
	}
	payload := (*res).Payload
	return payload, nil
}

func getRekorEntry(uuid string, client *client.Rekor) (models.LogEntry, error) {
	// TODO: models.LogEntry is a map from strings to LogEntryAnon. In what case would there by multiple entries returned?

	fmt.Printf("Querying rekor for %v \n", uuid)
	params := entries.NewGetLogEntryByUUIDParams().WithEntryUUID(uuid)
	res, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		fmt.Println("error getting rekor entry by uuid")
		return nil, err
	}

	var payload models.LogEntry = res.Payload
	return payload, nil

}
