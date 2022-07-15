package queryRekor

import (
	"fmt"
	"io"
	"net/http"

	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
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

func GetSbom(att *inTotoAttestation) ([]byte, error) {
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
	return bytes, nil
}

// retrieve Rekor entries associated with an sha hash and return their UUIDS
func GetUuids(sha string, client *client.Rekor) ([]string, error) {
	// TODO: deal with no entries being returned
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

// retrieve a Rekor entry by its UUID
func GetRekorEntry(uuid string, client *client.Rekor) (models.LogEntry, error) {
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

func NewRekorClient() (*client.Rekor, error) {
	client, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		fmt.Println("Error creating Rekor client")
		return nil, err
	}
	return client, nil
}
