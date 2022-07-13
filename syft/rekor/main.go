package main

import (
	"context"
	"fmt"

	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func main() {

	//sha := "7556f2bf9edc3f1da13cf23715636573bab3e18883977eacd9667441618faf14"
	sha := "f2e59e0e82c6a1b2c18ceea1dcb739f680f50ad588759217fc564b6aa5234791"

	client, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		fmt.Println(err)
	}

	uuids, err := getUuids(sha, client)
	if err != nil {
		fmt.Println("error", err)
		return
	}

	// for now, take the first uuid returned
	logEntries, err := getRekorEntry(uuids[0], client)
	if err != nil {
		fmt.Println(err)
		return
	}

	// there can be multiple entries, not all of them SBOM
	var logEntry models.LogEntryAnon
	for k := range logEntries {
		logEntry = logEntries[k]
	}

	ctx := context.Background()

	err = verify(ctx, client, &logEntry)
	fmt.Println(err)

}
