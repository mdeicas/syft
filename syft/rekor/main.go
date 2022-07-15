package main

import (
	"context"
	"fmt"

	rekor "github.com/anchore/syft/syft/rekor/queryRekor"
	"github.com/sigstore/rekor/pkg/generated/models"
)

/*
TODOs
	- integrate into Syft
	- how to output obtained SBOM
	- fix TODOs
*/

func main() {

	//sha := "7556f2bf9edc3f1da13cf23715636573bab3e18883977eacd9667441618faf14"
	sha := "f2e59e0e82c6a1b2c18ceea1dcb739f680f50ad588759217fc564b6aa5234791"

	client, err := rekor.NewRekorClient()
	if err != nil {
		fmt.Println(err)
		return
	}

	uuids, err := rekor.GetUuids(sha, client)
	if err != nil {
		fmt.Println("error", err)
		return
	}

	// for now, take the first uuid returned
	logEntries, err := rekor.GetRekorEntry(uuids[0], client)
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

	err = rekor.Verify(ctx, client, &logEntry)
	if err != nil {
		fmt.Println(err)
		return
	}

	att, err := rekor.ParseAttestation(&logEntry)
	if err != nil {
		fmt.Println("no error should occur here but one did")
		fmt.Println("err")
		return
	}

	sbomBytes, err := rekor.GetSbom(att)
	if err != nil {
		return
	}

	err = rekor.VerifySbomHash(att, sbomBytes)
	if err != nil {
		return
	}

	_, err = rekor.ParseSbom(sbomBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

}
