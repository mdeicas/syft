package main

import (
	"fmt"

	rekor "github.com/anchore/syft/syft/rekor/queryRekor"
)

func main() {

	//sha := "7556f2bf9edc3f1da13cf23715636573bab3e18883977eacd9667441618faf14"
	sha := "f2e59e0e82c6a1b2c18ceea1dcb739f680f50ad588759217fc564b6aa5234791"

	client, err := rekor.NewRekorClient()
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = rekor.GetAndVerifySbom(sha, client)
	if err != nil {
		fmt.Println(err)
		return
	}

}
