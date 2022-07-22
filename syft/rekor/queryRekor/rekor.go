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
)

const (
	DefaultRekorAddr = "https://rekor.sigstore.dev"
)

func getSboms(atts []inTotoAttestation) map[*inTotoAttestation][]byte {

	sbomsBytes := make(map[*inTotoAttestation][]byte)
	for _, att := range atts {
		if len(att.Predicate.Sboms) > 1 {
			log.Info("Attestation found on Rekor with multiple sboms, which is not currently supported")
		}
		uri := att.Predicate.Sboms[0].Uri

		req, err := http.NewRequest("GET", uri, nil)
		if err != nil {
			log.Debug("Error creating SBOM request: ", err)
			continue
		}

		client := http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Debug("Error making SBOM request: ", err)
			continue
		}

		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Debug("Error reading SBOM response: ", err)
			continue
		}

		log.Debugf("SBOM (%v bytes) retrieved", len(bytes))
		sbomsBytes[&att] = bytes
	}

	return sbomsBytes
}

// retrieve Rekor entries associated with an sha hash and return their UUIDS
func getUuids(sha string, client *client.Rekor) ([]string, error) {
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

// retrieve rekor entries from a list of uuids
func getRekorEntries(uuids []string, client *client.Rekor) ([]models.LogEntryAnon, error) {
	var rekorEntries []models.LogEntryAnon
	for _, uuid := range uuids {
		params := entries.NewGetLogEntryByUUIDParams().WithEntryUUID(uuid)
		res, err := client.Entries.GetLogEntryByUUID(params)
		if err != nil {
			log.Debug("error getting rekor entry by uuid")
			return nil, err
		}

		// TODO: why could there be multiple entries
		for _, v := range res.Payload {
			rekorEntries = append(rekorEntries, v)
		}
	}
	return rekorEntries, nil
}

func NewRekorClient() (*client.Rekor, error) {
	client, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		log.Debug("Error creating Rekor client")
		return nil, err
	}
	return client, nil
}

// retrieve SBOMs from Rekor by artifact hash and verify that the log entry exists, verify the signing certificate by
// verification options, and check the sbom hash
func GetAndVerifySboms(sha string, client *client.Rekor) ([]spdxSbomWithMetadata, error) {
	uuids, err := getUuids(sha, client)
	if err != nil {
		return nil, err
	}
	if len(uuids) == 0 {
		return nil, nil
	}

	anonEntries, err := getRekorEntries(uuids, client)
	if len(anonEntries) == 0 {
		return nil, err
	}
	for _, anonEntry := range anonEntries {
		log.Infof("Rekor entry/s retrieved \n\t\tlogIndex: %v ", *anonEntry.LogIndex)
	}

	ctx := context.Background()
	verifiedAnonEntries := Verify(ctx, client, anonEntries)
	if len(verifiedAnonEntries) == 0 {
		return nil, nil
	}
	atts, err := parseAndValidateAttestations(verifiedAnonEntries)
	if err != nil {
		log.Debug(err)
		return nil, nil
	}
	if len(atts) == 0 {
		return nil, nil
	}

	sbomsBytes := getSboms(atts)
	if len(sbomsBytes) == 0 {
		// TODO: not being able to retrieve SBOM should not stop queryRekor functionality (e.g. sbom could require permissions)
		log.Debugf("Sbom attestation(s) found on Rekor, but the sbom(s) could not be retrieved. ")
		return nil, nil
	}

	verifiedSbomsBytes := VerifySbomsHashes(sbomsBytes)
	if len(verifiedSbomsBytes) == 0 {
		log.Debugf("Sbom attestation(s) found on Rekor, but the sbom(s) hash(es) could not be verified")
		return nil, nil
	}

	sboms, err := parseSboms(verifiedSbomsBytes)
	if err != nil {
		return nil, err
	}
	if len(sboms) == 0 {
		log.Debugf("Sbom(s) found on Rekor and retrieved, but could not be parsed")
		return nil, nil
	}

	return joinSbomsWithMetadata(sboms), nil
}
