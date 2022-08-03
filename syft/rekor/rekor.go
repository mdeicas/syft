package rekor

import (
	"errors"
	"net/http"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/spdx/tools-golang/spdx"
)

const (
	DefaultRekorAddr = "https://rekor.sigstore.dev"
)

type Client struct {
	rekorClient *client.Rekor
	httpClient  *http.Client
}

type ExternalRef struct {
	SpdxRef spdx.ExternalDocumentRef2_2
}

func NewClient() (*Client, error) {
	rekorClient, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		return nil, errors.New("error creating Rekor client")
	}

	return &Client{
		rekorClient: rekorClient,
		httpClient:  &http.Client{},
	}, nil
}

func (r ExternalRef) ID() artifact.ID {
	id, err := artifact.IDByHash(r.SpdxRef.Checksum)
	if err != nil {
		panic("id could not be created from hash for an external ref")
	}
	return id
}

func NewExternalRef(docRef string, uri string, alg spdx.ChecksumAlgorithm, hash string) ExternalRef {
	return ExternalRef{
		SpdxRef: spdx.ExternalDocumentRef2_2{
			DocumentRefID: docRef, //docRef is how to identify this ref internally within the SBOM
			URI:           uri,
			Alg:           string(alg),
			Checksum:      hash, // hash of the external document
		},
	}
}

// CreateRekorSbomRels searches Rekor by the hash of the file in the given location and creates external reference relationships
// for any sboms that are found and verified
func CreateRekorSbomRels(resolver source.FileResolver, location source.Location, client *Client) ([]artifact.Relationship, error) {
	sboms, err := getAndVerifySbomsFromResolver(resolver, location, client)
	if err != nil {
		return nil, err
	}

	var rels []artifact.Relationship
	for _, sbomWithDigest := range sboms {
		if sbomWithDigest == nil || sbomWithDigest.spdx == nil {
			log.Warnf("SBOM found on Rekor for file in location %v, but CreateRekorSbomRels recieved a nil sbom")
		}
		sbom := sbomWithDigest.spdx
		if sbom.CreationInfo == nil {
			log.Warnf("SBOM found on Rekor for file in location %v, but its Creation Info section is empty. Ignoring SBOM", location.RealPath)
			continue
		}
		namespace := sbom.CreationInfo.DocumentNamespace
		docRef := sbom.CreationInfo.DocumentName
		if namespace == "" {
			log.Warnf("SBOM found on Rekor for file in location %v, but its namespace is empty. Ignoring SBOM.", location.RealPath)
			continue
		}

		externalRef := NewExternalRef(docRef, namespace, spdx.SHA1, sbomWithDigest.sha1)
		rel := &artifact.Relationship{
			From: location,
			To:   externalRef,
			Type: artifact.ContainsRelationship,
			Data: nil,
		}
		rels = append(rels, *rel)
		log.Debugf("Relationship created for SBOM found on Rekor \n\t\tFrom: %v \n\t\tTo: %v", rel.From.ID(), rel.To.ID())
	}

	return rels, nil
}
