package queryRekor

import (
	"crypto"
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/spdx/tools-golang/spdx"
)

type ExternalRef struct {
	SpdxRef spdx.ExternalDocumentRef2_2
}

func (r ExternalRef) ID() artifact.ID {

	id, err := artifact.IDByHash(r.SpdxRef.Checksum)
	if err != nil {
		panic("id could not be created from hash for an external ref")
	}

	return id
}

func NewExternalRef(docRef string, uri string, algo string, hash string) ExternalRef {
	return ExternalRef{
		SpdxRef: spdx.ExternalDocumentRef2_2{
			DocumentRefID: docRef,
			URI:           uri,
			Alg:           "SHA1",
			Checksum:      hash,
		},
	}
}

func CreateRekorSbomRels(resolver source.FileResolver, location source.Location) ([]artifact.Relationship, error) {

	closer, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.Debugf("error getting reader from resolver for a second time")
	}

	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256}
	digests, err := file.DigestsFromFile(closer, hashes)
	if err != nil {
		return nil, err
	}

	sha1, sha256 := parseDigests(digests)

	log.Debugf("Rekor is being queried for \n\t\tLocation: %v \n\t\tSHA1: %v \n\t\tSHA256: %v", location.RealPath, sha1, sha256)

	client, err := NewRekorClient()
	if err != nil {
		log.Debugf("Error creating rekor client")
		return nil, err
	}

	sboms, err := GetAndVerifySboms(sha256, client)
	if err != nil {
		log.Debug("Error retrieving or verifying sbom(s)")
		return nil, err
	}
	if len(sboms) == 0 {
		log.Debug("No sboms found on rekor")
		return nil, err
	}

	var rels []artifact.Relationship
	for _, sbom := range sboms {
		externalRef := NewExternalRef("sample-golang-prov", sbom.namespace, "SHA1", sha1)
		rel := artifact.Relationship{
			From: location,
			To:   externalRef,
			Type: artifact.ContainsRelationship,
			Data: fmt.Sprintf("External reference metadata: %+v", externalRef.SpdxRef),
		}
		rels = append(rels, rel)
		log.Debugf("Relationship created for SBOM found on Rekor \n\t\tFrom: %v \n\t\tTo: %v", rel.From.ID(), rel.To.ID())
	}

	return rels, nil

}
