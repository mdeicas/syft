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

func NewExternalRef(docRef string, uri string, alg spdx.ChecksumAlgorithm, hash string) ExternalRef {
	return ExternalRef{
		SpdxRef: spdx.ExternalDocumentRef2_2{
			DocumentRefID: docRef, //docRef is how to identify this ref internally within the SBOM
			URI:           uri,
			Alg:           string(alg),
			Checksum:      hash,
		},
	}
}

// CreateRekorSbomRels searches Rekor by the hash of the file in the given location and creates external reference relationships
// for any sboms that are found and verified
func CreateRekorSbomRels(resolver source.FileResolver, location source.Location) ([]artifact.Relationship, error) {
	closer, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("error getting reader from resolver: %w", err)
	}

	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256}
	digests, err := file.DigestsFromFile(closer, hashes)
	if err != nil {
		return nil, fmt.Errorf("error generating digests from file %v: %w", location.RealPath, err)
	}

	digestMap := parseDigests(digests)
	sha1, sha256 := digestMap[spdx.SHA1], digestMap[spdx.SHA256]

	log.Debugf("Rekor is being queried for \n\t\tLocation: %v \n\t\tSHA1: %v \n\t\tSHA256: %v", location.RealPath, sha1, sha256)

	client, err := NewRekorClient()
	if err != nil {
		return nil, fmt.Errorf("error creating rekor client: %w", err)
	}

	sboms, err := GetAndVerifySboms(sha256, client)
	if err != nil {
		return nil, fmt.Errorf("error searching rekor in location %v: %w", location.RealPath, err)
	}
	if len(sboms) == 0 {
		return nil, fmt.Errorf("no sboms found")
	}

	var rels []artifact.Relationship
	for _, sbom := range sboms {
		if sbom.CreationInfo == nil {
			log.Debugf("SBOM found on Rekor for file in location %v, but its Creation Info section is empty. Ignoring SBOM", location.RealPath)
			continue
		}
		namespace := sbom.CreationInfo.DocumentNamespace
		docRef := sbom.CreationInfo.DocumentName
		if namespace == "" {
			log.Debug("SBOM found on Rekor for file in location %v, but its namespace is empty. Ignoring SBOM.", location.RealPath)
			continue
		}
		externalRef := NewExternalRef(docRef, namespace, spdx.SHA1, sha1)
		rel := &artifact.Relationship{
			From: location,
			To:   externalRef,
			Type: artifact.ContainsRelationship,
			Data: fmt.Sprintf("External reference metadata: %+v", externalRef.SpdxRef),
		}
		rels = append(rels, *rel)
		log.Debugf("Relationship created for SBOM found on Rekor \n\t\tFrom: %v \n\t\tTo: %v", rel.From.ID(), rel.To.ID())
	}

	return rels, nil

}
