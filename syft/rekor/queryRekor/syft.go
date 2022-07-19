package queryRekor

import (
	"crypto"
	"errors"
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

func CreateRekorSbomRel(resolver source.FileResolver, location source.Location) (*artifact.Relationship, error) {

	closer, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.Debugf("error getting reader from resolver for a second time")
	}

	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256}
	digests, err := file.DigestsFromFile(closer, hashes)
	if err != nil {
		return nil, err
	}

	var sha1 string
	var sha256 string
	if digests[0].Algorithm == "sha1" && digests[1].Algorithm == "sha256" {
		sha1 = digests[0].Value
		sha256 = digests[1].Value
	} else if digests[0].Algorithm == "sha256" && digests[1].Algorithm == "sha1" {
		sha256 = digests[0].Value
		sha1 = digests[1].Value
	} else {
		log.Debug("Unexpected digests")
		return nil, nil
	}

	log.Debugf("Rekor is being queried for \n\t\tLocation: %v \n\t\tSHA1: %v \n\t\tSHA256: %v", location.RealPath, sha1, sha256)

	client, err := NewRekorClient()
	if err != nil {
		log.Debugf("Error creating rekor client")
		return nil, err
	}

	sbom, err := GetAndVerifySbom(sha256, client)
	if err != nil {
		log.Debug("Error retrieving or verifying sbom")
		return nil, err
	}
	if sbom == nil {
		log.Debug("No sbom found on rekor")
		return nil, err
	}

	namespace := sbom.CreationInfo.DocumentNamespace
	if namespace == "" {
		log.Debug("namespace for SBOM is nil")
		return nil, errors.New("sbomError")
	}

	// TODO - get package name from inside SBOM or from attestation.build-metadata?
	externalRef := NewExternalRef("sample-golang-prov", namespace, "SHA1", sha1)

	rel := &artifact.Relationship{
		From: location,
		To:   externalRef,
		Type: artifact.ContainsRelationship,
		Data: fmt.Sprintf("External reference metadata: %+v", externalRef.SpdxRef),
	}

	log.Debugf("Relationship created for SBOM found on Rekor \n\t\tFrom: %v \n\t\tTo: %v", rel.From.ID(), rel.To.ID())

	return rel, nil

}
