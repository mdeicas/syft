package spdx22json

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/rekor/queryRekor"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func Test_toExternalDocumentRefs(t *testing.T) {

	package_1 := pkg.Package{
		Name: "Hello World Package 1",
	}
	package_2 := pkg.Package{
		Name: "Hello World Package 2",
	}
	externalRef_1 := queryRekor.NewExternalRef("HelloWorld", "www.example.com", "SHA1", "bogushash")
	externalRef_2 := queryRekor.NewExternalRef("Test", "www.test.com", "sha1", "testhash")

	tests := []struct {
		name          string
		relationships []artifact.Relationship
		expected      []model.ExternalDocumentRef
	}{
		{
			name: "empty",
		},
		{
			name: "Both external relationships and non external relationships",
			relationships: []artifact.Relationship{
				{
					From: package_1,
					To:   package_2,
					Type: artifact.ContainsRelationship,
				},
				{
					From: package_1,
					To:   externalRef_1,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []model.ExternalDocumentRef{
				{
					ExternalDocumentID: model.ElementID(externalRef_1.ID()).String(),
					Checksum:           model.Checksum{Algorithm: "SHA1", ChecksumValue: "bogushash"},
					SpdxDocument:       externalRef_1.SpdxRef.URI,
				},
			},
		},
		{
			name: "Lowercase checksum algorithm",
			relationships: []artifact.Relationship{
				{
					From: package_1,
					To:   externalRef_2,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []model.ExternalDocumentRef{
				{
					ExternalDocumentID: model.ElementID(externalRef_2.ID()).String(),
					Checksum:           model.Checksum{Algorithm: "SHA1", ChecksumValue: "testhash"},
					SpdxDocument:       externalRef_2.SpdxRef.URI,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, toExternalDocumentRefs(test.relationships))
		})
	}
}

func Test_toFileTypes(t *testing.T) {

	tests := []struct {
		name     string
		metadata source.FileMetadata
		expected []string
	}{
		{
			name: "application",
			metadata: source.FileMetadata{
				MIMEType: "application/vnd.unknown",
			},
			expected: []string{
				string(spdxhelpers.ApplicationFileType),
			},
		},
		{
			name: "archive",
			metadata: source.FileMetadata{
				MIMEType: "application/zip",
			},
			expected: []string{
				string(spdxhelpers.ApplicationFileType),
				string(spdxhelpers.ArchiveFileType),
			},
		},
		{
			name: "audio",
			metadata: source.FileMetadata{
				MIMEType: "audio/ogg",
			},
			expected: []string{
				string(spdxhelpers.AudioFileType),
			},
		},
		{
			name: "video",
			metadata: source.FileMetadata{
				MIMEType: "video/3gpp",
			},
			expected: []string{
				string(spdxhelpers.VideoFileType),
			},
		},
		{
			name: "text",
			metadata: source.FileMetadata{
				MIMEType: "text/html",
			},
			expected: []string{
				string(spdxhelpers.TextFileType),
			},
		},
		{
			name: "image",
			metadata: source.FileMetadata{
				MIMEType: "image/png",
			},
			expected: []string{
				string(spdxhelpers.ImageFileType),
			},
		},
		{
			name: "binary",
			metadata: source.FileMetadata{
				MIMEType: "application/x-sharedlib",
			},
			expected: []string{
				string(spdxhelpers.ApplicationFileType),
				string(spdxhelpers.BinaryFileType),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, toFileTypes(&test.metadata))
		})
	}
}

func Test_lookupRelationship(t *testing.T) {

	tests := []struct {
		input   artifact.RelationshipType
		exists  bool
		ty      spdxhelpers.RelationshipType
		comment string
	}{
		{
			input:  artifact.ContainsRelationship,
			exists: true,
			ty:     spdxhelpers.ContainsRelationship,
		},
		{
			input:   artifact.OwnershipByFileOverlapRelationship,
			exists:  true,
			ty:      spdxhelpers.OtherRelationship,
			comment: "ownership-by-file-overlap: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by",
		},
		{
			input:  "made-up",
			exists: false,
		},
	}
	for _, test := range tests {
		t.Run(string(test.input), func(t *testing.T) {
			exists, ty, comment := lookupRelationship(test.input)
			assert.Equal(t, exists, test.exists)
			assert.Equal(t, ty, test.ty)
			assert.Equal(t, comment, test.comment)
		})
	}
}

func Test_toFileChecksums(t *testing.T) {
	tests := []struct {
		name     string
		digests  []file.Digest
		expected []model.Checksum
	}{
		{
			name: "empty",
		},
		{
			name: "has digests",
			digests: []file.Digest{
				{
					Algorithm: "SHA256",
					Value:     "deadbeefcafe",
				},
				{
					Algorithm: "md5",
					Value:     "meh",
				},
			},
			expected: []model.Checksum{
				{
					Algorithm:     "SHA256",
					ChecksumValue: "deadbeefcafe",
				},
				{
					Algorithm:     "MD5",
					ChecksumValue: "meh",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, toFileChecksums(test.digests))
		})
	}
}

func Test_fileIDsForPackage(t *testing.T) {

	p := pkg.Package{
		Name: "bogus",
	}

	c := source.Coordinates{
		RealPath:     "/path",
		FileSystemID: "nowhere",
	}

	tests := []struct {
		name          string
		id            string
		relationships []artifact.Relationship
		expected      []string
	}{
		{
			name: "find file IDs for packages with package-file relationships",
			id:   string(p.ID()),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{
				string(c.ID()),
			},
		},
		{
			name: "ignore package-to-package",
			id:   string(p.ID()),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{},
		},
		{
			name: "ignore file-to-file",
			id:   string(p.ID()),
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{},
		},
		{
			name: "ignore file-to-package",
			id:   string(p.ID()),
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{},
		},
		{
			name: "filter by relationship type",
			id:   string(p.ID()),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expected: []string{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, fileIDsForPackage(test.id, test.relationships))
		})
	}
}
