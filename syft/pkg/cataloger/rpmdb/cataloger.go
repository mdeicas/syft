/*
Package rpmdb provides a concrete Cataloger implementation for RPM "Package" DB files.
*/
package rpmdb

import (
	"fmt"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "rpmdb-cataloger"

type Cataloger struct{}

// NewRpmdbCataloger returns a new RPM DB cataloger object.
func NewRpmdbCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// UsesExternalSources indicates that the rpmdb cataloger does not use external sources
func (c *Cataloger) UsesExternalSources() bool {
	return false
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	fileMatches, err := resolver.FilesByGlob(pkg.RpmDBGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find rpmdb's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, location := range fileMatches {
		dbContentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return nil, nil, err
		}

		discoveredPkgs, err := parseRpmDB(resolver, location, dbContentReader)
		internal.CloseAndLogError(dbContentReader, location.VirtualPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to catalog rpmdb package=%+v: %w", location.RealPath, err)
		}

		pkgs = append(pkgs, discoveredPkgs...)
	}

	// Additionally look for RPM manifest files to detect packages in CBL-Mariner distroless images
	manifestFileMatches, err := resolver.FilesByGlob(pkg.RpmManifestGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find rpm manifests by glob: %w", err)
	}

	for _, location := range manifestFileMatches {
		reader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return nil, nil, err
		}

		discoveredPkgs, err := parseRpmManifest(location, reader)
		internal.CloseAndLogError(reader, location.VirtualPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to catalog rpm manifest=%+v: %w", location.RealPath, err)
		}

		pkgs = append(pkgs, discoveredPkgs...)
	}

	return pkgs, nil, nil
}
