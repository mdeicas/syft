# Motivation
There is currently no way to handle finding opaque binaries in images. With a few exceptions, it is not possible to look inside an executable and report information on its contents and dependencies. This information is accessible at the build time of executables, but there has been no way to propagate this data to a later stage in the software supply chain.  

With the development of the Sigstore supply chain security infrastructure, it is now possible to access information from the build time of artifacts.  This issue and related PRs propose a way to incorporate this information into Syft. 

# The rekor-cataloger 	
(link PR) contributes a package which can search the Rekor transparency log for information about SBOMs of executables, and the rekor-cataloger, the integration point between the package and Syft. 

## Design decisions
* To implement a cataloger specifically for searching and retrieving information from Rekor. This design meets a good midpoint between abstraction and configurability, and feasibility of implementation. Other designs considered included
    * A more general “SBOM” cataloger (encompassing https://github.com/anchore/syft/issues/737)
    * A simpler implementation, such as searching Rekor after all of the catalogers finish execution
* To reference the discovered SBOMs with external reference relationships instead of merging the discovered SBOM(s) with the Syft-produced SBOM. 
    * Merging SBOMs was considered to be an optional follow-up feature, and is still under investigation (https://github.com/anchore/syft/issues/617.

## How the rekor-cataloger works 
Upon finding an executable, Rekor is searched by hash. The log entries and associated SBOMs are retrieved and verified, and relationships are created. 

The rekor package exports an ExternalRef type that represents information about an external sbom. It is an identifiable, and is placed into a Syft relationship to upstream the information. When mapping the Syft SBOM format to other formats, relationships with ExternalRefs are handled in accordance with each format’s specification. In SPDX, they appear in the external reference documents section in addition to being referenced in a relationship. Here is an example:
```
...
"externalDocumentRefs": [
  {
   "externalDocumentId": "SPDXRef-24a791393ed162b5",
   "checksum": {
    "algorithm": "SHA1",
    "checksumValue": "eb141a8a026322e2ff6a1ec851af5268dfe59b20"
   },
   "spdxDocument": "http://www.example.com/binary.spdx"
  }
 ]
...
 "relationships": [
  {
    "spdxElementId": "SPDXRef-60c7a33477750e02",
    "relationshipType": "CONTAINS",
    "relatedSpdxElement": "SPDXRef-24a791393ed162b5"
  }
]
...
```

The rekor package can only read log entries that are associated with in-toto attestations (https://github.com/in-toto/attestation). The content of the SBOM that is referenced in the attestation must successfully be retrieved to continue execution, and only SPDX SBOMs can be read. 

## Demo
To demo the rekor-cataloger, run Syft on an image containing go-compiled binaries that have SBOMs on Rekor. 

# Managing external sources 
The use of external sources is new to Syft, and they should be managed carefully (i.e. configurability, clear to users what has been used and how). 
Accordingly, (link PR) introduces a new external sources configuration, an additional function that catalogers must implement, and a cli flag to shut off the use of external sources. This approach assumes that external sources will only come into Syft through catalogers. 

Separate from that PR, rekor-cataloger logs a warning indicating what was used to create the output SBOM. 

# Verification of data 
The use of external sources requires verification of data that is found. 

To explain the verification actions that are taken, simplified depictions of the Rekor log entry and in-toto attestation data formats are shown here:
```
Attestation:
    subject:
        hash (this is the hash of the binary)
    predicate:
        sbom-hash  
        sbom-uri

Rekor log entry:
    timestamp 
    attestation-hash
    certificate
```

The rekor package retrieves the Rekor log entry, the associated in-toto attestation, and the SBOM. It performs verification to ensure that the retrieved data has not been tampered with. It verifies that:
- the log entry has been signed by Rekor’s public key
- the certificate chains back to a Fulcio root certificate
- the log entry timestamp lies in the period of validity of the certificate 
- the attestation-hash equals the hash of the attestation that is obtained
- the attestation.subject hash equals the hash of the binary that is being searched for
- the attestation.predicate sbom-hash equals the hash of the sbom bytes retrieved from sbom-uri

These steps ensure that the retrieved information, and the upstream external document reference that is produced, can be trusted if Rekor, Fulcio, and the certificate subject are trusted.

A current limitation of Rekor entries for in-toto attestations does not allow the verification of the certificate subject’s signature over the attestation (https://github.com/sigstore/rekor/issues/582). Once this is possible, Rekor will not need to be trusted. 

When a builder, such as the slsa-github-generator (https://github.com/slsa-framework/slsa-github-generator), generates the SBOM and uploads it to Rekor, a path from source code to SBOM is created. In this case, the only trust predicates are the builder and Fulcio. 


# Surfacing packages versus surfacing binaries
External document references that the rekor-cataloger produces must be related to SBOM entries for *executables* as opposed to entries for the *packages* they contain (in-toto attestation subjects are executables, not packages. Also, packages cannot always be created for executables, so relationships cannot created for them). Currently, Syft only surfaces packages. Binaries that are found, but that cannot be looked inside of, do not appear in the SBOMs output by Syft. 

This raises the larger question of whether Syft should only surface an executable when it can provide meaningful information for it. The current design prevents the rekor-cataloger’s ability to report information in the output SBOM, but also should raise wider questions about how the completeness of SBOMs output by Syft is perceived.   

This PR includes a temporary solution to allow the use of the rekor-cataloger for golang binaries, but does not attempt to resolve the larger question. It involves a change (see commit titled “surface external relationships”) to the golang-binary-cataloger to create SBOM entries not only for the packages that executables contain, but also the executables themselves. This allows the rekor-cataloger to create external reference relationships using the entries for golang executables. Since no entries are created for binaries that are not golang-compiled, the results from the rekor-cataloger for them will not appear in output SBOMs. Another implication is that the rekor-cataloger cannot be run without the golang-binary cataloger, as rekor-cataloger does not itself create packages. 


# Follow up work
- Map relationships with ExternalRefs to Cyclone and SPDX TV formats (only SPDX JSON was implemented) 
- Verification of the signature over the attestation 
- Enable the rekor-cataloger to surface results for all binaries, not just golang-compiled ones
    - A proposed solution is for Syft to create an SBOM entry for all executables, whether or not they can be analyzed, and relate them to the packages they contain using relationships.  



