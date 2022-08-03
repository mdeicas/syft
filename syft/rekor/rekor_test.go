package rekor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name                string
	inputFilePath       string // resolver and location are created from this
	expectedOutput      []artifact.Relationship
	uuidsToLogEntryFile map[string]string // tells the rekorClient mock what uuids and what log entries to return
	httpClient          *http.Client
	expectedErr         string
	expectedLog         string
}

/*
***************

	Functions and types to complete the interfaces in client.Rekor. Most are unimplemented.

****************
*/

type entriesMock struct {
	test testCase
}

type indexMock struct {
	test testCase
}

type roundTripperMock struct {
	sbomFile string
}

func (rt roundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	sbom_bytes, err := os.ReadFile(rt.sbomFile)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(sbom_bytes)),
	}, nil
}

func (e entriesMock) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return nil, errors.New("Unimplemented")
}

func (e entriesMock) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, errors.New("Unimplemented")
}

func (e entriesMock) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	return nil, errors.New("Unimplemented")
}

func (e entriesMock) SetTransport(transport runtime.ClientTransport) {}

func (a indexMock) SetTransport(transport runtime.ClientTransport) {}

func (e entriesMock) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	uuid := params.EntryUUID

	filePath, ok := e.test.uuidsToLogEntryFile[uuid]
	if !ok {
		return nil, errors.New("no test data file exists for uuid %v")
	}

	if filePath == "return nil payload" {
		return &entries.GetLogEntryByUUIDOK{
			Payload: nil,
		}, nil
	}

	entry := &models.LogEntry{}
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading test data from file %v: \n%w", filePath, err)
	}
	err = json.Unmarshal(bytes, entry)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json test data from file %v: \n%w", filePath, err)
	}

	res := &entries.GetLogEntryByUUIDOK{
		Payload: *entry,
	}

	return res, nil
}

// ignores input hash; just returns uuids in test case
func (a indexMock) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	var uuids []string
	for uuid := range a.test.uuidsToLogEntryFile {
		uuids = append(uuids, uuid)
	}

	res := &index.SearchIndexOK{
		Payload: uuids,
	}
	return res, nil
}

/*
***************

	Test function

****************
*/

func Test_CreateRekorSbomRels(t *testing.T) {
	default_tc := &http.Client{
		Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-1.txt"},
	}

	testLogger, hook := test.NewNullLogger()
	log.Log = testLogger

	// just test succesful calls here because CreateRekorSbomRels does not return the verification errors, parse errors, etc
	tests := []testCase{
		{
			name:          "one sbom entry, one non-sbom entry",
			inputFilePath: "test-fixtures/file-to-hash.txt",
			expectedOutput: []artifact.Relationship{
				{
					From: source.NewLocation("test-fixtures/file-to-hash.txt"),
					To: NewExternalRef(
						"SBOM-SPDX-ba96f4cc-d9e3-4c83-a1db-ec5456b6a9ce",
						"http://www.example.com/binary.spdx",
						spdx.SHA1,
						"eb141a8a026322e2ff6a1ec851af5268dfe59b20",
					),
					Type: artifact.ContainsRelationship,
				},
			},
			uuidsToLogEntryFile: map[string]string{
				"c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4": "test-fixtures/log-entries/log-entry-1.json",
				"88aa67ce4f4a3fa3e8da8adb4e4799b53372f078459639e571e5583e2685c304": "test-fixtures/log-entries/log-entry-2.json",
			},
		},
		{
			name:          "sbom missing namespace",
			inputFilePath: "test-fixtures/file-to-hash.txt",
			uuidsToLogEntryFile: map[string]string{
				"09f4d6138d167fc246dc69badb11b9a931395e7ca00fb38a1889d287f9d4110e": "test-fixtures/log-entries/log-entry-5.json",
			},
			httpClient: &http.Client{
				Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-3.txt"},
			},
			expectedLog: "SBOM found on Rekor for file in location test-fixtures/file-to-hash.txt, but its namespace is empty. Ignoring SBOM.",
		},
		{
			name:          "file to hash is a folder",
			inputFilePath: "test-fixtures/",
			expectedErr:   "error generating digests",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// set up mocks
			rekorMock := &client.Rekor{
				Entries: entriesMock{test: test},
				Index:   indexMock{test: test},
			}

			var httpClient *http.Client
			if test.httpClient == nil {
				httpClient = default_tc
			} else {
				httpClient = test.httpClient
			}

			client := &Client{
				rekorClient: rekorMock,
				httpClient:  httpClient,
			}

			resolver := source.NewMockResolverForPaths(test.inputFilePath)
			location := source.NewLocation(test.inputFilePath)

			rels, err := CreateRekorSbomRels(resolver, location, client)

			if test.expectedErr == "" {
				assert.Equal(t, test.expectedOutput, rels)
				assert.NoError(t, err)
			}
			if test.expectedLog != "" {
				if hook.LastEntry().Message != test.expectedLog {
					msg := fmt.Sprintf("expected log message \"%v\" but got log message \"%v\"", test.expectedLog, hook.LastEntry().Message)
					assert.FailNow(t, msg)
				}
			}
			if test.expectedErr != "" {
				assert.ErrorContains(t, err, test.expectedErr)
			}
		})
	}
}
