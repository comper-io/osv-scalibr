// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package osvlocal

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/fakeserver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func npmVulnerability(id, name string) *osvpb.Vulnerability {
	return &osvpb.Vulnerability{
		Id: id,
		Affected: []*osvpb.Affected{{
			Package: &osvpb.Package{Ecosystem: "npm", Name: name},
			Ranges: []*osvpb.Range{{
				Type:   osvpb.Range_SEMVER,
				Events: []*osvpb.Event{{Introduced: "0"}},
			}},
		}},
	}
}

func sharedMatcherTestServer(t *testing.T, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	archive := fakeserver.ZipOSVs(t, map[string]*osvpb.Vulnerability{
		"OSV-A.json": npmVulnerability("OSV-A", "package-a"),
		"OSV-B.json": npmVulnerability("OSV-B", "package-b"),
	})
	return fakeserver.CreateZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(archive)
	})
}

func TestSharedLocalMatcherLoadsFullDatabaseOnce(t *testing.T) {
	var requests atomic.Int32
	server := sharedMatcherTestServer(t, &requests)
	matcher, err := newSharedLocalMatcher(t.TempDir(), "", true, server.URL, server.Client(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	packageA := &extractor.Package{Name: "package-a", Version: "1.0.0", PURLType: purl.TypeNPM}
	packageB := &extractor.Package{Name: "package-b", Version: "1.0.0", PURLType: purl.TypeNPM}
	if vulns, err := matcher.MatchVulnerabilities(t.Context(), packageA, []*extractor.Package{packageA}); err != nil || len(vulns) != 1 {
		t.Fatalf("first match returned %d vulnerabilities, %v", len(vulns), err)
	}
	if vulns, err := matcher.MatchVulnerabilities(t.Context(), packageB, []*extractor.Package{packageB}); err != nil || len(vulns) != 1 {
		t.Fatalf("second match returned %d vulnerabilities, %v", len(vulns), err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("database requests = %d, want 1", got)
	}
}

func TestSharedLocalMatcherSerializesInitialLoad(t *testing.T) {
	var requests atomic.Int32
	server := sharedMatcherTestServer(t, &requests)
	matcher, err := newSharedLocalMatcher(t.TempDir(), "", true, server.URL, server.Client(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &extractor.Package{Name: "package-a", Version: "1.0.0", PURLType: purl.TypeNPM}

	const workers = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns, err := matcher.MatchVulnerabilities(t.Context(), pkg, []*extractor.Package{pkg})
			if err != nil {
				errs <- err
				return
			}
			if len(vulns) != 1 {
				errs <- &unexpectedVulnerabilityCount{got: len(vulns)}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("database requests = %d, want 1", got)
	}
}

type unexpectedVulnerabilityCount struct{ got int }

func (e *unexpectedVulnerabilityCount) Error() string { return "unexpected vulnerability count" }
