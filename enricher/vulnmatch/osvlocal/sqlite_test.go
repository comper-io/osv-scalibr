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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/fakeserver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

type mutableArchiveServer struct {
	t       *testing.T
	mu      sync.Mutex
	archive []byte
	hash    string
	getGate <-chan struct{}
	getSeen chan<- struct{}
	status  int
}

func (s *mutableArchiveServer) set(vulnerability *osvpb.Vulnerability, getGate <-chan struct{}, getSeen chan<- struct{}) {
	s.t.Helper()
	archive := fakeserver.ZipOSVs(s.t, map[string]*osvpb.Vulnerability{vulnerability.GetId() + ".json": vulnerability})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archive = archive
	s.hash = fakeserver.ComputeCRC32CHash(s.t, archive)
	s.getGate = getGate
	s.getSeen = getSeen
	s.status = http.StatusOK
}

func (s *mutableArchiveServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	archive := append([]byte(nil), s.archive...)
	hash, gate, seen, status := s.hash, s.getGate, s.getSeen, s.status
	s.mu.Unlock()
	w.Header().Set("X-Goog-Hash", "crc32c="+hash)
	if r.Method == http.MethodHead {
		return
	}
	if seen != nil {
		select {
		case seen <- struct{}{}:
		default:
		}
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
	}
	_, _ = w.Write(archive)
}

func TestSQLiteRefreshFailureKeepsActiveGeneration(t *testing.T) {
	state := &mutableArchiveServer{t: t}
	state.set(npmVulnerability("OSV-OLD", "package-a"), nil, nil)
	server := httptest.NewServer(state)
	t.Cleanup(server.Close)
	store, err := newSQLiteStore(sqliteStoreConfig{
		name:            "npm",
		dbBasePath:      t.TempDir(),
		archiveURL:      server.URL,
		httpClient:      server.Client(),
		refreshInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg := &extractor.Package{Name: "package-a", Version: "1.0.0", PURLType: purl.TypeNPM}
	if err := store.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	store.mu.RLock()
	oldPath := store.activePath
	store.mu.RUnlock()

	seen := make(chan struct{}, 1)
	state.set(npmVulnerability("OSV-BROKEN", "package-a"), nil, seen)
	state.mu.Lock()
	state.status = http.StatusInternalServerError
	state.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	if err := store.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("failed refresh did not run")
	}
	deadline := time.Now().Add(time.Second)
	for {
		store.refreshMu.Lock()
		running := store.refreshRunning
		store.refreshMu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed refresh did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	assertSQLiteMatchID(t, store, pkg, "OSV-OLD")
	store.mu.RLock()
	activePath := store.activePath
	store.mu.RUnlock()
	if activePath != oldPath {
		t.Fatalf("active generation changed after failed refresh: %q -> %q", oldPath, activePath)
	}
}

func TestSQLiteRefreshServesOldGenerationUntilAtomicSwap(t *testing.T) {
	state := &mutableArchiveServer{t: t}
	state.set(npmVulnerability("OSV-OLD", "package-a"), nil, nil)
	server := httptest.NewServer(state)
	t.Cleanup(server.Close)
	store, err := newSQLiteStore(sqliteStoreConfig{
		name:            "npm",
		dbBasePath:      t.TempDir(),
		archiveURL:      server.URL,
		httpClient:      server.Client(),
		refreshInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg := &extractor.Package{Name: "package-a", Version: "1.0.0", PURLType: purl.TypeNPM}
	if err := store.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertSQLiteMatchID(t, store, pkg, "OSV-OLD")
	store.mu.RLock()
	oldPath := store.activePath
	store.mu.RUnlock()

	gate := make(chan struct{})
	seen := make(chan struct{}, 1)
	state.set(npmVulnerability("OSV-NEW", "package-a"), gate, seen)
	time.Sleep(10 * time.Millisecond)
	start := time.Now()
	if err := store.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertSQLiteMatchID(t, store, pkg, "OSV-OLD")
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("request waited for refresh: %v", elapsed)
	}
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("refresh download did not start")
	}
	close(gate)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		matches, err := store.Match(t.Context(), pkg.Name, false, pkg)
		if err == nil && len(matches) == 1 && matches[0].GetId() == "OSV-NEW" {
			if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("retired generation still exists: %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("new generation was not activated")
}

func assertSQLiteMatchID(t *testing.T, store *sqliteStore, pkg *extractor.Package, want string) {
	t.Helper()
	matches, err := store.Match(t.Context(), pkg.Name, false, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].GetId() != want {
		t.Fatalf("matches = %v, want only %s", matches, want)
	}
}
