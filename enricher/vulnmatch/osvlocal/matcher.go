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
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	osvutil "github.com/google/osv-scalibr/enricher/vulnmatch/internal/osvutil"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

const envKeyLocalDBCacheDirectory = "OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY"

// localMatcher implements the VulnerabilityMatcher interface by downloading the osv export zip files,
// and performing the matching locally.
type localMatcher struct {
	zippedDBRemoteHost string

	dbBasePath string
	mu         sync.Mutex
	dbs        map[osvconstants.Ecosystem]*cachedDB
	downloadDB bool
	// fullLoad loads every advisory in an ecosystem. This is required when the
	// matcher is reused across scans whose package sets differ.
	fullLoad bool
	// refreshInterval controls when a shared database is checked for updates.
	// A non-positive duration keeps a loaded result for the matcher's lifetime.
	refreshInterval time.Duration
	// userAgent sets the user agent requests for db zips are made with
	userAgent  string
	httpClient *http.Client
}

type cachedDB struct {
	mu          sync.Mutex
	db          *zipDB
	sqlite      *sqliteStore
	err         error
	lastAttempt time.Time
}

func newlocalMatcher(localDBPath string, userAgent string, downloadDB bool, zippedDBRemoteHost string, httpClient *http.Client) (*localMatcher, error) {
	dbBasePath, err := setupLocalDBDirectory(localDBPath)
	if err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dbBasePath, err)
	}

	return &localMatcher{
		zippedDBRemoteHost: zippedDBRemoteHost,

		dbBasePath: dbBasePath,
		dbs:        make(map[osvconstants.Ecosystem]*cachedDB),
		downloadDB: downloadDB,
		userAgent:  userAgent,
		httpClient: httpClient,
	}, nil
}

func newSharedLocalMatcher(localDBPath string, userAgent string, downloadDB bool, zippedDBRemoteHost string, httpClient *http.Client, refreshInterval time.Duration) (*localMatcher, error) {
	matcher, err := newlocalMatcher(localDBPath, userAgent, downloadDB, zippedDBRemoteHost, httpClient)
	if err != nil {
		return nil, err
	}
	matcher.fullLoad = true
	matcher.refreshInterval = refreshInterval
	return matcher, nil
}

func (matcher *localMatcher) MatchVulnerabilities(ctx context.Context, pkg *extractor.Package, pkgs []*extractor.Package) ([]*osvpb.Vulnerability, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	np := osvutil.ParsePackage(pkg)
	eco := np.Ecosystem.Ecosystem

	if np.Ecosystem.IsEmpty() {
		// matching ecosystem-less versions can only be attempted if we have a version
		if np.Version == "" {
			// Is a commit based query, skip local scanning
			return nil, nil
		}

		eco = "GIT"
	}

	if matcher.fullLoad {
		store, err := matcher.loadSQLiteStore(ctx, eco)
		if err != nil {
			return nil, err
		}
		return store.Match(ctx, np.Name, eco == "GIT", pkg)
	}

	db, err := matcher.loadDBFromCache(ctx, eco, pkgs)

	if err != nil {
		return nil, err
	}

	candidates := db.Vulnerabilities
	if eco != "GIT" {
		candidates = db.vulnerabilitiesByPackage[np.Name]
	}
	return VulnerabilitiesAffectingPackage(candidates, pkg), nil
}

func (matcher *localMatcher) loadSQLiteStore(ctx context.Context, eco osvconstants.Ecosystem) (*sqliteStore, error) {
	matcher.mu.Lock()
	entry, ok := matcher.dbs[eco]
	if !ok {
		entry = &cachedDB{}
		matcher.dbs[eco] = entry
	}
	matcher.mu.Unlock()

	entry.mu.Lock()
	if entry.sqlite == nil {
		store, err := newSQLiteStore(sqliteStoreConfig{
			name:            string(eco),
			dbBasePath:      matcher.dbBasePath,
			archiveURL:      fmt.Sprintf("%s/%s/all.zip", matcher.zippedDBRemoteHost, eco),
			userAgent:       matcher.userAgent,
			offline:         !matcher.downloadDB,
			httpClient:      matcher.httpClient,
			refreshInterval: matcher.refreshInterval,
		})
		if err != nil {
			entry.mu.Unlock()
			return nil, err
		}
		entry.sqlite = store
	}
	store := entry.sqlite
	entry.mu.Unlock()

	if err := store.Ensure(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (matcher *localMatcher) loadDBFromCache(ctx context.Context, eco osvconstants.Ecosystem, invs []*extractor.Package) (*zipDB, error) {
	matcher.mu.Lock()
	entry, ok := matcher.dbs[eco]
	if !ok {
		entry = &cachedDB{}
		matcher.dbs[eco] = entry
	}
	matcher.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if !entry.lastAttempt.IsZero() && (matcher.refreshInterval <= 0 || time.Since(entry.lastAttempt) < matcher.refreshInterval) {
		if entry.db != nil {
			return entry.db, nil
		}
		return nil, entry.err
	}

	packages := invs
	if matcher.fullLoad {
		packages = nil
	}

	db, err := newZippedDB(
		ctx,
		matcher.dbBasePath,
		string(eco),
		fmt.Sprintf("%s/%s/all.zip", matcher.zippedDBRemoteHost, eco),
		matcher.userAgent,
		!matcher.downloadDB,
		packages,
		matcher.httpClient,
	)
	entry.lastAttempt = time.Now()

	if err != nil {
		entry.err = err
		if entry.db != nil {
			log.Warnf("could not refresh db for %s ecosystem; using cached database: %v", eco, err)
			return entry.db, nil
		}
		log.Errorf("could not load db for %s ecosystem: %v", eco, err)
		return nil, entry.err
	}

	log.Infof("Loaded %s local db from %s", db.Name, db.StoredAt)

	entry.db = db
	entry.err = nil

	return db, nil
}

// setupLocalDBDirectory attempts to set up the directory the scanner should
// use to store local databases.
//
// if a local path is explicitly provided either by the localDBPath parameter
// or via the envKeyLocalDBCacheDirectory environment variable, the scanner will
// attempt to use the user cache directory if possible or otherwise the temp directory
//
// if an error occurs at any point when a local path is not explicitly provided,
// the scanner will fall back to the temp directory first before finally erroring
func setupLocalDBDirectory(localDBPath string) (string, error) {
	var err error

	// fallback to the env variable if a local database path has not been provided
	if localDBPath == "" {
		if p, envSet := os.LookupEnv(envKeyLocalDBCacheDirectory); envSet {
			localDBPath = p
		}
	}

	implicitPath := localDBPath == ""

	// if we're implicitly picking a path, use the user cache directory if available
	if implicitPath {
		localDBPath, err = os.UserCacheDir()

		if err != nil {
			localDBPath = os.TempDir()
		}
	}

	altPath := path.Join(localDBPath, "osv-scalibr")
	err = os.MkdirAll(altPath, 0750)
	if err == nil {
		return altPath, nil
	}

	// if we're implicitly picking a path, try the temp directory before giving up
	if implicitPath && localDBPath != os.TempDir() {
		return setupLocalDBDirectory(os.TempDir())
	}

	return "", err
}
