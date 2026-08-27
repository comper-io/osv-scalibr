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
	"archive/zip"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

type sqliteStoreConfig struct {
	name            string
	dbBasePath      string
	archiveURL      string
	userAgent       string
	offline         bool
	httpClient      *http.Client
	refreshInterval time.Duration
}

// sqliteStore owns immutable database generations for one ecosystem.
type sqliteStore struct {
	cfg sqliteStoreConfig
	dir string

	mu         sync.RWMutex
	active     *sql.DB
	activePath string
	activeHash uint32
	lastCheck  time.Time

	refreshMu      sync.Mutex
	refreshRunning bool
}

func newSQLiteStore(cfg sqliteStoreConfig) (*sqliteStore, error) {
	dir := filepath.Join(cfg.dbBasePath, cfg.name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create SQLite cache directory: %w", err)
	}
	s := &sqliteStore{cfg: cfg, dir: dir}
	if err := s.openNewestGeneration(); err != nil {
		return nil, err
	}
	return s, nil
}

// Ensure makes an initial generation available. Once a generation is active,
// stale checks and rebuilds run asynchronously so requests keep using it.
func (s *sqliteStore) Ensure(ctx context.Context) error {
	s.mu.RLock()
	active := s.active != nil
	stale := s.lastCheck.IsZero() || (s.cfg.refreshInterval > 0 && time.Since(s.lastCheck) >= s.cfg.refreshInterval)
	s.mu.RUnlock()
	if active {
		if stale && !s.cfg.offline {
			s.startRefresh()
		}
		return nil
	}
	return s.refresh(ctx)
}

func (s *sqliteStore) startRefresh() {
	s.refreshMu.Lock()
	if s.refreshRunning {
		s.refreshMu.Unlock()
		return
	}
	s.refreshRunning = true
	s.refreshMu.Unlock()
	go func() {
		defer func() {
			s.refreshMu.Lock()
			s.refreshRunning = false
			s.refreshMu.Unlock()
		}()
		if err := s.refresh(context.Background()); err != nil {
			log.Warnf("could not refresh %s SQLite vulnerability database; continuing with current generation: %v", s.cfg.name, err)
		}
	}()
}

func (s *sqliteStore) refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	s.mu.RLock()
	fresh := s.active != nil && s.cfg.refreshInterval > 0 && !s.lastCheck.IsZero() && time.Since(s.lastCheck) < s.cfg.refreshInterval
	s.mu.RUnlock()
	if fresh {
		return nil
	}

	s.mu.Lock()
	s.lastCheck = time.Now()
	s.mu.Unlock()

	archivePath := filepath.Join(s.dir, "all.zip")
	var hash uint32
	var err error
	if s.cfg.offline {
		hash, err = crc32cFile(archivePath)
	} else {
		hash, err = fetchRemoteArchiveCRC32CHash(ctx, s.cfg.archiveURL, s.cfg.httpClient)
	}
	if err != nil {
		return err
	}

	s.mu.RLock()
	unchanged := s.active != nil && s.activeHash == hash
	s.mu.RUnlock()
	if unchanged {
		return nil
	}

	generationPath := filepath.Join(s.dir, fmt.Sprintf("osv-%08x.sqlite", hash))
	if _, err := os.Stat(generationPath); errors.Is(err, os.ErrNotExist) {
		if !s.cfg.offline {
			if err := s.ensureArchive(ctx, archivePath, hash); err != nil {
				return err
			}
		}
		if err := buildSQLiteGeneration(ctx, archivePath, generationPath, s.cfg.name, hash); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	db, err := openSQLiteGeneration(generationPath, s.cfg.name)
	if err != nil {
		return err
	}

	s.mu.Lock()
	oldDB, oldPath := s.active, s.activePath
	s.active, s.activePath, s.activeHash = db, generationPath, hash
	s.mu.Unlock()

	if oldDB != nil {
		_ = oldDB.Close()
	}
	if oldPath != "" && oldPath != generationPath {
		_ = os.Remove(oldPath)
	}
	log.Infof("Activated %s SQLite vulnerability database generation %08x", s.cfg.name, hash)
	return nil
}

func (s *sqliteStore) ensureArchive(ctx context.Context, archivePath string, remoteHash uint32) error {
	if localHash, err := crc32cFile(archivePath); err == nil && localHash == remoteHash {
		return nil
	}
	return downloadArchive(ctx, s.cfg.archiveURL, archivePath, s.cfg.userAgent, remoteHash, s.cfg.httpClient)
}

func crc32cFile(filename string) (uint32, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err := io.Copy(h, f); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

func downloadArchive(ctx context.Context, archiveURL, destination, userAgent string, wantHash uint32, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("db host returned %s", resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".all-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := h.Sum32(); got != wantHash {
		return fmt.Errorf("downloaded archive checksum %08x, want %08x", got, wantHash)
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	return nil
}

func buildSQLiteGeneration(ctx context.Context, archivePath, destination, ecosystem string, hash uint32) error {
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".osv-*.sqlite")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite", sqliteDSN(tmpPath, false))
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		PRAGMA journal_mode=OFF;
		PRAGMA synchronous=OFF;
		PRAGMA temp_store=FILE;
		PRAGMA cache_size=-2048;
		CREATE TABLE metadata (schema_version INTEGER NOT NULL, ecosystem TEXT NOT NULL, archive_hash TEXT NOT NULL);
		CREATE TABLE advisories (id TEXT PRIMARY KEY, json BLOB NOT NULL) WITHOUT ROWID;
		CREATE TABLE package_advisories (package TEXT NOT NULL, advisory_id TEXT NOT NULL, PRIMARY KEY(package, advisory_id)) WITHOUT ROWID;
		CREATE TABLE git_advisories (repo TEXT NOT NULL, advisory_id TEXT NOT NULL, PRIMARY KEY(repo, advisory_id)) WITHOUT ROWID;
	`); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO metadata VALUES (?, ?, ?)", sqliteSchemaVersion, ecosystem, fmt.Sprintf("%08x", hash)); err != nil {
		return err
	}
	insertVuln, err := tx.PrepareContext(ctx, "INSERT OR REPLACE INTO advisories(id, json) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer insertVuln.Close()
	insertPackage, err := tx.PrepareContext(ctx, "INSERT OR IGNORE INTO package_advisories(package, advisory_id) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer insertPackage.Close()
	insertRepo, err := tx.PrepareContext(ctx, "INSERT OR IGNORE INTO git_advisories(repo, advisory_id) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer insertRepo.Close()

	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		content, vuln, err := readZipVulnerability(entry)
		if err != nil {
			continue
		}
		if _, err := insertVuln.ExecContext(ctx, vuln.GetId(), content); err != nil {
			return err
		}
		for _, affected := range vuln.GetAffected() {
			if name := affected.GetPackage().GetName(); name != "" {
				if _, err := insertPackage.ExecContext(ctx, name, vuln.GetId()); err != nil {
					return err
				}
			}
			for _, r := range affected.GetRanges() {
				if repo := vulns.NormalizeRepo(r.GetRepo()); repo != "" {
					if _, err := insertRepo.ExecContext(ctx, repo, vuln.GetId()); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	completed, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	if err := completed.Sync(); err != nil {
		_ = completed.Close()
		return err
	}
	if err := completed.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, destination)
}

func readZipVulnerability(entry *zip.File) ([]byte, *osvpb.Vulnerability, error) {
	f, err := entry.Open()
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	vuln := &osvpb.Vulnerability{}
	if err := protojson.Unmarshal(content, vuln); err != nil || vuln.GetId() == "" {
		return nil, nil, errors.New("invalid OSV vulnerability")
	}
	return content, vuln, nil
}

func sqliteDSN(filename string, readOnly bool) string {
	u := &url.URL{Scheme: "file", Path: filename}
	q := u.Query()
	q.Set("_pragma", "busy_timeout(5000)")
	if readOnly {
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(1)")
		q.Add("_pragma", "cache_size(-2048)")
		q.Add("_pragma", "mmap_size(0)")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func openSQLiteGeneration(filename, ecosystem string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteDSN(filename, true))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	var schema int
	var gotEcosystem, hash string
	if err := db.QueryRow("SELECT schema_version, ecosystem, archive_hash FROM metadata LIMIT 1").Scan(&schema, &gotEcosystem, &hash); err != nil {
		_ = db.Close()
		return nil, err
	}
	if schema != sqliteSchemaVersion || gotEcosystem != ecosystem {
		_ = db.Close()
		return nil, fmt.Errorf("incompatible SQLite vulnerability database")
	}
	return db, nil
}

func (s *sqliteStore) openNewestGeneration() error {
	files, err := filepath.Glob(filepath.Join(s.dir, "osv-*.sqlite"))
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool {
		iInfo, iErr := os.Stat(files[i])
		jInfo, jErr := os.Stat(files[j])
		if iErr != nil || jErr != nil {
			return files[i] > files[j]
		}
		return iInfo.ModTime().After(jInfo.ModTime())
	})
	for _, filename := range files {
		db, err := openSQLiteGeneration(filename, s.cfg.name)
		if err != nil {
			continue
		}
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(filename), "osv-"), ".sqlite")
		hashBytes, err := hex.DecodeString(base)
		if err != nil || len(hashBytes) != 4 {
			_ = db.Close()
			continue
		}
		s.active = db
		s.activePath = filename
		s.activeHash = uint32(hashBytes[0])<<24 | uint32(hashBytes[1])<<16 | uint32(hashBytes[2])<<8 | uint32(hashBytes[3])
		return nil
	}
	return nil
}

func (s *sqliteStore) Match(ctx context.Context, packageName string, git bool, pkg *extractor.Package) ([]*osvpb.Vulnerability, error) {
	table, column, key := "package_advisories", "package", packageName
	if git {
		table, column, key = "git_advisories", "repo", vulns.NormalizeRepo(packageName)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return nil, errors.New("SQLite vulnerability database is not loaded")
	}
	query := fmt.Sprintf("SELECT a.json FROM %s i JOIN advisories a ON a.id=i.advisory_id WHERE i.%s=?", table, column)
	rows, err := s.active.QueryContext(ctx, query, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []*osvpb.Vulnerability
	for rows.Next() {
		var content []byte
		if err := rows.Scan(&content); err != nil {
			return nil, err
		}
		vuln := &osvpb.Vulnerability{}
		if err := protojson.Unmarshal(content, vuln); err != nil {
			return nil, err
		}
		if vuln.GetWithdrawn() == nil && vulns.IsAffected(vuln, pkg) && !vulns.Include(matches, vuln) {
			matches = append(matches, vuln)
		}
	}
	return matches, rows.Err()
}
