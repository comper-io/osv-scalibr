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

// Package csproj extracts PackageReference dependencies from .NET project files
// (.csproj, .fsproj, .vbproj) and props files (e.g. Directory.Packages.props,
// Directory.Build.props). Implements the extraction described in
// https://github.com/google/osv-scalibr/issues/618.
package csproj

import (
	"context"
	"encoding/xml"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/csproj"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 5 * units.MiB
)

// Config is the configuration for the .NET csproj/props extractor.
type Config struct {
	Stats            stats.Collector
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts NuGet PackageReference from .NET project and props files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a .NET csproj/props extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewFromPluginConfig returns a csproj extractor from plugin config (InitFn signature).
func NewFromPluginConfig(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	c := DefaultConfig()
	if cfg.GetMaxFileSizeBytes() > 0 {
		c.MaxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return New(c), nil
}

// NewDefault returns an extractor with default config.
func NewDefault() filesystem.Extractor {
	return New(DefaultConfig())
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:            e.stats,
		MaxFileSizeBytes: e.maxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true for *.csproj, *.fsproj, *.vbproj, and *.props files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	ext := strings.ToLower(filepath.Ext(path))

	if ext == ".props" {
		return e.checkSize(api, path)
	}
	if ext == ".csproj" || ext == ".fsproj" || ext == ".vbproj" {
		return e.checkSize(api, path)
	}
	return false
}

func (e Extractor) checkSize(api filesystem.FileAPI, path string) bool {
	fileinfo, err := api.Stat()
	if err != nil || (e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes) {
		if e.stats != nil {
			e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
				Path:   path,
				Result: stats.FileRequiredResultSizeLimitExceeded,
			})
		}
		return false
	}
	if e.stats != nil {
		e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
			Path:   path,
			Result: stats.FileRequiredResultOK,
		})
	}
	return true
}

// Extract parses the project/props file for PackageReference elements.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := e.extractFromInput(ctx, input)
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: packages}, err
}

type packageReference struct {
	Include      string `xml:"Include,attr"`
	Update       string `xml:"Update,attr"`
	Version      string `xml:"Version,attr"`
	VersionChild string `xml:"Version"`
}

type itemGroup struct {
	PackageReferences []packageReference `xml:"PackageReference"`
}

type project struct {
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, err
	}

	var proj project
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&proj); err != nil {
		log.Errorf("Error parsing %s: %v", input.Path, err)
		return nil, err
	}

	// Collect version definitions for PackageReference Update (from props files)
	// When processing a project file, we may need to resolve Update refs from Directory.*.props
	versionMap := make(map[string]string)
	for _, ig := range proj.ItemGroups {
		for _, pr := range ig.PackageReferences {
			if pr.Include != "" && (pr.Version != "" || pr.VersionChild != "") {
				ver := pr.Version
				if ver == "" {
					ver = pr.VersionChild
				}
				versionMap[pr.Include] = strings.TrimSpace(ver)
			}
		}
	}

	// Also load versions from Directory.Packages.props and Directory.Build.props
	// when we have Update references (for .csproj/.fsproj/.vbproj files)
	ext := strings.ToLower(filepath.Ext(input.Path))
	if ext == ".csproj" || ext == ".fsproj" || ext == ".vbproj" {
		e.loadVersionMapFromProps(ctx, input, versionMap)
	}

	var result []*extractor.Package
	for _, ig := range proj.ItemGroups {
		for _, pr := range ig.PackageReferences {
			pkgName := pr.Include
			if pkgName == "" {
				pkgName = pr.Update
			}
			if pkgName == "" {
				continue
			}
			pkgName = strings.TrimSpace(pkgName)

			version := pr.Version
			if version == "" {
				version = pr.VersionChild
			}
			version = strings.TrimSpace(version)

			if version == "" && pr.Update != "" {
				version = versionMap[pkgName]
			}
			if version == "" {
				log.Warnf("Skipping PackageReference %q in %s: no version (Update refs need Directory.Packages.props or Directory.Build.props)", pkgName, input.Path)
				continue
			}

			result = append(result, &extractor.Package{
				Name:      pkgName,
				Version:   version,
				PURLType:  purl.TypeNuget,
				Locations: []string{input.Path},
			})
		}
	}

	return result, nil
}

// loadVersionMapFromProps walks up from the current file's directory looking for
// Directory.Packages.props and Directory.Build.props, merging their PackageReference
// Include+Version into versionMap.
func (e Extractor) loadVersionMapFromProps(_ context.Context, input *filesystem.ScanInput, versionMap map[string]string) {
	// input.Path is relative to the FS root (scan root)
	dir := filepath.Dir(input.Path)
	propsNames := []string{"Directory.Packages.props", "Directory.Build.props"}

	for dir != "." && dir != "" && !strings.HasPrefix(dir, "..") {
		for _, name := range propsNames {
			propsPath := filepath.Join(dir, name)
			propsPath = filepath.ToSlash(propsPath)

			f, err := input.FS.Open(propsPath)
			if err != nil {
				continue
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				continue
			}

			var proj project
			if err := xml.Unmarshal(data, &proj); err != nil {
				continue
			}

			for _, ig := range proj.ItemGroups {
				for _, pr := range ig.PackageReferences {
					if pr.Include != "" && (pr.Version != "" || pr.VersionChild != "") {
						ver := pr.Version
						if ver == "" {
							ver = pr.VersionChild
						}
						if _, exists := versionMap[pr.Include]; !exists {
							versionMap[strings.TrimSpace(pr.Include)] = strings.TrimSpace(ver)
						}
					}
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
}
