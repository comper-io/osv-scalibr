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

package csproj_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     csproj.Config
		wantCfg csproj.Config
	}{
		{
			name: "default",
			cfg:  csproj.DefaultConfig(),
			wantCfg: csproj.Config{
				MaxFileSizeBytes: 5 * units.MiB,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csproj.New(tt.cfg)
			if diff := cmp.Diff(tt.wantCfg.MaxFileSizeBytes, got.Config().MaxFileSizeBytes); diff != "" {
				t.Errorf("New(): (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{"csproj", "Project.csproj", 1000, 10000, true, stats.FileRequiredResultOK},
		{"fsproj", "Project.fsproj", 1000, 10000, true, stats.FileRequiredResultOK},
		{"vbproj", "Project.vbproj", 1000, 10000, true, stats.FileRequiredResultOK},
		{"props", "Directory.Packages.props", 1000, 10000, true, stats.FileRequiredResultOK},
		{"arbitrary props", "file.props", 1000, 10000, true, stats.FileRequiredResultOK},
		{"packages.config not required", "packages.config", 1000, 10000, false, ""},
		{"size exceeded", "Project.csproj", 10 * units.MiB, units.MiB, false, stats.FileRequiredResultSizeLimitExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = csproj.New(csproj.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			if tt.wantResultMetric != "" {
				gotResultMetric := collector.FileRequiredResult(tt.path)
				if gotResultMetric != tt.wantResultMetric {
					t.Errorf("FileRequired(%s) recorded %v, want %v", tt.path, gotResultMetric, tt.wantResultMetric)
				}
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "valid csproj with PackageReference",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.csproj",
			},
			WantPackages: []*extractor.Package{
				{Name: "LiteDB", Version: "5.0.12", PURLType: purl.TypeNuget, Locations: []string{"testdata/valid.csproj"}},
				{Name: "Newtonsoft.Json", Version: "13.0.1", PURLType: purl.TypeNuget, Locations: []string{"testdata/valid.csproj"}},
			},
		},
		{
			Name: "Version as child element",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/version_as_child.csproj",
			},
			WantPackages: []*extractor.Package{
				{Name: "SomePackage", Version: "1.2.3", PURLType: purl.TypeNuget, Locations: []string{"testdata/version_as_child.csproj"}},
			},
		},
		{
			Name: "props file with PackageReference",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/props_only.props",
			},
			WantPackages: []*extractor.Package{
				{Name: "LiteDB", Version: "5.0.12", PURLType: purl.TypeNuget, Locations: []string{"testdata/props_only.props"}},
				{Name: "OtherPkg", Version: "2.0.0", PURLType: purl.TypeNuget, Locations: []string{"testdata/props_only.props"}},
			},
		},
		{
			Name: "csproj with Update and Directory.Packages.props in same dir",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/update_with_props/App.csproj",
			},
			WantPackages: []*extractor.Package{
				{Name: "LiteDB", Version: "5.0.12", PURLType: purl.TypeNuget, Locations: []string{"testdata/update_with_props/App.csproj"}},
				{Name: "DirectPkg", Version: "1.0.0", PURLType: purl.TypeNuget, Locations: []string{"testdata/update_with_props/App.csproj"}},
			},
		},
		{
			Name: "invalid xml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.csproj",
			},
			WantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = csproj.New(csproj.Config{
				Stats:            collector,
				MaxFileSizeBytes: 100 * units.KiB,
			})

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Extract() error diff (-want +got):\n%s", diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("Extract() diff (-want +got):\n%s", diff)
			}
		})
	}
}
