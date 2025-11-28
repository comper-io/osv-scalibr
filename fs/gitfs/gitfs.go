// Copyright 2025 Google LLC
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

// Package gitfs provides an fs.FS implementation for a git repository at a specific commit.
package gitfs

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// GitFS implements fs.FS for a git repository commit.
type GitFS struct {
	repo       *git.Repository
	tree       *object.Tree
	commitHash plumbing.Hash
	commitTime time.Time
}

// New returns a new GitFS for the given repository path and commit hash.
// If commitHash is empty, HEAD is used.
func New(repoPath string, commitHash string) (*GitFS, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open git repo at %s: %w", repoPath, err)
	}

	var hash plumbing.Hash
	if commitHash == "" {
		head, err := repo.Head()
		if err != nil {
			return nil, fmt.Errorf("failed to get HEAD: %w", err)
		}
		hash = head.Hash()
	} else {
		hash = plumbing.NewHash(commitHash)
	}

	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object %s: %w", hash, err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for commit %s: %w", hash, err)
	}

	return &GitFS{
		repo:       repo,
		tree:       tree,
		commitHash: hash,
		commitTime: commit.Committer.When,
	}, nil
}

// Open opens the named file.
func (g *GitFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	if name == "." {
		return &openDir{
			info: &fileInfo{
				name:    ".",
				size:    0,
				mode:    fs.ModeDir | 0555,
				modTime: g.commitTime,
				isDir:   true,
			},
			entries: g.tree.Entries,
		}, nil
	}

	// Find the entry to check if it is a file or directory.
	entry, err := g.tree.FindEntry(name)
	if err != nil {
		if err == object.ErrEntryNotFound {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	if entry.Mode == filemode.Dir {
		subTree, err := g.tree.Tree(name)
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		return &openDir{
			info: &fileInfo{
				name:    path.Base(name),
				size:    0,
				mode:    fs.ModeDir | 0555,
				modTime: g.commitTime,
				isDir:   true,
			},
			entries: subTree.Entries,
		}, nil
	}

	// It's a file (or symlink, etc.)
	f, err := g.tree.File(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	reader, err := f.Blob.Reader()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	// Read content into memory to support ReaderAt
	// TODO: For very large files, this might be an issue.
	// Consider implementing a specific ReaderAt for git blobs if possible.
	readerAt, err := scalibrfs.NewReaderAt(reader)
	reader.Close() // Close the original reader
	if err != nil {
		return nil, fmt.Errorf("failed to create ReaderAt: %w", err)
	}

	return &openFile{
		info: &fileInfo{
			name:    path.Base(name),
			size:    f.Size,
			mode:    g.mapMode(f.Mode),
			modTime: g.commitTime,
			isDir:   false,
		},
		ReaderAt: readerAt,
	}, nil
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries sorted by filename.
func (g *GitFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}

	var entries []object.TreeEntry
	if name == "." {
		entries = g.tree.Entries
	} else {
		subTree, err := g.tree.Tree(name)
		if err != nil {
			if err == object.ErrEntryNotFound {
				return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
			}
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
		}
		entries = subTree.Entries
	}

	var res []fs.DirEntry
	for _, e := range entries {
		res = append(res, &dirEntry{
			info: &fileInfo{
				name:    e.Name,
				size:    0, // We don't know size without fetching object, but DirEntry doesn't strictly require it for IsDir/Name
				mode:    g.mapMode(e.Mode),
				modTime: g.commitTime,
				isDir:   e.Mode == filemode.Dir,
			},
		})
	}
	return res, nil
}

// Stat returns a FileInfo describing the file.
func (g *GitFS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}

	if name == "." {
		return &fileInfo{
			name:    ".",
			size:    0,
			mode:    fs.ModeDir | 0555,
			modTime: g.commitTime,
			isDir:   true,
		}, nil
	}

	entry, err := g.tree.FindEntry(name)
	if err != nil {
		if err == object.ErrEntryNotFound {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
		}
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}

	size := int64(0)
	if entry.Mode != filemode.Dir {
		// To get size, we might need the object.
		// Optimisation: For Stat, finding the entry is enough for Mode and Name.
		// But Size requires the Blob.
		// Check if we can get size efficiently.
		// object.Tree.File(name) gets the file.
		if f, err := g.tree.File(name); err == nil {
			size = f.Size
		}
	}

	return &fileInfo{
		name:    path.Base(name),
		size:    size,
		mode:    g.mapMode(entry.Mode),
		modTime: g.commitTime,
		isDir:   entry.Mode == filemode.Dir,
	}, nil
}

func (g *GitFS) mapMode(m filemode.FileMode) fs.FileMode {
	if m == filemode.Dir {
		return fs.ModeDir | 0555
	}
	if m == filemode.Symlink {
		return fs.ModeSymlink | 0555
	}
	// Git tracks executable bit
	if m == filemode.Executable {
		return 0755
	}
	return 0644
}

// fileInfo implements fs.FileInfo
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi *fileInfo) ModTime() time.Time { return fi.modTime }
func (fi *fileInfo) IsDir() bool        { return fi.isDir }
func (fi *fileInfo) Sys() any           { return nil }

// dirEntry implements fs.DirEntry
type dirEntry struct {
	info *fileInfo
}

func (de *dirEntry) Name() string               { return de.info.Name() }
func (de *dirEntry) IsDir() bool                { return de.info.IsDir() }
func (de *dirEntry) Type() fs.FileMode          { return de.info.Mode().Type() }
func (de *dirEntry) Info() (fs.FileInfo, error) { return de.info, nil }

// openFile implements fs.File for a blob
type openFile struct {
	info *fileInfo
	io.ReaderAt
	offset int64
}

func (f *openFile) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func (f *openFile) Read(p []byte) (int, error) {
	n, err := f.ReaderAt.ReadAt(p, f.offset)
	f.offset += int64(n)
	return n, err
}

func (f *openFile) Close() error {
	return nil
}

// openDir implements fs.File for a directory
type openDir struct {
	info    *fileInfo
	entries []object.TreeEntry
	offset  int
}

func (d *openDir) Stat() (fs.FileInfo, error) {
	return d.info, nil
}

func (d *openDir) Read(p []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.Name(), Err: fs.ErrInvalid}
}

func (d *openDir) Close() error {
	return nil
}

func (d *openDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.offset >= len(d.entries) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	count := n
	if n <= 0 {
		count = len(d.entries) - d.offset
	}

	var res []fs.DirEntry
	for i := 0; i < count && d.offset < len(d.entries); i++ {
		e := d.entries[d.offset]
		d.offset++
		
		// We need to map mode here too
		mode := fs.FileMode(0644)
		isDir := false
		if e.Mode == filemode.Dir {
			mode = fs.ModeDir | 0555
			isDir = true
		} else if e.Mode == filemode.Symlink {
			mode = fs.ModeSymlink | 0555
		} else if e.Mode == filemode.Executable {
			mode = 0755
		}

		res = append(res, &dirEntry{
			info: &fileInfo{
				name:    e.Name,
				size:    0, // Unknown size without lookup
				mode:    mode,
				modTime: d.info.modTime, // Inherit from parent/commit
				isDir:   isDir,
			},
		})
	}
	return res, nil
}

