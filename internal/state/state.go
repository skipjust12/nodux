// Package state keeps a small JSON document on disk across restarts:
// open alerts, detector state and the event stream position. Writes are
// atomic (temp file, fsync, rename, fsync of the directory), so a crash
// or power loss leaves either the old file or the new one, never half
// of each.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const fileName = "state.json"

type File struct {
	path string
	last []byte // what's on disk, to skip writes that change nothing
}

// Open prepares dir (created 0700 if missing) and checks that it's
// writable, so a misconfigured state_dir fails at startup rather than
// at the first save.
func Open(dir string) (*File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("state dir %s is not writable: %w", dir, err)
	}
	probe.Close()
	os.Remove(probe.Name())
	return &File{path: filepath.Join(dir, fileName)}, nil
}

// Path is where the state lives.
func (f *File) Path() string { return f.path }

// Load decodes the saved state into v. It reports false, and leaves v
// alone, if nothing was saved yet.
func (f *File) Load(v any) (bool, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%s: %w", f.path, err)
	}
	f.last = data
	return true, nil
}

// Save atomically replaces the saved state with v. Nothing is written
// if the encoded state didn't change.
func (f *File) Save(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if bytes.Equal(data, f.last) {
		return nil
	}

	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, fileName+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), f.path); err != nil {
		return err
	}
	// Make the rename itself durable.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	f.last = data
	return nil
}
