package state

import (
	"os"
	"path/filepath"
	"testing"
)

type doc struct {
	N    int               `json:"n"`
	Tags map[string]string `json:"tags"`
}

func TestFile_SaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state dir: %v %v", info, err)
	}

	var got doc
	if ok, err := f.Load(&got); ok || err != nil {
		t.Fatalf("empty dir: ok=%v err=%v", ok, err)
	}
	if err := f.Save(doc{N: 1, Tags: map[string]string{"b": "2", "a": "1"}}); err != nil {
		t.Fatal(err)
	}

	f2, _ := Open(dir)
	if ok, err := f2.Load(&got); !ok || err != nil || got.N != 1 || got.Tags["a"] != "1" {
		t.Fatalf("load: ok=%v err=%v got=%+v", ok, err, got)
	}
	if info, _ := os.Stat(f.Path()); info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftover temp files: %v", entries)
	}
}

func TestFile_SkipsUnchangedWrites(t *testing.T) {
	f, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.Save(doc{N: 1})
	info1, _ := os.Stat(f.Path())
	os.Chmod(f.Path(), 0o400) // a rewrite would replace the file, and its mode
	if err := f.Save(doc{N: 1}); err != nil {
		t.Fatal(err)
	}
	info2, _ := os.Stat(f.Path())
	if info2.Mode() != 0o400 || !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("unchanged state was rewritten")
	}
	if err := f.Save(doc{N: 2}); err != nil {
		t.Fatal(err)
	}
	var got doc
	f.Load(&got)
	if got.N != 2 {
		t.Errorf("got %+v", got)
	}
}

func TestFile_CorruptFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, fileName), []byte("{not json"), 0o600)
	f, _ := Open(dir)
	var got doc
	if ok, err := f.Load(&got); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestOpen_UnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if _, err := Open(dir); err == nil {
		t.Fatal("expected an error for a read-only dir")
	}
}
