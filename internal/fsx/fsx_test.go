// SPDX-License-Identifier: AGPL-3.0-only

package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

// A write is durable in order: the temporary file is synced while the
// target still holds what it held, then renamed into place, then the
// directory is synced with the target in place.
func TestWriteFileSyncsTheFileBeforeTheRenameAndTheDirectoryAfter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	type event struct {
		name   string
		isDir  bool
		target string // what the target held at the time
	}
	var events []event
	saved := Sync
	Sync = func(f *os.File) error {
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		events = append(events, event{name: f.Name(), isDir: fi.IsDir(), target: string(raw)})
		return nil
	}
	defer func() { Sync = saved }()
	if err := WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("two syncs, the file's and the directory's: %+v", events)
	}
	if events[0].isDir || events[0].name != path+".tmp" || events[0].target != "old\n" {
		t.Fatalf("the temporary file is synced while the target still holds what it held: %+v", events[0])
	}
	if !events[1].isDir || events[1].name != dir || events[1].target != "new\n" {
		t.Fatalf("the directory is synced with the target in place: %+v", events[1])
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("no temporary file left: %v", err)
	}
	// A directory at the temporary path blocks the write and is left
	// alone, the target untouched.
	blocked := filepath.Join(dir, "blocked.pem")
	if err := os.Mkdir(blocked+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(blocked, []byte("x"), 0o600); err == nil {
		t.Fatal("a blocked write must fail")
	}
	if fi, err := os.Stat(blocked + ".tmp"); err != nil || !fi.IsDir() {
		t.Fatalf("the blocker is left alone: %v %v", fi, err)
	}
	if _, err := os.Stat(blocked); !os.IsNotExist(err) {
		t.Fatalf("the target is untouched: %v", err)
	}
}
