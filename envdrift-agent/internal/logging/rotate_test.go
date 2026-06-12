// Package logging tests for the #494 size-rotating log writer.
package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotatingWriter_RotatesAtMaxBytes proves the size cap is enforced: once
// a write would push the file past maxBytes, the current content moves to
// <path>.1 and a fresh file receives the new write.
func TestRotatingWriter_RotatesAtMaxBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	w, err := NewRotatingWriter(path, 100, 2)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	first := strings.Repeat("a", 60) + "\n"
	second := strings.Repeat("b", 60) + "\n"

	for _, chunk := range []string{first, second} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	// 61+61 > 100: the second write must have rotated first out to .1.
	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("no rotation happened; %s.1 missing: %v", path, err)
	}
	if string(backup) != first {
		t.Errorf("backup content = %q, want the first chunk", backup)
	}

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != second {
		t.Errorf("active log = %q, want only the second chunk", current)
	}
}

// TestRotatingWriter_DropsOldestBeyondBackups forces three rotations with a
// single kept backup: only <path>.1 may exist afterwards; older generations
// are dropped so the total disk use stays bounded.
func TestRotatingWriter_DropsOldestBeyondBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	w, err := NewRotatingWriter(path, 10, 1)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	for i := 0; i < 4; i++ {
		if _, err := w.Write([]byte("0123456789")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected %s.1 to exist: %v", path, err)
	}
	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Errorf("%s.2 must not exist with backups=1 (err=%v)", path, err)
	}
}

// TestRotatingWriter_ShiftsBackupChain verifies the .1 -> .2 shift keeps the
// newest rotated file at .1 and the older one at .2.
func TestRotatingWriter_ShiftsBackupChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	w, err := NewRotatingWriter(path, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	for _, chunk := range []string{"aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	newest, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if string(newest) != "bbbbbbbbbb" {
		t.Errorf("%s.1 = %q, want the second chunk", path, newest)
	}
	oldest, err := os.ReadFile(path + ".2")
	if err != nil {
		t.Fatal(err)
	}
	if string(oldest) != "aaaaaaaaaa" {
		t.Errorf("%s.2 = %q, want the first chunk", path, oldest)
	}
}

// TestRotatingWriter_CreatesParentDirs covers the install path: the launchd
// plist points at ~/.envdrift/logs/agent.log, which may not exist yet.
func TestRotatingWriter_CreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "logs", "agent.log")
	w, err := NewRotatingWriter(path, 0, -1) // also exercises the defaults clamps
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Errorf("log content = %q", got)
	}
}

// TestRotatingWriter_ResumesSizeAcrossReopen pins the size accounting for an
// existing file: reopening must count the bytes already present, so a
// long-lived log still rotates even when each agent run writes little.
func TestRotatingWriter_ResumesSizeAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")

	w, err := NewRotatingWriter(path, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(strings.Repeat("a", 90))); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open (a restarted agent) and write past the cap: must rotate.
	w, err = NewRotatingWriter(path, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if _, err := w.Write([]byte(strings.Repeat("b", 20))); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("pre-existing bytes were not counted; no rotation happened: %v", err)
	}
}

// TestRotatingWriter_WriteAfterCloseFails pins the closed-writer contract the
// log package relies on (errors are discarded, not panics).
func TestRotatingWriter_WriteAfterCloseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	w, err := NewRotatingWriter(path, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil { // idempotent
		t.Errorf("second Close: %v", err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("Write after Close must fail")
	}
}
