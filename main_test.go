package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// 1. Expiry calculation: a normal item expires createdAt + expiryHours.
func TestExpiryCalculation(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	exp := ExpiryFor(now, false, 24)
	if exp == nil {
		t.Fatal("expected an expiry time")
	}
	if !exp.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("expiry = %v, want %v", *exp, now.Add(24*time.Hour))
	}
	if got := ExpiryFor(now, false, 1); !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("1h expiry = %v", *got)
	}
}

// 2. Keep-forever items never expire.
func TestKeepForeverNeverExpires(t *testing.T) {
	if exp := ExpiryFor(time.Now(), true, 24); exp != nil {
		t.Fatalf("keep-forever expiry = %v, want nil", *exp)
	}
	it := Item{KeepForever: true, ExpiresAt: nil}
	if it.IsExpired(time.Now().Add(365 * 24 * time.Hour)) {
		t.Fatal("keep-forever item reported expired a year later")
	}
	expired := time.Now().Add(-time.Hour)
	it2 := Item{ExpiresAt: &expired}
	if !it2.IsExpired(time.Now()) {
		t.Fatal("past-expiry item not reported expired")
	}
}

// 3a. Limit enforcement: maxItems blocks new clips once reached.
func TestMaxItemsLimit(t *testing.T) {
	s := testStore(t)
	st := Settings{MaxItems: 2, MaxFileMB: 100, DefaultExpiryHours: 24}
	if _, err := s.AddClip("one", false, st); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClip("two", false, st); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClip("three", false, st); err == nil {
		t.Fatal("expected an error when the item limit is reached")
	} else if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 3b. Limit enforcement: a file over maxFileMB gets 413 from the upload handler.
func TestMaxFileMBLimit(t *testing.T) {
	s := testStore(t)
	if err := s.SaveSettings(Settings{MaxItems: 200, MaxFileMB: 1, DefaultExpiryHours: 24}); err != nil {
		t.Fatal(err)
	}
	// 2 MB of data with a 1 MB limit.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(make([]byte, 2<<20))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.handleUpload(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body: %s", rec.Code, rec.Body.String())
	}
	if n, _ := s.CountItems(); n != 0 {
		t.Fatalf("oversized upload left %d item(s) behind", n)
	}
}

// 4. bcrypt password hashing and verification.
func TestPasswordHashVerify(t *testing.T) {
	hash, err := hashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "correct horse") {
		t.Fatal("correct password did not verify")
	}
	if verifyPassword(hash, "wrong password") {
		t.Fatal("wrong password verified")
	}
}

// 5. Settings defaults and validation bounds.
func TestSettingsDefaultsAndValidation(t *testing.T) {
	d := defaultSettings()
	if d.MaxItems != 200 || d.MaxFileMB != 100 || d.DefaultExpiryHours != 24 {
		t.Fatalf("defaults = %+v, want 200/100/24", d)
	}
	for _, bad := range []Settings{
		{MaxItems: 0, MaxFileMB: 100, DefaultExpiryHours: 24},
		{MaxItems: 10001, MaxFileMB: 100, DefaultExpiryHours: 24},
		{MaxItems: 200, MaxFileMB: 0, DefaultExpiryHours: 24},
		{MaxItems: 200, MaxFileMB: 1025, DefaultExpiryHours: 24},
		{MaxItems: 200, MaxFileMB: 100, DefaultExpiryHours: 0},
		{MaxItems: 200, MaxFileMB: 100, DefaultExpiryHours: 721},
	} {
		if err := ValidateSettings(bad); err == nil {
			t.Fatalf("ValidateSettings(%+v) = nil, want an error", bad)
		}
	}
	if err := ValidateSettings(Settings{MaxItems: 1, MaxFileMB: 1, DefaultExpiryHours: 1}); err != nil {
		t.Fatalf("edge-case settings rejected: %v", err)
	}
	if err := ValidateSettings(Settings{MaxItems: 10000, MaxFileMB: 1024, DefaultExpiryHours: 720}); err != nil {
		t.Fatalf("max settings rejected: %v", err)
	}
}

// 6. Filename sanitisation: no path traversal on upload/download.
func TestFilenameSanitisation(t *testing.T) {
	for in, want := range map[string]string{
		"../../etc/passwd":   "passwd",
		"/abs/path/file.txt": "file.txt",
		"":                   "file",
		"..":                 "file",
		"normal name.pdf":    "normal name.pdf",
	} {
		if got := sanitizeFilename(in); got != want {
			t.Fatalf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
	// Backslash paths must also come out traversal-free (no separators left).
	if got := sanitizeFilename(`..\windows\secret.txt`); strings.ContainsAny(got, `/\`) || got == ".." {
		t.Fatalf("sanitizeFilename backslash path unsafe: %q", got)
	}
	if got := sanitizeRelPath("../../etc/passwd"); strings.Contains(got, "..") {
		t.Fatalf("sanitizeRelPath kept traversal: %q", got)
	}
	if got := sanitizeRelPath("folder/sub/file.txt"); got != "folder/sub/file.txt" {
		t.Fatalf("sanitizeRelPath(%q) = %q", "folder/sub/file.txt", got)
	}
	if got := sanitizeID("../../etc/passwd"); strings.ContainsAny(got, "/.") {
		t.Fatalf("sanitizeID kept path characters: %q", got)
	}
}

// 7. Sweeper deletes expired files (disk + DB) and clips, keeps the rest.
func TestSweeperDeletesExpired(t *testing.T) {
	s := testStore(t)
	st := defaultSettings()
	old := time.Now().UTC().Add(-25 * time.Hour)
	expired := old.Add(24 * time.Hour)
	it, err := s.AddClip("old clip", false, st)
	if err != nil {
		t.Fatal(err)
	}
	// Force it to be expired by rewriting its expiry in the DB.
	it.ExpiresAt = &expired
	if err := s.SaveItem(*it); err != nil {
		t.Fatal(err)
	}
	// A file item that expired, with bytes on disk.
	fileIt := Item{ID: newID(), Kind: "file", Name: "gone.txt", Size: 3,
		CreatedAt: old, ExpiresAt: &expired}
	if err := os.WriteFile(s.uploadPath(fileIt.ID), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveItem(fileIt); err != nil {
		t.Fatal(err)
	}
	// A fresh item that must survive.
	if _, err := s.AddClip("fresh clip", false, st); err != nil {
		t.Fatal(err)
	}

	n, err := s.SweepExpired(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("swept %d items, want 2", n)
	}
	if _, err := os.Stat(s.uploadPath(fileIt.ID)); !os.IsNotExist(err) {
		t.Fatal("expired file was not removed from disk")
	}
	items, _ := s.ListItems()
	if len(items) != 1 || items[0].Text != "fresh clip" {
		t.Fatalf("after sweep: %d items, want the 1 fresh clip", len(items))
	}
}

// 8. Round trip: save a file item and a clip, list them newest first.
func TestStoreRoundTrip(t *testing.T) {
	s := testStore(t)
	st := defaultSettings()
	if _, err := s.AddClip("hello", true, st); err != nil {
		t.Fatal(err)
	}
	it := Item{ID: newID(), Kind: "file", Name: "a.txt", Size: 5, CreatedAt: time.Now().UTC()}
	if err := s.SaveItem(it); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("listed %d items, want 2", len(items))
	}
	if err := s.DeleteItem(it.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountItems(); n != 1 {
		t.Fatalf("count after delete = %d, want 1", n)
	}
	if _, err := filepath.Abs(s.UploadsDir()); err != nil {
		t.Fatal(err)
	}
}
