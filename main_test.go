package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// --- v0.2.0: installer auto-start + menu no longer blocks the daemon ---

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func goTool(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	p := filepath.Join(os.Getenv("HOME"), "workspace", "go-tool", "go", "bin", "go")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	t.Fatal("go toolchain not found (not in PATH, not in ~/workspace/go-tool/go/bin)")
	return ""
}

// buildTestBinary compiles the real binary into a temp dir.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "loadinme")
	cmd := exec.Command(goTool(t), "build", "-o", bin, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func healthOK(t *testing.T, port int) bool {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitHealth(t *testing.T, port int, want bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if healthOK(t, port) == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("health on port %d never became %v", port, want)
}

func runBin(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// 9. install.sh auto-starts the UI and opens the menu; no manual
// "run loadinme menu, then press 1" steps any more.
func TestInstallScriptAutoStart(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"/dev/tty", "LOADINME_NO_MENU", "LOADINME_NO_WEB",
		"LOCAL_BINARY", "/health", "start --port", "setup page",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("install.sh is missing %q", want)
		}
	}
	// The old manual flow must be gone: no "Next steps" block telling
	// the user to run the menu and then start the UI by hand.
	if strings.Contains(s, "Next steps:") {
		t.Fatal("install.sh still has a manual 'Next steps' block")
	}
	if strings.Contains(s, "loadinme serve --port 8080") {
		t.Fatal("install.sh still tells the user to start the UI by hand")
	}
	if out := exec.Command("bash", "-n", "install.sh").Run(); out != nil {
		t.Fatalf("bash -n install.sh failed: %v", out)
	}
}

// 10. /health probe: true for a live server, false when nothing listens.
func TestProbeHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	if !probeHealth(Config{Port: port}) {
		t.Fatal("probeHealth = false for a live /health server")
	}
	if probeHealth(Config{Port: freePort(t)}) {
		t.Fatal("probeHealth = true with nothing listening")
	}
}

// 11. pidAlive: true for our own process, false for a dead one.
func TestPidAlive(t *testing.T) {
	if !pidAlive(os.Getpid()) {
		t.Fatal("pidAlive(own pid) = false")
	}
	// A PID that (almost certainly) never existed.
	if pidAlive(999999) {
		t.Fatal("pidAlive(999999) = true")
	}
}

// 12. `loadinme start` starts the UI (and /health answers), a second
// start is a harmless no-op, `stop` stops it.
func TestStartStopViaBinary(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	cfg := Config{Port: port, DataDir: dataDir}

	out, err := runBin(t, bin, "start", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Web UI started") {
		t.Fatalf("start output = %q, want 'Web UI started'", out)
	}
	waitHealth(t, port, true)
	if !isServiceRunning(cfg) {
		t.Fatal("isServiceRunning = false while the UI is up")
	}

	// Second start must not spawn a second copy.
	out, err = runBin(t, bin, "start", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("second start: %v\n%s", err, out)
	}
	if !strings.Contains(out, "already running") {
		t.Fatalf("second start output = %q, want 'already running'", out)
	}
	waitHealth(t, port, true)

	out, err = runBin(t, bin, "stop", "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("stop: %v\n%s", err, out)
	}
	waitHealth(t, port, false)
	if isServiceRunning(cfg) {
		t.Fatal("isServiceRunning = true after stop")
	}
}

// 13. Regression test for the v0.1.0 DB-lock bug: starting the UI from
// the menu must work WHILE the menu is still open (the menu used to
// hold the bbolt lock, so the daemon died with "could not open data
// store: timeout" while the menu printed "Web UI started").
func TestMenuStartWhileMenuOpen(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)

	cmd := exec.Command(bin, "menu", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = runBin(t, bin, "stop", "--data-dir", dataDir)
	}()
	// Press 1 (Start), keep the menu alive by leaving stdin open.
	if _, err := io.WriteString(stdin, "1\n"); err != nil {
		t.Fatal(err)
	}
	// The UI must come up while the menu process is still running.
	waitHealth(t, port, true)
	if !isServiceRunning(Config{Port: port, DataDir: dataDir}) {
		t.Fatal("isServiceRunning = false while menu-started UI is up")
	}
	// Exit the menu (Enter for the pause, then 0).
	_, _ = io.WriteString(stdin, "\n0\n")
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("menu exited with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("menu did not exit")
	}
	// The UI must still be running after the menu exits.
	waitHealth(t, port, true)
}
