package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	waitHealthOrFail(t, port, want, "")
}

// waitHealthOrFail is waitHealth with extra context (e.g. the menu's
// or the reset command's captured output) included in the failure
// message, so a CI failure shows what the process actually printed
// instead of only "health never became true".
func waitHealthOrFail(t *testing.T, port int, want bool, extra string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if healthOK(t, port) == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	if extra != "" {
		t.Fatalf("health on port %d never became %v\n%s", port, want, extra)
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
	// v0.4.0: after installing, the UI is ALWAYS restarted with the
	// new version — the old "already running, skip the restart" path
	// must be gone, and the script must stop the old process first,
	// then start the new one and print its version.
	for _, want := range []string{
		"stop --data-dir", "Web UI restarted on port", "version",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("install.sh is missing restart-after-update %q", want)
		}
	}
	if strings.Contains(s, "Web UI is already running on port") {
		t.Fatal("install.sh still skips the restart when the UI is already running")
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

// v0.4.0: the generated systemd unit must disable systemd's
// start-rate limiting. CI run #25 failed because the test suite
// starts/stops the same loadinme.service unit many times in a row
// and systemd refused with "start of the service was attempted too
// often" — the unit sat in a failed state and the restart after a
// menu password reset never came up. StartLimitIntervalSec=0 turns
// the limit off, so menu/installer restarts can never be refused
// for being "too often", on a VPS or in CI.
func TestServiceFileDisablesStartRateLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := Config{Port: 18080, DataDir: t.TempDir()}
	if err := installServiceFile(cfg); err != nil {
		t.Fatalf("installServiceFile: %v", err)
	}
	b, err := os.ReadFile(serviceFilePath())
	if err != nil {
		t.Fatalf("read service file: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "StartLimitIntervalSec=0") {
		t.Fatalf("service file is missing StartLimitIntervalSec=0:\n%s", s)
	}
	// It must be a [Unit] setting (before [Service]), not a stray line.
	if strings.Index(s, "StartLimitIntervalSec=0") > strings.Index(s, "[Service]") {
		t.Fatalf("StartLimitIntervalSec=0 is not in the [Unit] section:\n%s", s)
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

// --- v0.3.0: image preview endpoint /p/{id} ---

// tinyPNG is a valid 1x1 PNG.
var tinyPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
	0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
	0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
	0x42, 0x60, 0x82,
}

func testAuthedServer(t *testing.T, s *Store) (*httptest.Server, string) {
	t.Helper()
	hash, err := hashPassword("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUser("testuser", hash); err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateSession("testuser")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newRouter(s, Config{DataDir: s.DataDir()}))
	t.Cleanup(srv.Close)
	return srv, sessionCookie + "=" + token
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func uploadViaAPI(t *testing.T, srv *httptest.Server, cookie, filename string, data []byte) string {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/upload", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Cookie", cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload %s: status = %d, want 201; body: %s", filename, resp.StatusCode, b)
	}
	var out struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Item.ID == "" {
		t.Fatal("upload returned no item id")
	}
	return out.Item.ID
}

func getPreview(t *testing.T, srv *httptest.Server, cookie, id string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/p/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// 14a. A PNG preview returns 200, image/png, inline, with the exact bytes.
func TestPreviewImagePNG(t *testing.T) {
	s := testStore(t)
	srv, cookie := testAuthedServer(t, s)
	id := uploadViaAPI(t, srv, cookie, "tiny.png", tinyPNG)
	resp := getPreview(t, srv, cookie, id)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "inline" {
		t.Fatalf("Content-Disposition = %q, want inline", cd)
	}
	if v := resp.Header.Get("X-Content-Type-Options"); v != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", v)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, tinyPNG) {
		t.Fatalf("preview body = %d bytes, want the %d uploaded PNG bytes", len(got), len(tinyPNG))
	}
}

// 14b. Non-image previews are rejected: .txt and .svg both get 415
// (SVG is not previewed — it can carry scripts).
func TestPreviewNonImage415(t *testing.T) {
	s := testStore(t)
	srv, cookie := testAuthedServer(t, s)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"notes.txt", []byte("hello")},
		{"pic.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)},
	} {
		id := uploadViaAPI(t, srv, cookie, tc.name, tc.data)
		resp := getPreview(t, srv, cookie, id)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("preview %s: status = %d, want 415", tc.name, resp.StatusCode)
		}
	}
}

// 14c. Unauthenticated preview redirects to /login (303), like /f/.
func TestPreviewUnauthRedirect(t *testing.T) {
	s := testStore(t)
	srv, _ := testAuthedServer(t, s)
	resp := getPreview(t, srv, "", "0123456789abcdef01234567")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauth preview status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("unauth preview Location = %q, want /login", loc)
	}
}

// --- v0.4.0: password reset logs out all sessions; 0 cancels; restart after update ---

func setTestUser(t *testing.T, s *Store, password string) string {
	t.Helper()
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUser("testuser", hash); err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateSession("testuser")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.SessionUser(token); !ok {
		t.Fatal("new session did not verify")
	}
	return token
}

// 15a. Reset path (SetUser + ClearSessions): the old session token
// stops working, the old password stops verifying, the new one works.
func TestPasswordResetClearsSessions(t *testing.T) {
	s := testStore(t)
	token := setTestUser(t, s, "oldpass123")

	newHash, err := hashPassword("newpass123")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUser("testuser", newHash); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearSessions(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.SessionUser(token); ok {
		t.Fatal("old session still valid after password reset")
	}
	_, hash, _ := s.GetUser()
	if verifyPassword(hash, "oldpass123") {
		t.Fatal("old password still verifies after reset")
	}
	if !verifyPassword(hash, "newpass123") {
		t.Fatal("new password does not verify after reset")
	}
}

// 15b. Typing "0" at a set-password prompt cancels (errCancelled) and
// changes nothing: not at the username prompt, not at the password prompt.
func TestSetPasswordCancelOnZero(t *testing.T) {
	// No user yet: "0" at the username prompt cancels, no user created.
	s := testStore(t)
	sc := bufio.NewScanner(strings.NewReader("0\n"))
	if err := setPasswordCLI(s, "", sc); !errors.Is(err, errCancelled) {
		t.Fatalf("username-prompt 0: err = %v, want errCancelled", err)
	}
	if has, _ := s.HasUser(); has {
		t.Fatal("cancelled reset still created a user")
	}

	// Existing user: "0" at the new-password prompt cancels, hash unchanged.
	s2 := testStore(t)
	_ = setTestUser(t, s2, "oldpass123")
	sc2 := bufio.NewScanner(strings.NewReader("0\n"))
	if err := setPasswordCLI(s2, "", sc2); !errors.Is(err, errCancelled) {
		t.Fatalf("password-prompt 0: err = %v, want errCancelled", err)
	}
	_, hash, _ := s2.GetUser()
	if !verifyPassword(hash, "oldpass123") {
		t.Fatal("cancelled reset changed the password")
	}
}

// 15c. A successful reset via setPasswordCLI logs out the old session.
func TestSetPasswordResetLogsOut(t *testing.T) {
	s := testStore(t)
	token := setTestUser(t, s, "oldpass123")
	sc := bufio.NewScanner(strings.NewReader("newpass123\nnewpass123\n"))
	if err := setPasswordCLI(s, "", sc); err != nil {
		t.Fatalf("setPasswordCLI: %v", err)
	}
	if _, ok := s.SessionUser(token); ok {
		t.Fatal("old session still valid after CLI password reset")
	}
	_, hash, _ := s.GetUser()
	if !verifyPassword(hash, "newpass123") {
		t.Fatal("new password does not verify after CLI reset")
	}
}

// 15d. promptCancel: "0" cancels, a value is returned as-is, an empty
// answer keeps the default.
func TestPromptCancelZero(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader("0\n"))
	if _, cancelled := promptCancel(sc, "Web port", "8080"); !cancelled {
		t.Fatal("promptCancel(\"0\") did not cancel")
	}
	sc = bufio.NewScanner(strings.NewReader("9090\n"))
	if v, cancelled := promptCancel(sc, "Web port", "8080"); cancelled || v != "9090" {
		t.Fatalf("promptCancel(\"9090\") = (%q, %v), want (\"9090\", false)", v, cancelled)
	}
	sc = bufio.NewScanner(strings.NewReader("\n"))
	if v, cancelled := promptCancel(sc, "Web port", "8080"); cancelled || v != "8080" {
		t.Fatalf("promptCancel(\"\") = (%q, %v), want (\"8080\", false)", v, cancelled)
	}
}

// 15e. The menu prints no farewell: "Bye" must not appear anywhere in
// the Go sources, and choosing 0 exits the menu silently.
func TestMenuNoBye(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || e.Name() == "main_test.go" {
			continue // this test file itself mentions "Bye" in its comment
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "Bye") {
			t.Fatalf("%s still contains \"Bye\"", e.Name())
		}
	}
}

// --- v0.4.0 (continued): reset while the server is running ---

// loginViaHTTP logs in over HTTP and returns the session cookie
// ("" when the login failed) and the login response status.
func loginViaHTTP(t *testing.T, port int, username, password string) (string, int) {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	resp, err := noRedirectClient().PostForm(fmt.Sprintf("http://127.0.0.1:%d/login", port), form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	cookie := resp.Header.Get("Set-Cookie")
	if i := strings.Index(cookie, ";"); i >= 0 {
		cookie = cookie[:i]
	}
	return cookie, resp.StatusCode
}

func apiItemsStatus(t *testing.T, port int, cookie string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/items", port), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func createUserViaCLI(t *testing.T, bin, dataDir, input string) {
	t.Helper()
	cmd := exec.Command(bin, "set-password", "--data-dir", dataDir)
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set-password: %v\n%s", err, out)
	}
}

// 16a. `reset-password` while the server is running: the CLI must stop
// the UI, reset, and restart it. Old cookie dies (401), old password
// fails, new password works, /health answers afterwards.
func TestResetPasswordWhileServerRunning(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	createUserViaCLI(t, bin, dataDir, "testuser\noldpass123\noldpass123\n")

	out, err := runBin(t, bin, "start", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	waitHealth(t, port, true)
	defer func() { _, _ = runBin(t, bin, "stop", "--data-dir", dataDir) }()

	oldCookie, code := loginViaHTTP(t, port, "testuser", "oldpass123")
	if code != http.StatusSeeOther || oldCookie == "" {
		t.Fatalf("login with old password: status %d, cookie %q", code, oldCookie)
	}
	if st := apiItemsStatus(t, port, oldCookie); st != http.StatusOK {
		t.Fatalf("old cookie /api/items: %d, want 200", st)
	}

	cmd := exec.Command(bin, "reset-password", "--data-dir", dataDir)
	cmd.Stdin = strings.NewReader("newpass123\nnewpass123\n")
	resetOut, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reset-password while running: %v\n%s", err, resetOut)
	}
	if !strings.Contains(string(resetOut), "logged out") {
		t.Fatalf("reset output missing logout notice: %q", resetOut)
	}
	waitHealthOrFail(t, port, true, "reset-password output:\n"+string(resetOut))

	if st := apiItemsStatus(t, port, oldCookie); st != http.StatusUnauthorized {
		t.Fatalf("old cookie after reset: %d, want 401", st)
	}
	if badCookie, _ := loginViaHTTP(t, port, "testuser", "oldpass123"); badCookie != "" {
		t.Fatal("old password still logs in after reset")
	}
	newCookie, _ := loginViaHTTP(t, port, "testuser", "newpass123")
	if newCookie == "" || apiItemsStatus(t, port, newCookie) != http.StatusOK {
		t.Fatal("new password does not log in after reset")
	}
}

// 16b. Menu option 8 while the server is running: same flow through
// the menu — stop, reset, restart, no farewell, server still up.
func TestMenuResetPasswordWhileRunning(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	createUserViaCLI(t, bin, dataDir, "testuser\noldpass123\noldpass123\n")

	out, err := runBin(t, bin, "start", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	waitHealth(t, port, true)
	defer func() { _, _ = runBin(t, bin, "stop", "--data-dir", dataDir) }()

	oldCookie, _ := loginViaHTTP(t, port, "testuser", "oldpass123")
	if oldCookie == "" {
		t.Fatal("could not log in before menu reset")
	}

	cmd := exec.Command(bin, "menu", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// 8 = reset password, new password twice, Enter at the pause, 0 = exit.
	if _, err := io.WriteString(stdin, "8\nnewpass123\nnewpass123\n\n0\n"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("menu exited with error: %v\noutput:\n%s", err, buf.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("menu did not exit\noutput:\n%s", buf.String())
	}
	menuOut := buf.String()
	if strings.Contains(menuOut, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", menuOut)
	}
	if !strings.Contains(menuOut, "Password reset for user") {
		t.Fatalf("menu reset output missing success message:\n%s", menuOut)
	}
	waitHealthOrFail(t, port, true, "menu output:\n"+menuOut)
	if st := apiItemsStatus(t, port, oldCookie); st != http.StatusUnauthorized {
		t.Fatalf("old cookie after menu reset: %d, want 401", st)
	}
	newCookie, _ := loginViaHTTP(t, port, "testuser", "newpass123")
	if newCookie == "" || apiItemsStatus(t, port, newCookie) != http.StatusOK {
		t.Fatal("new password does not log in after menu reset")
	}
}

// v0.5.0: a --port flag or LOADINME_PORT env override is one-off and
// must never be written back to config.json. v0.4.0 clobbered it:
// serve saved the config after the override was applied, so an
// update that started the UI on the 8080 default permanently
// overwrote the user's saved port 5234. Regression test: the saved
// port stays 5234 through a flag override, an env override, and a
// plain start that must keep serving on the saved port.
func TestPortOverrideDoesNotClobberSavedPort(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	const savedPort = 5234

	savedPortInConfig := func() int {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
		if err != nil {
			t.Fatalf("read config.json: %v", err)
		}
		var cfg Config
		if err := json.Unmarshal(b, &cfg); err != nil {
			t.Fatalf("parse config.json: %v", err)
		}
		return cfg.Port
	}
	stop := func() {
		t.Helper()
		if out, err := runBin(t, bin, "stop", "--data-dir", dataDir); err != nil {
			t.Fatalf("stop: %v\n%s", err, out)
		}
	}

	// Save port 5234 the way the menu does (option 5).
	if err := saveConfig(Config{Port: savedPort, DataDir: dataDir}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	// 1. --port override: the UI serves on the override port, but
	// config.json must still say 5234 afterwards.
	override := freePort(t)
	if override == savedPort {
		override = freePort(t)
	}
	out, err := runBin(t, bin, "start", "--port", strconv.Itoa(override), "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start with --port override: %v\n%s", err, out)
	}
	waitHealth(t, override, true)
	if got := savedPortInConfig(); got != savedPort {
		t.Fatalf("config port after --port %d start = %d, want %d (override clobbered the saved port)", override, got, savedPort)
	}
	stop()
	waitHealth(t, override, false)

	// 2. LOADINME_PORT override: same — serves on the env port,
	// saved port stays 5234.
	t.Setenv("LOADINME_PORT", strconv.Itoa(override))
	out, err = runBin(t, bin, "start", "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start with LOADINME_PORT override: %v\n%s", err, out)
	}
	waitHealth(t, override, true)
	if got := savedPortInConfig(); got != savedPort {
		t.Fatalf("config port after LOADINME_PORT=%d start = %d, want %d (override clobbered the saved port)", override, got, savedPort)
	}
	stop()
	waitHealth(t, override, false)

	// 3. No override: the UI must serve on the saved port 5234, and
	// the config must still say 5234.
	t.Setenv("LOADINME_PORT", "")
	out, err = runBin(t, bin, "start", "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start without override: %v\n%s", err, out)
	}
	waitHealth(t, savedPort, true)
	if got := savedPortInConfig(); got != savedPort {
		t.Fatalf("config port after plain start = %d, want %d", got, savedPort)
	}
	stop()
	waitHealth(t, savedPort, false)
}

// v0.5.0: install.sh must read the saved port from config.json even
// when python3 is missing (v0.4.0 used python3 only, so the parse
// silently failed and the update started the UI on 8080). This runs
// the actual saved_port() function from install.sh — extracted
// verbatim, not a copy — with python3 hidden from PATH.
// v0.5.0: install.sh must read the saved port from config.json even
// when python3 is missing (v0.4.0 used python3 only, so the parse
// silently failed and the update started the UI on 8080). This runs
// the actual saved_port() function from install.sh — extracted
// verbatim, not a copy — with python3 hidden from PATH.
func TestInstallScriptSavedPortWithoutPython3(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "saved_port()") {
		t.Fatal("install.sh is missing the saved_port() function")
	}
	if strings.Contains(s, `python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('port') or 8080)"`) {
		t.Fatal("install.sh still uses the python3-only port parse that falls back to 8080")
	}
	// Extract saved_port() verbatim from install.sh (up to its
	// closing brace on its own line) and run it.
	lines := strings.Split(s, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "saved_port() {") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("could not find saved_port() in install.sh")
	}
	end := -1
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatal("could not find the end of saved_port() in install.sh")
	}
	fn := strings.Join(lines[start:end+1], "\n")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{\n  \"port\": 5234,\n  \"dataDir\": \""+dir+"\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run saved_port with a minimal PATH that has bash/grep/head
	// but NO python3, so only the grep fallback can work.
	toolDir := t.TempDir()
	for _, tool := range []string{"bash", "grep", "head"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("LookPath %s: %v", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(toolDir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	runSavedPort := func(pathEnv, cfg string) string {
		t.Helper()
		script := fn + "\nsaved_port \"$1\"\n"
		cmd := exec.Command(toolDir+"/bash", "-c", script, "test", cfg)
		cmd.Env = []string{"PATH=" + pathEnv}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("saved_port run failed (PATH=%s): %v\n%s", pathEnv, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	if got := runSavedPort(toolDir, cfgPath); got != "5234" {
		t.Fatalf("saved_port without python3 = %q, want 5234", got)
	}
	// With the normal PATH (python3 present) it must also say 5234.
	if got := runSavedPort(os.Getenv("PATH"), cfgPath); got != "5234" {
		t.Fatalf("saved_port with python3 = %q, want 5234", got)
	}
	// Missing file: 8080, and only then.
	if got := runSavedPort(toolDir, filepath.Join(dir, "nope.json")); got != "8080" {
		t.Fatalf("saved_port missing file = %q, want 8080", got)
	}
	// Config with no port key: 8080.
	noPortPath := filepath.Join(dir, "noport.json")
	if err := os.WriteFile(noPortPath, []byte("{\n  \"dataDir\": \""+dir+"\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := runSavedPort(toolDir, noPortPath); got != "8080" {
		t.Fatalf("saved_port no-port config = %q, want 8080", got)
	}
}

// v0.5.0 companion to TestPortOverrideDoesNotClobberSavedPort: on a
// FRESH data dir (no config.json yet) a --port override IS persisted,
// because later commands (menu, reset-password, restart) load the
// port from config.json — without it they would restart the UI on
// the 8080 default instead of the port it was running on. (This is
// what TestResetPasswordWhileServerRunning relies on.)
func TestFirstRunPersistsOverridePort(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)

	out, err := runBin(t, bin, "start", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	waitHealth(t, port, true)
	defer func() {
		_, _ = runBin(t, bin, "stop", "--data-dir", dataDir)
	}()
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatalf("config.json was not created on first run: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	if cfg.Port != port {
		t.Fatalf("first-run config port = %d, want %d", cfg.Port, port)
	}
}

// --- v0.6.0: Domain & SSL in one menu option (6), with revoke ---

// runMenuInput starts `loadinme menu`, feeds it input, waits for it
// to exit, and returns its combined output. extraEnv is passed to
// the menu child process (e.g. LOADINME_LETSENCRYPT_DIR to point the
// certificate directory at a temp dir).
func runMenuInput(t *testing.T, bin, dataDir string, port int, input string, extraEnv ...string) string {
	t.Helper()
	cmd := exec.Command(bin, "menu", "--port", strconv.Itoa(port), "--data-dir", dataDir)
	cmd.Env = append(os.Environ(), extraEnv...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stdin, input); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("menu exited with error: %v\noutput:\n%s", err, buf.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("menu did not exit\noutput:\n%s", buf.String())
	}
	return buf.String()
}

// certbotInstalled reports whether certbot is on PATH. The SSL tests
// that expect the "certbot is not installed" path skip when it is.
func certbotInstalled() bool {
	_, err := exec.LookPath("certbot")
	return err == nil
}

// writeFakeCertFolder writes a self-signed certificate (and a dummy
// private key) for domains into <base>/live/<folder>/, the way certbot
// lays certificates out. folder may differ from the domains the
// certificate covers (e.g. example.com-0001). It returns the
// certificate's expiry date.
func writeFakeCertFolder(t *testing.T, base, folder string, domains []string, notAfter time.Time) time.Time {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cn := folder
	if len(domains) > 0 {
		cn = domains[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "live", folder)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), []byte("fake key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return notAfter
}

// writeFakeCert writes a self-signed certificate (and a dummy private
// key) for domain into <base>/live/<domain>/, the way certbot lays
// certificates out. It returns the certificate's expiry date.
func writeFakeCert(t *testing.T, base, domain string, notAfter time.Time) time.Time {
	t.Helper()
	return writeFakeCertFolder(t, base, domain, []string{domain}, notAfter)
}

// Get SSL with certbot absent: the menu must print the
// certbot-not-installed guidance, change no SSL setting, and return
// to the menu. (The domain is saved — that is the point of submenu 1
// — but TLS stays off and no certificate is configured.)
func TestDomainSSLGetNoCertbot(t *testing.T) {
	if certbotInstalled() {
		t.Skip("certbot is installed; this test needs it absent")
	}
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	// 6 = Domain & SSL, 1 = Get SSL, domain, email, 0 = back to the
	// main menu, Enter at the pause, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n1\nexample.com\nuser@example.com\n0\n\n0\n")
	if !strings.Contains(out, "certbot is not installed") {
		t.Fatalf("missing certbot guidance:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatalf("config.json was not written: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	if cfg.Domain != "example.com" {
		t.Fatalf("saved domain = %q, want example.com", cfg.Domain)
	}
	if cfg.TLSEnabled || cfg.CertFile != "" || cfg.KeyFile != "" {
		t.Fatalf("SSL changed without certbot: TLSEnabled=%v cert=%q key=%q", cfg.TLSEnabled, cfg.CertFile, cfg.KeyFile)
	}
}

// List certificates with an empty letsencrypt dir: the submenu must
// say plainly that none were found (and name the directory it
// checked), then 0 returns to the main menu and 0 exits silently.
func TestDomainSSLListNone(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	leDir := t.TempDir() // no live/ inside: no certificates at all
	// 6 = Domain & SSL, 2 = List & revoke, 0 = back, Enter, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n2\n0\n\n0\n", "LOADINME_LETSENCRYPT_DIR="+leDir)
	if !strings.Contains(out, "No certificates found") {
		t.Fatalf("missing 'no certificates' message:\n%s", out)
	}
	if !strings.Contains(out, filepath.Join(leDir, "live")) {
		t.Fatalf("list did not name the directory checked:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
}

// List a fake self-signed certificate and "revoke" it with certbot
// absent: the menu must show the certificate with its expiry date,
// then print the manual revoke commands instead of deleting anything,
// and leave the config untouched.
func TestDomainSSLRevokeFakeCertNoCertbot(t *testing.T) {
	if certbotInstalled() {
		t.Skip("certbot is installed; this test needs it absent")
	}
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	leDir := t.TempDir()
	expiry := writeFakeCert(t, leDir, "example.com", time.Now().Add(90*24*time.Hour))
	// 6 = Domain & SSL, 2 = List & revoke, domain, y = confirm,
	// 0 = back, Enter, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n2\nexample.com\ny\n0\n\n0\n", "LOADINME_LETSENCRYPT_DIR="+leDir)
	if !strings.Contains(out, "example.com") || !strings.Contains(out, "expires "+expiry.Format("2006-01-02")) {
		t.Fatalf("list did not show the certificate with its expiry:\n%s", out)
	}
	if !strings.Contains(out, "certbot is not installed") || !strings.Contains(out, "certbot revoke --cert-path") {
		t.Fatalf("missing manual revoke commands:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
	// Nothing was deleted and the config was not touched.
	if _, err := os.Stat(filepath.Join(leDir, "live", "example.com", "fullchain.pem")); err != nil {
		t.Fatalf("certificate was deleted without certbot: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "config.json")); err == nil {
		var cfg Config
		if err := json.Unmarshal(b, &cfg); err == nil && (cfg.TLSEnabled || cfg.CertFile != "" || cfg.KeyFile != "") {
			t.Fatalf("revoke changed the config without certbot: %+v", cfg)
		}
	}
}

// Submenu 0 returns to the main menu (it must NOT exit the app):
// after 6 then 0, the main menu is printed again, and a second 0
// exits silently with no farewell.
func TestDomainSSLSubmenuBackToMain(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	// 6 = Domain & SSL, 0 = back to main menu, Enter, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n0\n\n0\n")
	if !strings.Contains(out, "Domain & SSL") {
		t.Fatalf("submenu never opened:\n%s", out)
	}
	if strings.Count(out, "Choose [0-11]") < 2 {
		t.Fatalf("main menu was not shown again after leaving the submenu:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
}

// --- v0.6.1: certificates matched by covered domain, not folder name ---

// A certificate stored under a different folder name than its domain
// must still be listed under the domain it covers, and revoking by
// that domain must find it (certbot absent: manual commands, nothing
// deleted, config untouched).
func TestDomainSSLListAndRevokeByCoveredDomain(t *testing.T) {
	if certbotInstalled() {
		t.Skip("certbot is installed; this test needs it absent")
	}
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	leDir := t.TempDir()
	expiry := writeFakeCertFolder(t, leDir, "other-0001", []string{"demo.example.com"}, time.Now().Add(90*24*time.Hour))
	// 6 = Domain & SSL, 2 = List & revoke, domain, y = confirm,
	// 0 = back, Enter, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n2\ndemo.example.com\ny\n0\n\n0\n", "LOADINME_LETSENCRYPT_DIR="+leDir)
	if !strings.Contains(out, "demo.example.com") || !strings.Contains(out, "expires "+expiry.Format("2006-01-02")) {
		t.Fatalf("list did not show the certificate under its domain:\n%s", out)
	}
	if !strings.Contains(out, "other-0001") {
		t.Fatalf("list did not show the lineage name:\n%s", out)
	}
	if !strings.Contains(out, "certbot is not installed") || !strings.Contains(out, "certbot revoke --cert-path") {
		t.Fatalf("missing manual revoke commands:\n%s", out)
	}
	if !strings.Contains(out, filepath.Join("live", "other-0001", "cert.pem")) {
		t.Fatalf("revoke commands did not use the lineage path:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(leDir, "live", "other-0001", "fullchain.pem")); err != nil {
		t.Fatalf("certificate was deleted without certbot: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "config.json")); err == nil {
		var cfg Config
		if err := json.Unmarshal(b, &cfg); err == nil && (cfg.TLSEnabled || cfg.CertFile != "" || cfg.KeyFile != "") {
			t.Fatalf("revoke changed the config without certbot: %+v", cfg)
		}
	}
}

// Get SSL for a domain whose certificate lives under another folder
// name must offer to enable HTTPS with it instead of running certbot.
func TestDomainSSLGetUsesCoveringCert(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	leDir := t.TempDir()
	writeFakeCertFolder(t, leDir, "other-0001", []string{"demo.example.com"}, time.Now().Add(90*24*time.Hour))
	// 6 = Domain & SSL, 1 = Get SSL, domain, y = enable, 0 = back,
	// Enter, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n1\ndemo.example.com\ny\n0\n\n0\n", "LOADINME_LETSENCRYPT_DIR="+leDir)
	if !strings.Contains(out, "Certificate already found") {
		t.Fatalf("Get SSL did not find the covering certificate:\n%s", out)
	}
	if strings.Contains(out, "Running certbot") {
		t.Fatalf("Get SSL ran certbot for a domain that already has a certificate:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatalf("config.json was not written: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	if !cfg.TLSEnabled {
		t.Fatalf("TLS was not enabled: %+v", cfg)
	}
	want := filepath.Join(leDir, "live", "other-0001", "fullchain.pem")
	if cfg.CertFile != want {
		t.Fatalf("cert file = %q, want %q", cfg.CertFile, want)
	}
}

// Several certificates covering one domain: Get SSL lists them and
// lets the user pick one by number.
func TestDomainSSLGetPicksAmongCoveringCerts(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	leDir := t.TempDir()
	writeFakeCertFolder(t, leDir, "demo.example.com-0001", []string{"demo.example.com"}, time.Now().Add(30*24*time.Hour))
	writeFakeCertFolder(t, leDir, "demo.example.com-0002", []string{"demo.example.com"}, time.Now().Add(60*24*time.Hour))
	// 6, 1, domain, pick 2, y = enable, 0 = back, Enter, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n1\ndemo.example.com\n2\ny\n0\n\n0\n", "LOADINME_LETSENCRYPT_DIR="+leDir)
	if !strings.Contains(out, "More than one certificate covers") {
		t.Fatalf("Get SSL did not list the covering certificates:\n%s", out)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatalf("config.json was not written: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	want := filepath.Join(leDir, "live", "demo.example.com-0002", "fullchain.pem")
	if cfg.CertFile != want {
		t.Fatalf("cert file = %q, want the picked certificate %q", cfg.CertFile, want)
	}
}

// Submenu 3 clears a saved domain (and switches SSL off when it was
// on): the config ends up with no domain and TLS off, and the menu
// afterwards shows no domain on top.
func TestDomainSSLClearSavedDomain(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	leDir := t.TempDir()
	writeFakeCertFolder(t, leDir, "stale.example.com", []string{"stale.example.com"}, time.Now().Add(90*24*time.Hour))
	seed := Config{
		Port:       port,
		DataDir:    dataDir,
		Domain:     "stale.example.com",
		TLSEnabled: true,
		CertFile:   filepath.Join(leDir, "live", "stale.example.com", "fullchain.pem"),
		KeyFile:    filepath.Join(leDir, "live", "stale.example.com", "privkey.pem"),
	}
	b, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	// 6 = Domain & SSL, 3 = Clear saved domain, 0 = back, Enter,
	// 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n3\n0\n\n0\n", "LOADINME_LETSENCRYPT_DIR="+leDir)
	if !strings.Contains(out, "Saved domain cleared") {
		t.Fatalf("missing clear confirmation:\n%s", out)
	}
	if !strings.Contains(out, "SSL switched off") {
		t.Fatalf("clear did not say SSL was switched off:\n%s", out)
	}
	if !strings.Contains(out, "Domain: (none set)") {
		t.Fatalf("menu still shows a domain after clearing:\n%s", out)
	}
	if strings.Contains(out, "Bye") {
		t.Fatalf("menu printed a farewell:\n%s", out)
	}
	b, err = os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatalf("config.json was not written: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	if cfg.Domain != "" {
		t.Fatalf("saved domain = %q, want empty", cfg.Domain)
	}
	if cfg.TLSEnabled || cfg.CertFile != "" || cfg.KeyFile != "" {
		t.Fatalf("SSL was not switched off: %+v", cfg)
	}
}
