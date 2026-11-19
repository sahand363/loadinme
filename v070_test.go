package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	"sync"
	"testing"
	"time"
)

// --- v0.7.0 helpers ---

// writeCertPair writes a real self-signed certificate + EC key for
// domain into dir/fullchain.pem and dir/privkey.pem.
func writeCertPair(t *testing.T, dir, domain string, serial int64, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := marshalECKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func readConfigFile(t *testing.T, dataDir string) Config {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeConfigFile(t *testing.T, cfg Config) {
	t.Helper()
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- certificate reloader ---

func TestCertReloaderPicksUpNewCertWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "demo.example.com", 1, time.Now().Add(40*24*time.Hour))
	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	r.interval = time.Minute
	c, _ := r.GetCertificate(nil)
	if c.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("serial = %v, want 1", c.Leaf.SerialNumber)
	}
	// Renewal writes new files (later mtime).
	time.Sleep(20 * time.Millisecond)
	writeCertPair(t, dir, "demo.example.com", 2, time.Now().Add(90*24*time.Hour))
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)
	// Within the interval: still the old one (files are checked at
	// most once a minute).
	now = now.Add(30 * time.Second)
	c, _ = r.GetCertificate(nil)
	if c.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("reloaded before the interval passed")
	}
	now = now.Add(31 * time.Second)
	c, _ = r.GetCertificate(nil)
	if c.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("serial after interval = %v, want 2 (renewed cert not picked up)", c.Leaf.SerialNumber)
	}
}

func TestCertReloaderKeepsOldCertOnBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "demo.example.com", 7, time.Now().Add(40*24*time.Hour))
	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)
	now = now.Add(2 * time.Minute)
	c, _ := r.GetCertificate(nil)
	if c == nil || c.Leaf.SerialNumber.Int64() != 7 {
		t.Fatal("a broken certificate file replaced the working one")
	}
}

// An old config pointing at certbot's /etc/letsencrypt layout still
// serves HTTPS (existing installs must not break).
func TestServeLegacyLetsEncryptPaths(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	leDir := t.TempDir()
	certPath, keyPath := writeCertPair(t, filepath.Join(leDir, "live", "old.example.com"), "old.example.com", 5, time.Now().Add(50*24*time.Hour))
	port := freePort(t)
	writeConfigFile(t, Config{Port: port, DataDir: dataDir, Domain: "old.example.com", TLSEnabled: true, CertFile: certPath, KeyFile: keyPath})
	cmd := exec.Command(bin, "serve", "--data-dir", dataDir)
	cmd.Env = append(os.Environ(), "LOADINME_LETSENCRYPT_DIR="+leDir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", port))
		if err == nil {
			serial := resp.TLS.PeerCertificates[0].SerialNumber.Int64()
			resp.Body.Close()
			if serial != 5 {
				t.Fatalf("served serial %d, want 5", serial)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https never came up: %v\n%s", err, out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	// ssl status calls it a certbot certificate and suggests re-issuing.
	stCmd := exec.Command(bin, "ssl", "status", "--data-dir", dataDir)
	stCmd.Env = append(os.Environ(), "LOADINME_LETSENCRYPT_DIR="+leDir)
	st, _ := stCmd.CombinedOutput()
	if !strings.Contains(string(st), "certbot") || !strings.Contains(string(st), "re-issue") {
		t.Fatalf("status did not flag the certbot certificate:\n%s", st)
	}
}

// --- setup code ---

func TestSetupRequiresCode(t *testing.T) {
	s := testStore(t)
	srv := httptest.NewServer(newRouter(s, Config{DataDir: s.DataDir()}))
	defer srv.Close()
	c := noRedirectClient()
	resp, err := c.Get(srv.URL + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `name="code"`) {
		t.Fatal("setup page has no setup-code field")
	}
	code := readSetupCode(s.DataDir())
	if len(normalizeSetupCode(code)) != 8 {
		t.Fatalf("setup code %q not created", code)
	}
	fi, err := os.Stat(setupCodePath(s.DataDir()))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("setup-code file mode: %v %v", fi, err)
	}
	post := func(code string) *http.Response {
		resp, err := c.PostForm(srv.URL+"/setup", url.Values{"code": {code}, "username": {"me"}, "password": {"longpassword"}, "confirm": {"longpassword"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := post(""); !strings.Contains(r.Header.Get("Location"), "error=code") {
		t.Fatalf("no code: Location = %q", r.Header.Get("Location"))
	}
	if r := post("WRONG-CODE"); !strings.Contains(r.Header.Get("Location"), "error=code") {
		t.Fatalf("wrong code: Location = %q", r.Header.Get("Location"))
	}
	if has, _ := s.HasUser(); has {
		t.Fatal("a user was created without the setup code")
	}
	// Lower case, no dash: still accepted.
	r := post(strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if r.Header.Get("Location") != "/" {
		t.Fatalf("right code: Location = %q", r.Header.Get("Location"))
	}
	if has, _ := s.HasUser(); !has {
		t.Fatal("user not created with the right code")
	}
	if _, err := os.Stat(setupCodePath(s.DataDir())); !os.IsNotExist(err) {
		t.Fatal("setup-code file not removed after setup")
	}
}

func TestSetupRejectsShortPassword(t *testing.T) {
	s := testStore(t)
	srv := httptest.NewServer(newRouter(s, Config{DataDir: s.DataDir()}))
	defer srv.Close()
	code, err := ensureSetupCode(s.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noRedirectClient().PostForm(srv.URL+"/setup", url.Values{"code": {code}, "username": {"me"}, "password": {"1234567"}, "confirm": {"1234567"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=1") {
		t.Fatalf("7-char password accepted: %q", resp.Header.Get("Location"))
	}
	if has, _ := s.HasUser(); has {
		t.Fatal("user created with a 7-character password")
	}
}

func TestServePrintsSetupCodeAndMenuShowsIt(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	if out, err := runBin(t, bin, "start", "--port", strconv.Itoa(port), "--data-dir", dataDir); err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = runBin(t, bin, "stop", "--data-dir", dataDir) })
	code := readSetupCode(dataDir)
	if code == "" {
		t.Fatal("serve did not create a setup code")
	}
	menu := runMenuInput(t, bin, dataDir, port, "0\n")
	if !strings.Contains(menu, "Setup code: "+code) {
		t.Fatalf("menu header does not show the setup code:\n%s", menu)
	}
}

// --- passwords ---

func TestChangePasswordMinLength(t *testing.T) {
	s := testStore(t)
	srv, cookie := testAuthedServer(t, s)
	body := strings.NewReader(`{"currentPassword":"testpass","newPassword":"short12"}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/change-password", body)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("7-char new password: status %d, want 400", resp.StatusCode)
	}
	_, hash, _ := s.GetUser()
	if !verifyPassword(hash, "testpass") {
		t.Fatal("password changed despite being too short")
	}
}

func TestCLIPasswordMinLength(t *testing.T) {
	s := testStore(t)
	sc := bufio.NewScanner(strings.NewReader("me\nshort\nshort\n"))
	err := setPasswordCLI(s, "", sc)
	if err == nil || !strings.Contains(err.Error(), "at least 8") {
		t.Fatalf("err = %v, want min-length error", err)
	}
}

// Existing short passwords keep working (only NEW passwords need 8).
func TestExistingShortPasswordStillLogsIn(t *testing.T) {
	s := testStore(t)
	hash, _ := hashPassword("abcd")
	_ = s.SetUser("old", hash)
	srv := httptest.NewServer(newRouter(s, Config{DataDir: s.DataDir()}))
	defer srv.Close()
	resp, err := noRedirectClient().PostForm(srv.URL+"/login", url.Values{"username": {"old"}, "password": {"abcd"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("old 4-char password no longer logs in: %q", resp.Header.Get("Location"))
	}
}

// --- login rate limit ---

func TestLoginRateLimitLocksAfterFiveFailures(t *testing.T) {
	s := testStore(t)
	hash, _ := hashPassword("rightpassword")
	_ = s.SetUser("me", hash)
	srv := httptest.NewServer(newRouter(s, Config{DataDir: s.DataDir()}))
	defer srv.Close()
	c := noRedirectClient()
	login := func(pw string) string {
		resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {"me"}, "password": {pw}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("Location")
	}
	for i := 1; i <= 4; i++ {
		if loc := login("wrong"); loc != "/login?error=1" {
			t.Fatalf("failure %d: Location %q", i, loc)
		}
	}
	if loc := login("wrong"); !strings.Contains(loc, "error=locked") || !strings.Contains(loc, "wait=60") {
		t.Fatalf("5th failure did not lock for 60s: %q", loc)
	}
	// Even the right password is refused while locked.
	if loc := login("rightpassword"); !strings.Contains(loc, "error=locked") {
		t.Fatalf("right password accepted during lockout: %q", loc)
	}
}

func TestLoginLimiterBackoffDoublesAndCaps(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	var waits []time.Duration
	for round := 0; round < 7; round++ {
		var w time.Duration
		for i := 0; i < loginMaxFailures; i++ {
			w = l.fail("1.2.3.4")
		}
		waits = append(waits, w)
		now = now.Add(w + time.Second)
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("lockouts = %v, want %v", waits, want)
		}
	}
	l.succeed("1.2.3.4")
	if _, locked := l.blocked("1.2.3.4"); locked {
		t.Fatal("still locked after success")
	}
	if w := l.fail("1.2.3.4"); w != 0 {
		t.Fatal("record not cleared by a successful login")
	}
}

func TestClientIPTrustsForwardedOnlyFromLoopback(t *testing.T) {
	r := httptest.NewRequest("POST", "/login", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("spoofed XFF from a remote client was believed: %s", got)
	}
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.7")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("XFF via local proxy: got %s, want the right-most entry", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := clientIP(r); got != "127.0.0.1" {
		t.Fatalf("loopback without XFF: %s", got)
	}
}

// --- Secure cookie ---

func TestSessionCookieSecureOnlyOverTLS(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		s := testStore(t)
		hash, _ := hashPassword("rightpassword")
		_ = s.SetUser("me", hash)
		h := newRouter(s, Config{DataDir: s.DataDir(), TLSEnabled: useTLS})
		var srv *httptest.Server
		if useTLS {
			srv = httptest.NewTLSServer(h)
		} else {
			srv = httptest.NewServer(h)
		}
		c := srv.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {"me"}, "password": {"rightpassword"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		sc := resp.Header.Get("Set-Cookie")
		if !strings.Contains(sc, sessionCookie+"=") {
			t.Fatalf("tls=%v: no session cookie", useTLS)
		}
		if strings.Contains(sc, "Secure") != useTLS {
			t.Fatalf("tls=%v: Set-Cookie = %q", useTLS, sc)
		}
		srv.Close()
	}
}

// --- upload body cap ---

func TestUploadBodyCappedBeforeParsing(t *testing.T) {
	s := testStore(t)
	if err := s.SaveSettings(Settings{MaxItems: 10, MaxFileMB: 1, DefaultExpiryHours: 24}); err != nil {
		t.Fatal(err)
	}
	srv, cookie := testAuthedServer(t, s)
	// 1 MB limit + 8 MB room: a 12 MB body must be cut off.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		fw, _ := mw.CreateFormFile("file", "big.bin")
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for i := 0; i < 12; i++ {
			if _, err := fw.Write(chunk); err != nil {
				break
			}
		}
		_ = mw.Close()
		_ = pw.Close()
	}()
	req, _ := http.NewRequest("POST", srv.URL+"/api/upload", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Cookie", cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// The server answers 413 and closes the connection while the
		// client is still sending; some platforms surface that as a
		// write error instead of the response. Either way nothing
		// may have been stored.
		t.Logf("client saw a transport error (server cut the body off): %v", err)
		if entries, _ := os.ReadDir(s.UploadsDir()); len(entries) != 0 {
			t.Fatalf("upload left %d files behind", len(entries))
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 413: %s", resp.StatusCode, b)
	}
	// Nothing was left in uploads/.
	entries, _ := os.ReadDir(s.UploadsDir())
	if len(entries) != 0 {
		t.Fatalf("upload left %d files behind", len(entries))
	}
}

// --- nginx config inspection ---

const sampleNginxDump = `nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/nginx.conf:
http {
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    upstream app { server 127.0.0.1:8080; }
}

# configuration file /etc/nginx/sites-enabled/default:
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    # server_name commented.example.com;
    location / { return 444; }
}

# configuration file /etc/nginx/sites-enabled/blog:
server {
    listen 443 ssl;
    server_name blog.example.com;
}
server {
    server_name blog.example.com www.blog.example.com;
    location / { return 301 https://$host$request_uri; }
}

# configuration file /etc/nginx/sites-enabled/shop:
server {
    listen 0.0.0.0:80;
    server_name shop.example.com;
    location /.well-known/acme-challenge/ { proxy_pass http://127.0.0.1:41580; }
    location / { proxy_pass http://app; }
}

# configuration file /etc/nginx/sites-enabled/tls-only:
server {
    listen 8443 ssl;
    server_name files.example.com;
}

# configuration file /etc/nginx/conf.d/loadinme-acme-files.example.com.conf:
server {
    listen 80;
    server_name files.example.com;
}
`

func TestFindNginxBlockFor(t *testing.T) {
	if _, found := findNginxBlockFor(sampleNginxDump, "files.example.com"); found {
		t.Fatal("files.example.com: matched a port-8443 block or LoadInMe's own snippet")
	}
	if _, found := findNginxBlockFor(sampleNginxDump, "commented.example.com"); found {
		t.Fatal("matched a commented-out server_name")
	}
	blk, found := findNginxBlockFor(sampleNginxDump, "www.blog.example.com")
	if !found || blk.File != "/etc/nginx/sites-enabled/blog" {
		t.Fatalf("blog block (no listen = port 80) not found: %+v", blk)
	}
	if blk.hasChallengeProxy() {
		t.Fatal("blog block has no challenge proxy")
	}
	shop, found := findNginxBlockFor(sampleNginxDump, "SHOP.example.com")
	if !found || !shop.hasChallengeProxy() {
		t.Fatalf("shop block with the challenge line not recognised: %+v", shop)
	}
	if n := len(parseNginxServers(sampleNginxDump)); n != 6 {
		t.Fatalf("parsed %d server blocks, want 6 (upstream 'server x;' is not a block)", n)
	}
}

func TestNginxListensOn80(t *testing.T) {
	cases := map[string]bool{
		"80": true, "80 default_server": true, "[::]:80": true, "0.0.0.0:80": true,
		"1.2.3.4": true, "443 ssl": false, "[::]:443 ssl": false, "8080": false, "unix:/run/x.sock": false,
	}
	for l, want := range cases {
		if got := (nginxServer{Listens: []string{l}}).listensOn80(); got != want {
			t.Errorf("listen %q: listensOn80 = %v, want %v", l, got, want)
		}
	}
	if !(nginxServer{}).listensOn80() {
		t.Error("no listen directive should mean port 80")
	}
}

func TestNginxSnippetContent(t *testing.T) {
	sn := nginxSnippet("files.example.com", 45678, true)
	for _, want := range []string{"listen 80;", "listen [::]:80;", "server_name files.example.com;", "location /.well-known/acme-challenge/", "proxy_pass http://127.0.0.1:45678;"} {
		if !strings.Contains(sn, want) {
			t.Fatalf("snippet lacks %q:\n%s", want, sn)
		}
	}
	if strings.Contains(nginxSnippet("a.b", 1, false), "[::]") {
		t.Fatal("IPv4-only snippet listens on IPv6")
	}
	if !strings.Contains(nginxChallengeLine(), "proxy_pass http://127.0.0.1:41580;") {
		t.Fatalf("challenge line: %s", nginxChallengeLine())
	}
}

func TestUnitFromCgroup(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/apache2.service\n":                                  "apache2.service",
		"12:pids:/system.slice/nginx.service\n0::/system.slice/nginx.service": "nginx.service",
		"0::/user.slice/user-1000.slice/session-3.scope\n":                    "",
		"0::/system.slice/docker-abc.scope\n":                                 "",
	}
	for in, want := range cases {
		if got := unitFromCgroup(in); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListeningOnSeesListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	l, _, ok := listeningOn(port)
	if !ok {
		ln.Close()
		t.Skip("no /proc/net/tcp here")
	}
	if !l {
		t.Fatal("listeningOn missed an open listener")
	}
	ln.Close()
	if l, _, _ := listeningOn(port); l {
		t.Fatal("listeningOn still sees a closed listener")
	}
}

// --- challenge server, preflight, Cloudflare, timer ---

func TestChallengeServerServesOnlyTokens(t *testing.T) {
	cs, err := startChallengeServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	cs.set("tok123", "tok123.thumb")
	base := fmt.Sprintf("http://127.0.0.1:%d", cs.port())
	resp, err := http.Get(base + "/.well-known/acme-challenge/tok123")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "tok123.thumb" {
		t.Fatalf("token: %d %q", resp.StatusCode, b)
	}
	for _, p := range []string{"/.well-known/acme-challenge/other", "/", "/health"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s: status %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestPreflightLocalhostPointsHere(t *testing.T) {
	t.Setenv("LOADINME_PUBLIC_IP", "203.0.113.50")
	pf := preflight("localhost")
	if !pf.OK {
		t.Fatalf("localhost should point here: %v", pf.Lines)
	}
	if pf := preflight("does-not-exist.invalid"); pf.OK || !strings.Contains(strings.Join(pf.Lines, " "), "does not resolve") {
		t.Fatalf("unresolvable domain: %+v", pf)
	}
	if !isCloudflareIP(net.ParseIP("104.16.1.1")) || isCloudflareIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("Cloudflare range check wrong")
	}
}

func TestCloudflareDNSClient(t *testing.T) {
	var mu sync.Mutex
	var created, deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"message":"Invalid API Token"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":{"status":"active"}}`)
	})
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") == "example.com" {
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone1","name":"example.com"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":[]}`)
	})
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		created = append(created, fmt.Sprint(body["type"], " ", body["name"], " ", body["content"]))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec9"}}`)
	})
	mux.HandleFunc("/zones/zone1/dns_records/rec9", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deleted = append(deleted, r.Method)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec9"}}`)
	})
	api := httptest.NewServer(mux)
	defer api.Close()
	t.Setenv("LOADINME_CLOUDFLARE_API", api.URL)
	ctx := context.Background()
	if err := newCloudflareDNS("bad", nil).Verify(ctx); err == nil || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Fatalf("bad token: %v", err)
	}
	cf := newCloudflareDNS("good", nil)
	if err := cf.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	cf.resolver = "127.0.0.1:1" // nothing there: visibility check gives up fast
	done := make(chan struct{})
	var cleanup func()
	var perr error
	go func() {
		c2, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		cleanup, perr = cf.Present(c2, "files.sub.example.com", "VALUE")
		close(done)
	}()
	<-done
	if perr != nil {
		t.Fatal(perr)
	}
	cleanup()
	if len(created) != 1 || created[0] != "TXT _acme-challenge.files.sub.example.com VALUE" {
		t.Fatalf("created = %v", created)
	}
	if len(deleted) != 1 || deleted[0] != "DELETE" {
		t.Fatalf("deleted = %v", deleted)
	}
	// Token file is private.
	dataDir := t.TempDir()
	if err := saveCloudflareToken(dataDir, " tok \n"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(cloudflareTokenPath(dataDir))
	if fi.Mode().Perm() != 0o600 || readCloudflareToken(dataDir) != "tok" {
		t.Fatalf("token file mode %v / content %q", fi.Mode().Perm(), readCloudflareToken(dataDir))
	}
}

func TestRenewTimerUnitFiles(t *testing.T) {
	svc, tmr := renewUnitFiles("/home/me/.local/bin/loadinme", "/home/me/.loadinme")
	if !strings.Contains(svc, "ExecStart=/home/me/.local/bin/loadinme ssl renew --data-dir /home/me/.loadinme") {
		t.Fatalf("service:\n%s", svc)
	}
	if !strings.Contains(tmr, "OnCalendar=*-*-* 00,12:00:00") || !strings.Contains(tmr, "Persistent=true") {
		t.Fatalf("timer:\n%s", tmr)
	}
}

func TestSaveCertFilesPrivate(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, err := saveCertFiles(dataDir, "Files.Example.com", []byte("CERT"), []byte("KEY"))
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(dataDir, "certs", "files.example.com")
	if filepath.Dir(certPath) != wantDir || filepath.Base(certPath) != "fullchain.pem" || filepath.Base(keyPath) != "privkey.pem" {
		t.Fatalf("paths %s %s", certPath, keyPath)
	}
	for _, p := range []string{certPath, keyPath} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v err %v", p, fi.Mode().Perm(), err)
		}
	}
}

// --- renew decisions ---

func TestRenewSkipsWhenFarFromExpiry(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath := writeCertPair(t, certDir(dataDir, "a.example.com"), "a.example.com", 3, time.Now().Add(80*24*time.Hour))
	cfg := Config{DataDir: dataDir, Domain: "a.example.com", TLSEnabled: true, CertFile: certPath, KeyFile: keyPath}
	_ = writeRenewalInfo(dataDir, renewalInfo{Domain: "a.example.com", Method: methodStandalone})
	var out bytes.Buffer
	if err := runRenew(&cfg, false, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no renewal needed") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestRenewNeedsRootForHTTP(t *testing.T) {
	if isRoot() {
		t.Skip("running as root")
	}
	dataDir := t.TempDir()
	certPath, keyPath := writeCertPair(t, certDir(dataDir, "a.example.com"), "a.example.com", 3, time.Now().Add(10*24*time.Hour))
	cfg := Config{DataDir: dataDir, Domain: "a.example.com", TLSEnabled: true, CertFile: certPath, KeyFile: keyPath}
	_ = writeRenewalInfo(dataDir, renewalInfo{Domain: "a.example.com", Method: methodStopService, Unit: "x.service"})
	err := runRenew(&cfg, false, io.Discard)
	if err != errNeedRoot {
		t.Fatalf("err = %v, want errNeedRoot", err)
	}
}

// --- menu ---

func TestMenuSSLStatusAndOff(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	certPath, keyPath := writeCertPair(t, certDir(dataDir, "demo.example.com"), "demo.example.com", 9, time.Now().Add(60*24*time.Hour))
	writeConfigFile(t, Config{Port: port, DataDir: dataDir, Domain: "demo.example.com", TLSEnabled: true, CertFile: certPath, KeyFile: keyPath})
	_ = writeRenewalInfo(dataDir, renewalInfo{Domain: "demo.example.com", Email: "a@b.c", Method: methodNginx})
	// 6, 2 = status, 4 = off, y, y = delete files, 0 = back, 0 = exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n2\n4\ny\ny\n0\n0\n", "LOADINME_SYSTEMD_DIR="+t.TempDir())
	for _, want := range []string{"Choose [0-6]", "Expires:", "days left", "HTTP through nginx", "Renewal:", "SSL is off", "Deleted the certificate files"} {
		if !strings.Contains(out, want) {
			t.Fatalf("menu output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Press Enter") {
		t.Fatalf("extra Enter asked:\n%s", out)
	}
	cfg := readConfigFile(t, dataDir)
	if cfg.TLSEnabled || cfg.CertFile != "" {
		t.Fatalf("SSL not off: %+v", cfg)
	}
	if _, err := os.Stat(certDir(dataDir, "demo.example.com")); !os.IsNotExist(err) {
		t.Fatal("certificate files not deleted")
	}
}

func TestMenuGetSSLCancelAndBadDomain(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	// 6, 1, 0 = cancel at the domain prompt, 1, "not a domain", 0, 0.
	out := runMenuInput(t, bin, dataDir, port, "6\n1\n0\n1\nnot a domain\n0\n0\n")
	if !strings.Contains(out, "Cancelled.") || !strings.Contains(out, "does not look like a domain") {
		t.Fatalf("output:\n%s", out)
	}
	if strings.Contains(out, "Press Enter") {
		t.Fatalf("extra Enter asked:\n%s", out)
	}
}

func TestSSLCLIStatusAndUsage(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	out, err := runBin(t, bin, "ssl", "status", "--data-dir", dataDir)
	if err != nil || !strings.Contains(out, "Domain:  (none set)") || !strings.Contains(out, "SSL:     off") {
		t.Fatalf("ssl status: %v\n%s", err, out)
	}
	out, _ = runBin(t, bin, "ssl", "--help")
	for _, w := range []string{"ssl issue", "ssl renew", "ssl status", "ssl off"} {
		if !strings.Contains(out, w) {
			t.Fatalf("ssl --help lacks %q:\n%s", w, out)
		}
	}
	out, _ = runBin(t, bin, "--help")
	if !strings.Contains(out, "loadinme ssl issue|renew|status|off") {
		t.Fatalf("--help does not mention ssl:\n%s", out)
	}
}

func TestNoSahfarReferences(t *testing.T) {
	for _, f := range []string{"go.mod", "install.sh", "menu.go", "README.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "sahfar363") {
			t.Fatalf("%s still mentions sahfar363", f)
		}
	}
}
