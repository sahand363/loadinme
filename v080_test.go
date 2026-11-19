package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- v0.8.0: address without port ---

type fakeExposeEnv struct {
	dump      string
	dumpErr   error
	apache    string
	caddyfile string
	procs     []string
}

func (f fakeExposeEnv) nginxDump() (string, error)    { return f.dump, f.dumpErr }
func (f fakeExposeEnv) apacheVhosts() (string, error) { return f.apache, nil }
func (f fakeExposeEnv) caddyfileFor(portOwner) string { return f.caddyfile }
func (f fakeExposeEnv) running(names ...string) bool {
	for _, n := range names {
		for _, p := range f.procs {
			if n == p {
				return true
			}
		}
	}
	return false
}

func exposeTestCfg(t *testing.T) Config {
	dataDir := t.TempDir()
	c, k := writeCertPair(t, certDir(dataDir, "inme.example.com"), "inme.example.com", 3, time.Now().Add(60*24*time.Hour))
	return Config{Port: 5234, DataDir: dataDir, Domain: "inme.example.com", TLSEnabled: true, CertFile: c, KeyFile: k}
}

func TestDecideExposeDirect(t *testing.T) {
	cfg := exposeTestCfg(t)
	p := decideExpose(cfg, portOwner{Free: true}, portOwner{Free: true}, fakeExposeEnv{})
	if p.Method != exposeDirect || !p.Redirect80 {
		t.Fatalf("plan = %+v", p)
	}
	p = decideExpose(cfg, portOwner{Free: true}, portOwner{Process: "nginx", PID: 7}, fakeExposeEnv{})
	if p.Method != exposeDirect || p.Redirect80 {
		t.Fatalf("80 busy: plan = %+v", p)
	}
	// No certificate: nothing to serve on 443 yet.
	noCert := cfg
	noCert.TLSEnabled, noCert.CertFile = false, ""
	if p := decideExpose(noCert, portOwner{Free: true}, portOwner{Free: true}, fakeExposeEnv{}); p.Method != exposePlanNoCert {
		t.Fatalf("no cert: plan = %+v", p)
	}
	// Port 443 is LoadInMe's own port already.
	own := cfg
	own.Port = 443
	if p := decideExpose(own, portOwner{Process: "loadinme"}, portOwner{Free: true}, fakeExposeEnv{}); p.Method != exposePlanAlready {
		t.Fatalf("own 443: plan = %+v", p)
	}
}

func TestDecideExposeOtherOwnersAreNotTouched(t *testing.T) {
	cfg := exposeTestCfg(t)
	for proc, want := range map[string]string{
		"docker-proxy": "Docker",
		"xray":         "xray",
		"x-ui":         "x-ui",
		"haproxy":      "HAProxy",
		"stunnel4":     "stunnel4",
		"":             "could not tell",
	} {
		p := decideExpose(cfg, portOwner{Process: proc, PID: 42}, portOwner{Free: true}, fakeExposeEnv{})
		if p.Method != exposePlanOther {
			t.Fatalf("%q: method %s", proc, p.Method)
		}
		all := strings.Join(append(p.Why, p.Hints...), "\n")
		if !strings.Contains(all, want) || !strings.Contains(all, "https://inme.example.com:5234") {
			t.Fatalf("%q: explanation lacks %q or the port URL:\n%s", proc, want, all)
		}
	}
}

const nginxDumpOther443 = `# configuration file /etc/nginx/nginx.conf:
http { include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }
# configuration file /etc/nginx/sites-enabled/other:
server {
    listen 443 ssl default_server;
    server_name other.example.com;
    ssl_certificate /etc/ssl/other.pem;
}
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
`

func TestDecideExposeNginx(t *testing.T) {
	cfg := exposeTestCfg(t)
	o := portOwner{Process: "nginx", PID: 10}
	p := decideExpose(cfg, o, o, fakeExposeEnv{dump: nginxDumpOther443})
	if p.Method != exposeNginx || !p.Redirect80 {
		t.Fatalf("plan = %+v", p)
	}
	// A user block for the domain on 443: never clobbered.
	taken := nginxDumpOther443 + "# configuration file /etc/nginx/sites-enabled/inme:\nserver { listen 443 ssl; server_name inme.example.com; }\n"
	p = decideExpose(cfg, o, o, fakeExposeEnv{dump: taken})
	if p.Method != exposePlanTaken || p.Block != "/etc/nginx/sites-enabled/inme" {
		t.Fatalf("taken: plan = %+v", p)
	}
	// A user block for the domain on 80: no redirect block added.
	on80 := nginxDumpOther443 + "# configuration file /etc/nginx/sites-enabled/inme80:\nserver { listen 80; server_name inme.example.com; }\n"
	p = decideExpose(cfg, o, o, fakeExposeEnv{dump: on80})
	if p.Method != exposeNginx || p.Redirect80 {
		t.Fatalf("80 taken: plan = %+v", p)
	}
	// LoadInMe's own earlier file does not count as the user's.
	own := nginxDumpOther443 + "# configuration file /etc/nginx/conf.d/loadinme-inme.example.com.conf:\nserver { listen 443 ssl; server_name inme.example.com; }\n"
	if p := decideExpose(cfg, o, o, fakeExposeEnv{dump: own}); p.Method != exposeNginx {
		t.Fatalf("own file: plan = %+v", p)
	}
	// Owner unknown (no root), but nginx is the only web server running.
	if p := decideExpose(cfg, portOwner{}, portOwner{}, fakeExposeEnv{dump: nginxDumpOther443, procs: []string{"nginx"}}); p.Method != exposeNginx {
		t.Fatalf("guessed nginx: plan = %+v", p)
	}
}

func TestNginxExposeConf(t *testing.T) {
	c := nginxExposeConf("inme.example.com", 5234, "/home/u/.loadinme/certs/inme.example.com/fullchain.pem", "/home/u/.loadinme/certs/inme.example.com/privkey.pem", true, true)
	for _, want := range []string{
		"listen 443 ssl;", "listen [::]:443 ssl;", "server_name inme.example.com;",
		`ssl_certificate "/home/u/.loadinme/certs/inme.example.com/fullchain.pem";`,
		`ssl_certificate_key "/home/u/.loadinme/certs/inme.example.com/privkey.pem";`,
		"proxy_pass http://127.0.0.1:5234;", "proxy_set_header Host $host;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto https;", "client_max_body_size 0;",
		"proxy_request_buffering off;", "listen 80;", "return 301 https://$host$request_uri;",
		"proxy_pass http://127.0.0.1:41580;",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("conf lacks %q:\n%s", want, c)
		}
	}
	// The port-80 block keeps v0.7.0 renewals working: it is found as
	// the domain's block with the challenge line (nginx-existing).
	dump := "# configuration file /etc/nginx/conf.d/loadinme-inme.example.com.conf:\n" + c
	blk, ok := findNginxBlockFor(dump, "inme.example.com")
	if !ok || !blk.hasChallengeProxy() {
		t.Fatalf("port-80 block not usable for renewals: %+v %v", blk, ok)
	}
	if _, ok := findNginxBlockOn(dump, "inme.example.com", "443"); !ok {
		t.Fatal("443 block not parsed")
	}
	noRedirect := nginxExposeConf("inme.example.com", 5234, "/c", "/k", false, false)
	if strings.Contains(noRedirect, "listen 80") || strings.Contains(noRedirect, "[::]") {
		t.Fatalf("unexpected port-80 / IPv6 parts:\n%s", noRedirect)
	}
}

const apacheS = `VirtualHost configuration:
*:443                  other.example.com (/etc/apache2/sites-enabled/default-ssl.conf:2)
*:80                   is a NameVirtualHost
         default server 127.0.1.1 (/etc/apache2/sites-enabled/000-default.conf:1)
         port 80 namevhost 127.0.1.1 (/etc/apache2/sites-enabled/000-default.conf:1)
         port 80 namevhost www.site.example (/etc/apache2/sites-enabled/site.conf:1)
                 alias site.example
ServerRoot: "/etc/apache2"
`

func TestParseApacheVhosts(t *testing.T) {
	v := parseApacheVhosts(apacheS)
	if apacheVhostFile(v, "other.example.com", 443, "") != "/etc/apache2/sites-enabled/default-ssl.conf" {
		t.Fatalf("443 vhost not found: %+v", v)
	}
	if apacheVhostFile(v, "site.example", 80, "") != "/etc/apache2/sites-enabled/site.conf" {
		t.Fatalf("alias not found: %+v", v)
	}
	if apacheVhostFile(v, "inme.example.com", 443, "") != "" {
		t.Fatal("phantom vhost")
	}
	cfg := exposeTestCfg(t)
	o := portOwner{Process: "apache2", PID: 3}
	p := decideExpose(cfg, o, o, fakeExposeEnv{apache: apacheS})
	if p.Method != exposeApache || !p.Redirect80 {
		t.Fatalf("plan = %+v", p)
	}
	taken := apacheS + "*:443                  inme.example.com (/etc/apache2/sites-enabled/inme.conf:1)\n"
	if p := decideExpose(cfg, o, o, fakeExposeEnv{apache: taken}); p.Method != exposePlanTaken {
		t.Fatalf("taken: plan = %+v", p)
	}
	conf := apacheExposeConf("inme.example.com", 5234, "/c.pem", "/k.pem", true)
	for _, want := range []string{"<VirtualHost *:443>", "ServerName inme.example.com", "SSLEngine on",
		`SSLCertificateFile "/c.pem"`, "ProxyPreserveHost On", `RequestHeader set X-Forwarded-Proto "https"`,
		"ProxyPass / http://127.0.0.1:5234/", "LimitRequestBody 0", "<VirtualHost *:80>",
		"http://127.0.0.1:41580/.well-known/acme-challenge/", "RedirectMatch 301"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("apache conf lacks %q:\n%s", want, conf)
		}
	}
}

func TestDecideExposeCaddy(t *testing.T) {
	cfg := exposeTestCfg(t)
	o := portOwner{Process: "caddy", PID: 5}
	cf := filepath.Join(t.TempDir(), "Caddyfile")
	_ = os.WriteFile(cf, []byte("other.example.com {\n\treverse_proxy 127.0.0.1:9000\n}\n"), 0o644)
	p := decideExpose(cfg, o, o, fakeExposeEnv{caddyfile: cf})
	if p.Method != exposeCaddy || p.Block != cf {
		t.Fatalf("plan = %+v", p)
	}
	_ = os.WriteFile(cf, []byte("https://inme.example.com, www.inme.example.com {\n\tfile_server\n}\n"), 0o644)
	if p := decideExpose(cfg, o, o, fakeExposeEnv{caddyfile: cf}); p.Method != exposePlanTaken {
		t.Fatalf("taken: plan = %+v", p)
	}
	p = decideExpose(cfg, o, o, fakeExposeEnv{})
	if p.Method != exposePlanManual || !strings.Contains(strings.Join(p.Hints, "\n"), "reverse_proxy 127.0.0.1:5234") {
		t.Fatalf("manual: plan = %+v", p)
	}
}

func TestCaddyBlockAddRemove(t *testing.T) {
	orig := "other.example.com {\n\treverse_proxy 127.0.0.1:9000\n}\n"
	added := strings.TrimRight(orig, "\n") + "\n\n" + caddyBlock("inme.example.com", 5234)
	if caddyfileHasSite(added, "inme.example.com") {
		t.Fatal("LoadInMe's own block counted as the user's site")
	}
	if !strings.Contains(added, "inme.example.com {\n\treverse_proxy 127.0.0.1:5234\n}") {
		t.Fatalf("block:\n%s", added)
	}
	back := removeCaddyBlock(added, "inme.example.com")
	if strings.TrimRight(back, "\n") != strings.TrimRight(orig, "\n") {
		t.Fatalf("not restored:\n%q\nwant\n%q", back, orig)
	}
}

func TestPort80Handler(t *testing.T) {
	dataDir := t.TempDir()
	cd, err := newChallengeDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	cd.set("tok_EN-1", "tok_EN-1.keyauth")
	h := port80Handler(dataDir, "inme.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://inme.example.com/.well-known/acme-challenge/tok_EN-1", nil))
	if rec.Code != 200 || rec.Body.String() != "tok_EN-1.keyauth" {
		t.Fatalf("challenge: %d %q", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{"../config.json", "missing", "a%2Fb"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://x/.well-known/acme-challenge/"+bad, nil))
		if rec.Code != 404 {
			t.Fatalf("%q: %d", bad, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://evil.example/f/abc?x=1", nil))
	if rec.Code != 301 || rec.Header().Get("Location") != "https://inme.example.com/f/abc?x=1" {
		t.Fatalf("redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cd.Close()
	if _, err := os.Stat(filepath.Join(challengeDirPath(dataDir), "tok_EN-1")); !os.IsNotExist(err) {
		t.Fatal("challenge file left behind")
	}
}

func TestWebAddressWithExpose(t *testing.T) {
	cfg := Config{Port: 5234, Domain: "inme.example.com", TLSEnabled: true, CertFile: "/c", KeyFile: "/k"}
	if got := webAddressFor(cfg); got != "https://inme.example.com:5234" {
		t.Fatalf("without expose: %s", got)
	}
	cfg.Expose = &ExposeInfo{Method: exposeDirect}
	if got := webAddressFor(cfg); got != "https://inme.example.com" {
		t.Fatalf("direct: %s", got)
	}
	if !cfg.servesTLS() || cfg.proxied() {
		t.Fatal("direct must serve TLS itself")
	}
	cfg.Expose = &ExposeInfo{Method: exposeNginx}
	cfg.BindAddress = "127.0.0.1"
	if got := webAddressHost(cfg); got != "inme.example.com" {
		t.Fatalf("nginx host: %s", got)
	}
	if cfg.servesTLS() || !cfg.proxied() || cfg.listenAddr() != "127.0.0.1:5234" {
		t.Fatalf("nginx: servesTLS=%v proxied=%v addr=%s", cfg.servesTLS(), cfg.proxied(), cfg.listenAddr())
	}
}

func TestExposeConfigRoundTripKeepsPort(t *testing.T) {
	dataDir := t.TempDir()
	cfg := Config{Port: 5234, DataDir: dataDir, Domain: "inme.example.com", BindAddress: "127.0.0.1",
		Expose: &ExposeInfo{Method: exposeNginx, File: "/etc/nginx/conf.d/loadinme-inme.example.com.conf", Redirect80: true}}
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 5234 || got.BindAddress != "127.0.0.1" || got.Expose == nil || got.Expose.Method != exposeNginx {
		t.Fatalf("round trip: %+v %+v", got, got.Expose)
	}
	// An old (v0.7.0) config has neither field.
	plain := Config{Port: 5234, DataDir: dataDir}
	_ = saveConfig(plain)
	b, _ := os.ReadFile(configPath(dataDir))
	if strings.Contains(string(b), "expose") || strings.Contains(string(b), "bindAddress") {
		t.Fatalf("empty fields written:\n%s", b)
	}
}

// startServe runs `loadinme serve` and returns its output buffer.
func startServe(t *testing.T, bin, dataDir string, env ...string) *bytes.Buffer {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--data-dir", dataDir)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return &out
}

func TestServeProxiedIsPlainHTTPOnLoopback(t *testing.T) {
	bin := buildTestBinary(t)
	cfg := exposeTestCfg(t)
	cfg.Port = freePort(t)
	cfg.BindAddress = "127.0.0.1"
	cfg.Expose = &ExposeInfo{Method: exposeNginx}
	writeConfigFile(t, cfg)
	out := startServe(t, bin, cfg.DataDir)
	waitHealthOrFail(t, cfg.Port, true, out.String())
	if !strings.Contains(out.String(), "127.0.0.1:"+strconv.Itoa(cfg.Port)) {
		t.Fatalf("serve output:\n%s", out.String())
	}
	// Only loopback: the port is not open on another local address.
	if ip := outboundIP(); ip != "" && ip != "127.0.0.1" {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(cfg.Port)), time.Second); err == nil {
			c.Close()
			t.Fatalf("port %d is reachable on %s, want loopback only", cfg.Port, ip)
		}
	}
}

func TestServeDirectAddsHTTPSAndRedirectListeners(t *testing.T) {
	bin := buildTestBinary(t)
	cfg := exposeTestCfg(t)
	cfg.Port = freePort(t)
	hp, p80 := freePort(t), freePort(t)
	cfg.Expose = &ExposeInfo{Method: exposeDirect, Redirect80: true}
	writeConfigFile(t, cfg)
	cd, _ := newChallengeDir(cfg.DataDir)
	cd.set("abcDEF", "abcDEF.ka")
	out := startServe(t, bin, cfg.DataDir, "LOADINME_HTTPS_PORT="+strconv.Itoa(hp), "LOADINME_HTTP_PORT="+strconv.Itoa(p80))
	client := &http.Client{Timeout: 2 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: cfg.Domain}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", hp))
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https on the 443 stand-in never answered: %v\n%s", err, out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The own port still serves HTTPS too.
	if resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", cfg.Port)); err != nil || resp.StatusCode != 200 {
		t.Fatalf("own port: %v", err)
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/some/path", p80))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := fmt.Sprintf("https://%s:%d/some/path", cfg.Domain, hp); resp.StatusCode != 301 || resp.Header.Get("Location") != want {
		t.Fatalf("redirect %d %q, want %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
	resp, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/abcDEF", p80))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "abcDEF.ka" {
		t.Fatalf("challenge through :80 listener: %q", b)
	}
}

func TestServeDirectKeepsOwnPortWhen443Busy(t *testing.T) {
	bin := buildTestBinary(t)
	cfg := exposeTestCfg(t)
	cfg.Port = freePort(t)
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	hp := busy.Addr().(*net.TCPAddr).Port
	cfg.Expose = &ExposeInfo{Method: exposeDirect}
	writeConfigFile(t, cfg)
	out := startServe(t, bin, cfg.DataDir, "LOADINME_HTTPS_PORT="+strconv.Itoa(hp))
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", cfg.Port))
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("own port never answered: %v\n%s", err, out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if !strings.Contains(out.String(), "could not listen on port "+strconv.Itoa(hp)) {
		t.Fatalf("no warning about the busy port:\n%s", out.String())
	}
}

func TestCLIExposeDirectAndUnexpose(t *testing.T) {
	bin := buildTestBinary(t)
	cfg := exposeTestCfg(t)
	cfg.Port = freePort(t)
	writeConfigFile(t, cfg)
	env := append(os.Environ(), "LOADINME_HTTPS_PORT="+strconv.Itoa(freePort(t)), "LOADINME_HTTP_PORT="+strconv.Itoa(freePort(t)))
	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	out := run("ssl", "expose", "--yes", "--no-restart", "--data-dir", cfg.DataDir)
	if !strings.Contains(out, "port 443 is free") && !strings.Contains(out, "is free, so LoadInMe answers") {
		t.Fatalf("expose output:\n%s", out)
	}
	got := readConfigFile(t, cfg.DataDir)
	if got.Expose == nil || got.Expose.Method != exposeDirect || !got.Expose.Redirect80 || got.Expose.Setcap || got.Port != cfg.Port || got.BindAddress != "" {
		t.Fatalf("config after expose: %+v %+v", got, got.Expose)
	}
	st := run("ssl", "status", "--data-dir", cfg.DataDir)
	if !strings.Contains(st, "Address: https://inme.example.com — no port") {
		t.Fatalf("status:\n%s", st)
	}
	// SSL off is refused while the address without port is set up.
	cmd := exec.Command(bin, "ssl", "off", "--no-restart", "--data-dir", cfg.DataDir)
	cmd.Env = env
	if o, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(o), "Remove that first") {
		t.Fatalf("ssl off not refused: %v\n%s", err, o)
	}
	out = run("ssl", "expose", "--yes", "--no-restart", "--data-dir", cfg.DataDir)
	if !strings.Contains(out, "Already set up") {
		t.Fatalf("second expose:\n%s", out)
	}
	run("ssl", "unexpose", "--no-restart", "--data-dir", cfg.DataDir)
	got = readConfigFile(t, cfg.DataDir)
	if got.Expose != nil || got.Port != cfg.Port || !got.TLSEnabled {
		t.Fatalf("config after unexpose: %+v", got)
	}
}

func TestCLIExposeOtherOwnerTouchesNothing(t *testing.T) {
	bin := buildTestBinary(t)
	cfg := exposeTestCfg(t)
	cfg.Port = freePort(t)
	writeConfigFile(t, cfg)
	before, _ := os.ReadFile(configPath(cfg.DataDir))
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	nginxDir := t.TempDir()
	cmd := exec.Command(bin, "ssl", "expose", "--yes", "--no-restart", "--data-dir", cfg.DataDir)
	cmd.Env = append(os.Environ(), "LOADINME_HTTPS_PORT="+strconv.Itoa(busy.Addr().(*net.TCPAddr).Port), "LOADINME_NGINX_CONF_DIR="+nginxDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expose: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "LoadInMe does not touch it") || !strings.Contains(string(out), "Nothing was changed") {
		t.Fatalf("output:\n%s", out)
	}
	after, _ := os.ReadFile(configPath(cfg.DataDir))
	if !bytes.Equal(before, after) {
		t.Fatalf("config changed:\n%s\n→\n%s", before, after)
	}
	if m, _ := filepath.Glob(filepath.Join(nginxDir, "*")); len(m) > 0 {
		t.Fatalf("files written: %v", m)
	}
}

func TestMenuAddressWithoutPortEntry(t *testing.T) {
	bin := buildTestBinary(t)
	dataDir := t.TempDir()
	port := freePort(t)
	// 6 → 6 without SSL: explains; 0 back; 0 exit.
	out := runMenuInput(t, bin, dataDir, port, "6\n6\n0\n0\n")
	for _, want := range []string{"6  Address without port", "Choose [0-6]", "First get SSL"} {
		if !strings.Contains(out, want) {
			t.Fatalf("menu lacks %q:\n%s", want, out)
		}
	}
	// With an exposed config: shows the method and the undo entry;
	// 0 at the submenu goes back. Port change is refused while proxied.
	cfg := exposeTestCfg(t)
	cfg.Port = port
	cfg.BindAddress = "127.0.0.1"
	cfg.Expose = &ExposeInfo{Method: exposeNginx, Manual: true}
	writeConfigFile(t, cfg)
	out = runMenuInput(t, bin, cfg.DataDir, port, "6\n6\n0\n0\n5\n\n0\n")
	for _, want := range []string{"Web UI: https://inme.example.com\n", "no port needed", "Now: https://inme.example.com — through nginx", "2  Undo", "Undo the address without port first"} {
		if !strings.Contains(out, want) {
			t.Fatalf("menu lacks %q:\n%s", want, out)
		}
	}
	if got := readConfigFile(t, cfg.DataDir); got.Port != port {
		t.Fatalf("port changed: %d", got.Port)
	}
}

func TestMenuUnexposeManualNeedsNoRoot(t *testing.T) {
	bin := buildTestBinary(t)
	cfg := exposeTestCfg(t)
	cfg.Port = freePort(t)
	cfg.BindAddress = "127.0.0.1"
	cfg.Expose = &ExposeInfo{Method: exposeNginx, Manual: true, PrevBind: ""}
	writeConfigFile(t, cfg)
	// 6 → 6 → 2 Undo → y; the web UI is not running, so it is started
	// again on its own port with HTTPS; then 0, 3 (stop is not needed).
	out := runMenuInput(t, bin, cfg.DataDir, cfg.Port, "6\n6\n2\ny\n0\n2\n\n0\n")
	if !strings.Contains(out, "Undone. LoadInMe is back at https://inme.example.com:"+strconv.Itoa(cfg.Port)) {
		t.Fatalf("output:\n%s", out)
	}
	got := readConfigFile(t, cfg.DataDir)
	if got.Expose != nil || got.BindAddress != "" || got.Port != cfg.Port {
		t.Fatalf("config: %+v", got)
	}
}

func TestInstallScriptReappliesSetcapBeforeStart(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "setcap cap_net_bind_service=+ep \"$BIN\"")
	j := strings.Index(s, "\"$BIN\" start --port")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("install.sh must re-apply setcap before starting the web UI (setcap at %d, start at %d)", i, j)
	}
}

func TestRenewalAcceptsSelf80AndApacheExisting(t *testing.T) {
	for _, m := range []string{methodSelf80, methodApacheExisting} {
		if methodLabel(m) == m {
			t.Fatalf("no label for %s", m)
		}
		if (sslPlan{Method: m}).needsRoot() != (m != methodSelf80) {
			t.Fatalf("needsRoot wrong for %s", m)
		}
	}
}
