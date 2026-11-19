package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Address without port (v0.8.0): after SSL is issued, LoadInMe makes
// itself reachable at https://<domain> with no port, in the best way
// this server allows. It looks at who owns port 443 (and 80), the same
// way Get SSL looks at port 80:
//
//	direct  443 is free: LoadInMe serves HTTPS on 443 itself (its own
//	        port keeps working too), plus a small :80 listener that
//	        redirects to https:// and answers Let's Encrypt renewals
//	nginx   nginx owns 443: a conf.d server block for the domain proxies
//	        to LoadInMe, which then listens on 127.0.0.1 only (plain http)
//	apache  Apache owns 443: the same with a vhost
//	caddy   Caddy owns 443: a `<domain> { reverse_proxy … }` block is
//	        appended to its Caddyfile (Caddy brings its own certificate)
//	other   anything else (Docker, xray/x-ui, HAProxy, unknown): nothing
//	        is touched; LoadInMe stays at https://<domain>:<port>
const (
	exposeDirect = "direct"
	exposeNginx  = "nginx"
	exposeApache = "apache"
	exposeCaddy  = "caddy"
	// Plans that change nothing.
	exposePlanAlready = "already"
	exposePlanNoCert  = "no-cert"
	exposePlanTaken   = "taken"  // the web server already serves the domain on 443
	exposePlanManual  = "manual" // Caddy without a Caddyfile LoadInMe can edit
	exposePlanOther   = "other"  // something else owns 443
)

// ExposeInfo is saved in config.json while the address without port is
// set up, so it can be shown, renewed around, and undone exactly.
type ExposeInfo struct {
	Method     string    `json:"method"`
	File       string    `json:"file,omitempty"`       // config file LoadInMe wrote or edited
	SiteLink   string    `json:"siteLink,omitempty"`   // Apache (Debian): the sites-enabled link
	Redirect80 bool      `json:"redirect80,omitempty"` // a port-80 → https redirect was added
	Setcap     bool      `json:"setcap,omitempty"`     // the binary was given cap_net_bind_service
	SetcapExe  string    `json:"setcapExe,omitempty"`
	PrevBind   string    `json:"prevBind,omitempty"` // bind address before (restored on undo)
	Manual     bool      `json:"manual,omitempty"`   // the user added the block to their own config
	Since      time.Time `json:"since"`
}

func exposeLabel(m string) string {
	switch m {
	case exposeDirect:
		return "LoadInMe serves port 443 itself"
	case exposeNginx:
		return "through nginx on port 443"
	case exposeApache:
		return "through Apache on port 443"
	case exposeCaddy:
		return "through Caddy on port 443"
	case exposePlanAlready:
		return "already without a port"
	case exposePlanNoCert:
		return "needs the SSL certificate first"
	case exposePlanTaken:
		return "your web server already serves this domain — one block needed"
	case exposePlanManual:
		return "Caddy — add one block by hand"
	case exposePlanOther:
		return "not possible here — port 443 belongs to another program"
	}
	return m
}

// httpsPort / httpPort are 443 and 80; LOADINME_HTTPS_PORT and
// LOADINME_HTTP_PORT move them for tests.
func envPort(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return def
}

func httpsPort() int { return envPort("LOADINME_HTTPS_PORT", 443) }
func httpPort() int  { return envPort("LOADINME_HTTP_PORT", 80) }

// proxied reports whether a web server in front of LoadInMe serves
// https://<domain>: LoadInMe itself then speaks plain http on loopback.
func (c Config) proxied() bool { return c.Expose != nil && c.Expose.Method != exposeDirect }

// servesTLS reports whether LoadInMe's own listener speaks HTTPS.
func (c Config) servesTLS() bool {
	return c.TLSEnabled && c.CertFile != "" && c.KeyFile != "" && !c.proxied()
}

func (c Config) listenAddr() string { return net.JoinHostPort(c.BindAddress, strconv.Itoa(c.Port)) }

// --- ACME challenge files for LoadInMe's own :80 listener ---

func challengeDirPath(dataDir string) string { return filepath.Join(dataDir, "acme-challenge") }

var acmeTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// challengeDir writes key authorizations as files that the running
// web UI's :80 listener serves (`loadinme ssl renew` is a separate
// process, and cannot bind :80 while LoadInMe holds it).
type challengeDir struct {
	dataDir, dir string
	mu           sync.Mutex
	files        []string
}

func newChallengeDir(dataDir string) (*challengeDir, error) {
	dir := challengeDirPath(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o755)
	chownToApp(dataDir, dir)
	return &challengeDir{dataDir: dataDir, dir: dir}, nil
}

func (c *challengeDir) set(token, keyAuth string) {
	if !acmeTokenRe.MatchString(token) {
		return
	}
	p := filepath.Join(c.dir, token)
	if err := os.WriteFile(p, []byte(keyAuth), 0o644); err != nil {
		return
	}
	chownToApp(c.dataDir, p)
	c.mu.Lock()
	c.files = append(c.files, p)
	c.mu.Unlock()
}

func (c *challengeDir) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.files {
		_ = os.Remove(f)
	}
	c.files = nil
}

// port80Handler is LoadInMe's own :80 listener in direct mode: it
// answers Let's Encrypt from the challenge files and sends everything
// else to https://<domain>.
func port80Handler(dataDir, domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			token := strings.TrimPrefix(r.URL.Path, prefix)
			if !acmeTokenRe.MatchString(token) {
				http.NotFound(w, r)
				return
			}
			b, err := os.ReadFile(filepath.Join(challengeDirPath(dataDir), token))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(b)
			return
		}
		target := "https://" + domain
		if p := httpsPort(); p != 443 {
			target += ":" + strconv.Itoa(p)
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

// selfAnswers80 reports whether LoadInMe's own :80 listener is the
// one on port 80 (it serves a probe file written here).
func selfAnswers80(dataDir string) bool {
	cd, err := newChallengeDir(dataDir)
	if err != nil {
		return false
	}
	defer cd.Close()
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	token := "loadinme-probe-" + hex.EncodeToString(b)
	cd.set(token, token+".ok")
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("http://127.0.0.1:80/.well-known/acme-challenge/" + token)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return resp.StatusCode == http.StatusOK && string(body) == token+".ok"
}

// startDirectListeners adds the :443 HTTPS listener and the :80
// redirect listener of direct mode. A port it cannot get is a warning,
// not a failure: LoadInMe's own port keeps working.
func startDirectListeners(cfg Config, handler http.Handler, tlsCfg *tls.Config) {
	hp := httpsPort()
	if cfg.Port != hp {
		ln, err := net.Listen("tcp", net.JoinHostPort(cfg.BindAddress, strconv.Itoa(hp)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "loadinme: could not listen on port %d for https://%s: %v\n", hp, cfg.Domain, err)
			fmt.Fprintf(os.Stderr, "  https://%s:%d still works.%s\n", cfg.Domain, cfg.Port, lowPortHint(err))
		} else {
			s := &http.Server{Handler: handler, TLSConfig: tlsCfg.Clone(), ReadTimeout: 15 * time.Minute, WriteTimeout: 15 * time.Minute}
			go func() { _ = s.ServeTLS(ln, "", "") }()
			fmt.Printf("Serving on :%d too (HTTPS) — https://%s\n", hp, cfg.Domain)
		}
	}
	if cfg.Expose.Redirect80 && cfg.Port != httpPort() {
		ln, err := net.Listen("tcp", net.JoinHostPort(cfg.BindAddress, strconv.Itoa(httpPort())))
		if err != nil {
			fmt.Fprintf(os.Stderr, "loadinme: could not listen on port %d (http → https redirect is off): %v%s\n", httpPort(), err, lowPortHint(err))
			return
		}
		s := &http.Server{Handler: port80Handler(cfg.DataDir, cfg.Domain), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = s.Serve(ln) }()
		fmt.Printf("Serving on :%d too (redirects to https://, answers Let's Encrypt)\n", httpPort())
	}
}

func lowPortHint(err error) string {
	if err != nil && strings.Contains(err.Error(), "permission denied") {
		return "\n  This binary may not use ports below 1024 any more (setcap is lost when the file is replaced by hand).\n  Fix: sudo setcap cap_net_bind_service=+ep " + selfExe() + " — then restart the web UI."
	}
	return ""
}

// --- privileges for ports below 1024 ---

func unprivilegedPortStart() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		return 1024
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 1024
	}
	return n
}

// appRunsAsRoot reports whether the web UI itself runs as root.
func appRunsAsRoot(dataDir string) bool {
	if !isRoot() {
		return false
	}
	if _, ok := sudoInvoker(); ok {
		return false
	}
	uid, _, ok := fileOwner(dataDir)
	return !ok || uid == 0
}

// setcapNeeded reports whether the binary needs cap_net_bind_service
// to listen on these ports.
func setcapNeeded(dataDir string, ports ...int) bool {
	if appRunsAsRoot(dataDir) {
		return false
	}
	start := unprivilegedPortStart()
	for _, p := range ports {
		if p < start {
			return true
		}
	}
	return false
}

func setcapBind(exe string) error {
	out, err := exec.Command("setcap", "cap_net_bind_service=+ep", exe).CombinedOutput()
	if err != nil {
		return fmt.Errorf("setcap: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func setcapRemove(exe string) error {
	out, err := exec.Command("setcap", "-r", exe).CombinedOutput()
	if err != nil {
		return fmt.Errorf("setcap -r: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// hasBindCap reports whether getcap lists cap_net_bind_service on exe
// (true when getcap is missing, so removal is still tried).
func hasBindCap(exe string) bool {
	out, err := exec.Command("getcap", exe).Output()
	if err != nil {
		return true
	}
	return strings.Contains(string(out), "cap_net_bind_service")
}

// reapplySetcap gives a replaced binary (self-update) the port
// permission again.
func reapplySetcap(exe string, out io.Writer) {
	var err error
	if isRoot() {
		err = setcapBind(exe)
	} else {
		fmt.Fprintln(out, "Giving the new binary permission to use ports 443/80 again (setcap) — asking sudo…")
		cmd := exec.Command("sudo", "setcap", "cap_net_bind_service=+ep", exe)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, out, out
		err = cmd.Run()
	}
	if err != nil {
		fmt.Fprintln(out, "⚠ Could not run setcap:", err)
		fmt.Fprintln(out, "  Run: sudo setcap cap_net_bind_service=+ep "+exe+" — then restart the web UI (option 3).")
		return
	}
	fmt.Fprintln(out, "✓ Port 443/80 permission (setcap) re-applied to", exe)
}

// --- detection ---

func procRunning(names ...string) bool {
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", p.Name(), "comm"))
		if err != nil {
			continue
		}
		c := strings.TrimSpace(string(b))
		for _, n := range names {
			if c == n {
				return true
			}
		}
	}
	return false
}

func isApacheName(p string) bool { return p == "apache2" || p == "httpd" }

// exposeEnv is what the planner asks the system; tests replace it.
type exposeEnv interface {
	nginxDump() (string, error)
	apacheVhosts() (string, error)
	caddyfileFor(o portOwner) string
	running(names ...string) bool
}

type realExposeEnv struct{}

func (realExposeEnv) nginxDump() (string, error) { return nginxDump() }
func (realExposeEnv) apacheVhosts() (string, error) {
	ctl := apacheCtl()
	if ctl == "" {
		return "", errors.New("apachectl not found")
	}
	out, err := exec.Command(ctl, "-S").CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s -S: %v: %s", ctl, err, strings.TrimSpace(lastLines(string(out), 3)))
	}
	return string(out), nil
}
func (realExposeEnv) caddyfileFor(o portOwner) string { return findCaddyfile(o.PID) }
func (realExposeEnv) running(names ...string) bool    { return procRunning(names...) }

type exposePlan struct {
	Method     string
	Why        []string
	Hints      []string // what the user could do (plans that change nothing)
	Owner      portOwner
	Owner80    portOwner
	Redirect80 bool
	Server     string // "nginx", "Apache", "Caddy" (taken / manual)
	Block      string // taken: file of the existing block; caddy: the Caddyfile
	Manual     bool
}

func planExpose(cfg Config) exposePlan {
	return decideExpose(cfg, detectPortOwner(httpsPort()), detectPortOwner(httpPort()), realExposeEnv{})
}

func decideExpose(cfg Config, o, o80 portOwner, env exposeEnv) exposePlan {
	d := cfg.Domain
	hp := httpsPort()
	p := exposePlan{Owner: o, Owner80: o80}
	hasCert := cfg.TLSEnabled && cfg.CertFile != "" && cfg.KeyFile != ""
	if cfg.Port == hp && hasCert {
		p.Method = exposePlanAlready
		p.Why = []string{"LoadInMe's own port is " + strconv.Itoa(hp) + ", so https://" + d + " already works with no port."}
		return p
	}
	noCert := func(server string) exposePlan {
		p.Method = exposePlanNoCert
		p.Why = []string{server + " needs LoadInMe's SSL certificate for " + d + " — get it first (6 → 1 Get SSL)."}
		return p
	}
	if o.Free {
		if !hasCert {
			return noCert("Serving https://" + d + " on port 443")
		}
		p.Method = exposeDirect
		p.Redirect80 = o80.Free
		p.Why = []string{
			"Port 443 is free, so LoadInMe answers https://" + d + " on port 443 itself",
			fmt.Sprintf("(its own port %d keeps working too). Nothing else is touched.", cfg.Port),
		}
		if p.Redirect80 {
			p.Why = append(p.Why,
				"Port 80 is free as well: LoadInMe also listens there, sends http:// visitors to https://,",
				"and answers Let's Encrypt there when the certificate is renewed.")
		} else {
			p.Why = append(p.Why, "Port 80 is used by "+o80.describe()+", so there is no http:// → https:// redirect;",
				"renewals keep working the way Get SSL set them up.")
		}
		ports := []int{hp}
		if p.Redirect80 {
			ports = append(ports, httpPort())
		}
		if setcapNeeded(cfg.DataDir, ports...) {
			p.Why = append(p.Why, "LoadInMe runs as your user, not root, so its binary gets permission to use ports",
				"below 1024 (setcap cap_net_bind_service; removed again on undo, re-applied after updates).")
		}
		return p
	}
	proc := o.Process
	if proc == "" {
		// Without root the owner may be unknown: guess only when
		// exactly one web server runs.
		var found []string
		for _, n := range []string{"nginx", "apache2", "httpd", "caddy"} {
			if env.running(n) {
				found = append(found, n)
			}
		}
		if len(found) == 1 {
			proc = found[0]
		}
	}
	switch {
	case proc == "nginx":
		if !hasCert {
			return noCert("nginx")
		}
		dump, err := env.nginxDump()
		if err != nil {
			return otherPlan(p, cfg, "nginx owns port 443, but its config could not be read ("+err.Error()+").", nil)
		}
		if blk, ok := findNginxBlockOn(dump, d, strconv.Itoa(hp), "loadinme-"); ok {
			p.Method, p.Server, p.Block = exposePlanTaken, "nginx", blk.File
			p.Why = []string{"nginx owns port 443 and already has a server block for " + d + " in " + blk.File + ".",
				"LoadInMe does not change your own server blocks."}
			return p
		}
		p.Method = exposeNginx
		if o80.Free || o80.Process == "nginx" || (o80.Process == "" && env.running("nginx")) {
			if _, ok := findNginxBlockOn(dump, d, "80", "loadinme-"); !ok {
				p.Redirect80 = true
			}
		}
		p.Why = []string{
			"nginx owns port 443. LoadInMe adds one file, " + nginxExposePath(d) + ": a server block for " + d,
			"on 443 with LoadInMe's certificate that forwards to LoadInMe on 127.0.0.1:" + strconv.Itoa(cfg.Port) + ".",
			"Your other nginx sites are not touched. LoadInMe then listens on 127.0.0.1 only (plain http",
			"behind nginx), and nginx is reloaded after every certificate renewal.",
		}
		if p.Redirect80 {
			p.Why = append(p.Why, "It also answers http://"+d+" on port 80 with a redirect to https:// (and passes",
				"Let's Encrypt renewals to LoadInMe).")
		}
		return p
	case isApacheName(proc):
		if !hasCert {
			return noCert("Apache")
		}
		vh, err := env.apacheVhosts()
		if err != nil {
			return otherPlan(p, cfg, "Apache owns port 443, but its config could not be read ("+err.Error()+").", nil)
		}
		vhosts := parseApacheVhosts(vh)
		if f := apacheVhostFile(vhosts, d, hp, "loadinme-"); f != "" {
			p.Method, p.Server, p.Block = exposePlanTaken, "Apache", f
			p.Why = []string{"Apache owns port 443 and already has a vhost for " + d + " in " + f + ".",
				"LoadInMe does not change your own vhosts."}
			return p
		}
		p.Method = exposeApache
		if isApacheName(o80.Process) || (o80.Process == "" && !o80.Free && (env.running("apache2") || env.running("httpd"))) {
			if apacheVhostFile(vhosts, d, 80, "loadinme-") == "" {
				p.Redirect80 = true
			}
		}
		file, _ := apacheExposePaths(d)
		p.Why = []string{
			"Apache owns port 443. LoadInMe adds one vhost, " + file + ", for " + d + " on 443 with",
			"LoadInMe's certificate that forwards to LoadInMe on 127.0.0.1:" + strconv.Itoa(cfg.Port) + " (it enables",
			"mod_proxy, mod_proxy_http, mod_ssl and mod_headers if needed). Your other sites are not touched.",
			"LoadInMe then listens on 127.0.0.1 only, and Apache is reloaded after every renewal.",
		}
		if p.Redirect80 {
			p.Why = append(p.Why, "It also answers http://"+d+" on port 80 with a redirect to https://.")
		}
		return p
	case proc == "caddy":
		cf := env.caddyfileFor(o)
		block := caddyBlock(d, cfg.Port)
		if cf == "" {
			p.Method, p.Server = exposePlanManual, "Caddy"
			p.Why = []string{"Caddy owns port 443, but LoadInMe could not find a Caddyfile it may edit",
				"(Caddy may run from a JSON config or its API)."}
			p.Hints = append([]string{"Add this site to your Caddy config and reload Caddy, then choose this again:", ""},
				indentLines(block, "    ")...)
			return p
		}
		b, _ := os.ReadFile(cf)
		if caddyfileHasSite(string(b), d) {
			p.Method, p.Server, p.Block = exposePlanTaken, "Caddy", cf
			p.Why = []string{"Caddy owns port 443 and " + cf + " already has a site for " + d + "."}
			return p
		}
		p.Method, p.Block = exposeCaddy, cf
		p.Why = []string{
			"Caddy owns port 443 and reads " + cf + ". LoadInMe can add this block to the end of it",
			"and reload Caddy:",
			"",
		}
		p.Why = append(p.Why, indentLines(block, "    ")...)
		p.Why = append(p.Why, "",
			"Caddy gets and renews its own certificate for "+d+". LoadInMe then listens on 127.0.0.1 only.")
		return p
	}
	return otherPlan(p, cfg, "", nil)
}

// otherPlan: something LoadInMe must not touch owns port 443.
func otherPlan(p exposePlan, cfg Config, reason string, _ []string) exposePlan {
	d := cfg.Domain
	own := fmt.Sprintf("https://%s:%d", d, cfg.Port)
	p.Method = exposePlanOther
	proc := strings.ToLower(p.Owner.Process)
	what := p.Owner.describe()
	var hints []string
	switch {
	case reason != "":
		p.Why = []string{reason}
	case strings.Contains(proc, "docker") || strings.Contains(proc, "containerd"):
		p.Why = []string{"Port 443 is published by a Docker container (" + what + ")."}
		hints = []string{
			"• Publish that container on another port, then choose this again; or",
			"• let the container's web server forward " + d + " to this server's port " + strconv.Itoa(cfg.Port) + ".",
		}
	case strings.Contains(proc, "xray") || strings.Contains(proc, "x-ui") || strings.Contains(proc, "v2ray") ||
		strings.Contains(proc, "sing-box") || strings.Contains(proc, "hysteria") || strings.Contains(proc, "trojan"):
		p.Why = []string{"Port 443 is used by " + what + " — a proxy panel / xray inbound (often VLESS, Reality",
			"or Trojan). Those need port 443 to themselves, so LoadInMe leaves it alone."}
		hints = []string{
			"• Keep using " + own + " (it works now); or",
			"• move that inbound to another port, then choose this again; or",
			"• advanced: put an SNI router on 443 (nginx `stream` with ssl_preread, or HAProxy) that sends " + d,
			"  to 127.0.0.1:" + strconv.Itoa(cfg.Port) + " and everything else to xray.",
		}
	case strings.Contains(proc, "haproxy"):
		p.Why = []string{"Port 443 is used by HAProxy (" + what + ")."}
		hints = []string{
			"• Add a backend for " + d + " (by SNI, or by Host if HAProxy ends TLS) that forwards to",
			"  127.0.0.1:" + strconv.Itoa(cfg.Port) + ", then use " + "https://" + d + "."}
	case proc == "loadinme":
		p.Why = []string{"Port 443 is used by another LoadInMe (" + what + ")."}
	case proc == "":
		p.Why = []string{"Port 443 is in use, but LoadInMe could not tell by which program (run it as root to see)."}
	default:
		p.Why = []string{"Port 443 is used by " + what + "."}
	}
	p.Why = append(p.Why, "LoadInMe does not touch it, so the address keeps its port: "+own+".")
	if len(hints) == 0 {
		hints = []string{"• Keep using " + own + " (it works now); or",
			"• free port 443, then choose this again — LoadInMe then serves it itself."}
	}
	p.Hints = append([]string{"What you could do:"}, hints...)
	return p
}

func indentLines(s, ind string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		out = append(out, ind+l)
	}
	return out
}

// --- nginx ---

func nginxExposePath(domain string) string {
	return filepath.Join(nginxConfDir(), "loadinme-"+strings.ToLower(domain)+".conf")
}

func nginxProxyLocation(port int) string {
	return fmt.Sprintf(`location / {
    proxy_pass http://127.0.0.1:%d;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 15m;
    proxy_send_timeout 15m;
    # LoadInMe checks the upload size itself (Settings → max file size).
    client_max_body_size 0;
    proxy_request_buffering off;
}`, port)
}

func nginxExposeConf(domain string, port int, cert, key string, redirect80, ipv6 bool) string {
	hp := strconv.Itoa(httpsPort())
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by LoadInMe: https://%s with no port.\n", domain)
	b.WriteString("# Remove it with: loadinme ssl unexpose (menu 6 → 6 → Undo).\n")
	b.WriteString("server {\n")
	b.WriteString("    listen " + hp + " ssl;\n")
	if ipv6 {
		b.WriteString("    listen [::]:" + hp + " ssl;\n")
	}
	fmt.Fprintf(&b, "    server_name %s;\n", domain)
	fmt.Fprintf(&b, "    ssl_certificate \"%s\";\n", cert)
	fmt.Fprintf(&b, "    ssl_certificate_key \"%s\";\n", key)
	b.WriteString(strings.Join(indentLines(nginxProxyLocation(port), "    "), "\n") + "\n")
	b.WriteString("}\n")
	if redirect80 {
		b.WriteString("server {\n")
		b.WriteString("    listen 80;\n")
		if ipv6 {
			b.WriteString("    listen [::]:80;\n")
		}
		fmt.Fprintf(&b, "    server_name %s;\n", domain)
		b.WriteString("    # Let's Encrypt renewals for LoadInMe (loadinme ssl renew).\n")
		fmt.Fprintf(&b, "    location /.well-known/acme-challenge/ {\n        proxy_pass http://127.0.0.1:%d;\n        proxy_set_header Host $host;\n    }\n", acmeLoopbackPort())
		b.WriteString("    location / {\n        return 301 https://$host$request_uri;\n    }\n")
		b.WriteString("}\n")
	}
	return b.String()
}

func applyNginx(cfg Config, plan exposePlan, out io.Writer) (ExposeInfo, error) {
	d := cfg.Domain
	path := nginxExposePath(d)
	old, hadOld := os.ReadFile(path)
	restore := func() {
		if hadOld == nil {
			_ = os.WriteFile(path, old, 0o644)
		} else {
			_ = os.Remove(path)
		}
	}
	try := func(ipv6 bool) error {
		if err := os.WriteFile(path, []byte(nginxExposeConf(d, cfg.Port, cfg.CertFile, cfg.KeyFile, plan.Redirect80, ipv6)), 0o644); err != nil {
			return err
		}
		return nginxTest()
	}
	if err := try(true); err != nil {
		if err2 := try(false); err2 != nil {
			restore()
			return ExposeInfo{}, fmt.Errorf("nginx did not accept %s, so it was removed again (nothing changed): %v", path, err)
		}
	}
	if dump, err := nginxDump(); err == nil && !strings.Contains(dump, "# configuration file "+path+":") {
		restore()
		return ExposeInfo{}, fmt.Errorf("nginx does not include %s/*.conf, so the file would not be used (nothing changed)", nginxConfDir())
	}
	if err := nginxReload(); err != nil {
		restore()
		_ = nginxReload()
		return ExposeInfo{}, fmt.Errorf("nginx could not be reloaded, so %s was removed again: %v", path, err)
	}
	fmt.Fprintln(out, "✓ Added", path, "and reloaded nginx (nginx -t passed).")
	return ExposeInfo{Method: exposeNginx, File: path, Redirect80: plan.Redirect80}, nil
}

// --- Apache ---

func apacheCtl() string {
	for _, c := range []string{"apache2ctl", "apachectl"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// apacheRoot is /etc/apache2 (Debian/Ubuntu, sites-available) or
// /etc/httpd (RHEL family, conf.d). LOADINME_APACHE_ROOT overrides it.
func apacheRoot() (root string, debian bool) {
	if r := os.Getenv("LOADINME_APACHE_ROOT"); r != "" {
		_, err := os.Stat(filepath.Join(r, "sites-available"))
		return r, err == nil
	}
	if _, err := os.Stat("/etc/apache2/sites-available"); err == nil {
		return "/etc/apache2", true
	}
	if _, err := os.Stat("/etc/httpd/conf.d"); err == nil {
		return "/etc/httpd", false
	}
	return "/etc/apache2", true
}

// apacheExposePaths returns the vhost file and (Debian) its
// sites-enabled link.
func apacheExposePaths(domain string) (file, link string) {
	root, debian := apacheRoot()
	name := "loadinme-" + strings.ToLower(domain) + ".conf"
	if debian {
		return filepath.Join(root, "sites-available", name), filepath.Join(root, "sites-enabled", name)
	}
	return filepath.Join(root, "conf.d", name), ""
}

// apacheChallengeVhost returns LoadInMe's enabled vhost file for the
// domain when it forwards the ACME challenge (renewals through Apache).
func apacheChallengeVhost(domain string) string {
	file, link := apacheExposePaths(domain)
	if link != "" {
		if _, err := os.Stat(link); err != nil {
			return ""
		}
	}
	b, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(b), "127.0.0.1:"+strconv.Itoa(acmeLoopbackPort())) {
		return ""
	}
	return file
}

type apacheVhost struct {
	Port  int
	Names []string
	File  string
}

var (
	apacheNameVhostRe = regexp.MustCompile(`port (\d+) namevhost (\S+) \((.+):\d+\)`)
	apacheSingleRe    = regexp.MustCompile(`^\s*\S*:(\d+)\s+(\S+) \((.+):\d+\)\s*$`)
	apacheAliasRe     = regexp.MustCompile(`^\s+alias (\S+)`)
)

// parseApacheVhosts reads `apachectl -S`.
func parseApacheVhosts(s string) []apacheVhost {
	var out []apacheVhost
	for _, line := range strings.Split(s, "\n") {
		if m := apacheNameVhostRe.FindStringSubmatch(line); m != nil {
			p, _ := strconv.Atoi(m[1])
			out = append(out, apacheVhost{Port: p, Names: []string{m[2]}, File: m[3]})
			continue
		}
		if m := apacheAliasRe.FindStringSubmatch(line); m != nil && len(out) > 0 {
			out[len(out)-1].Names = append(out[len(out)-1].Names, m[1])
			continue
		}
		if m := apacheSingleRe.FindStringSubmatch(line); m != nil && m[2] != "is" {
			p, _ := strconv.Atoi(m[1])
			out = append(out, apacheVhost{Port: p, Names: []string{m[2]}, File: m[3]})
		}
	}
	return out
}

func apacheVhostFile(vhosts []apacheVhost, domain string, port int, skip string) string {
	for _, v := range vhosts {
		if v.Port != port || (skip != "" && strings.Contains(filepath.Base(v.File), skip)) {
			continue
		}
		for _, n := range v.Names {
			if strings.EqualFold(n, domain) {
				return v.File
			}
		}
	}
	return ""
}

func apacheExposeConf(domain string, port int, cert, key string, redirect80 bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by LoadInMe: https://%s with no port.\n", domain)
	b.WriteString("# Remove it with: loadinme ssl unexpose (menu 6 → 6 → Undo).\n")
	fmt.Fprintf(&b, "<VirtualHost *:%d>\n", httpsPort())
	fmt.Fprintf(&b, "    ServerName %s\n", domain)
	b.WriteString("    SSLEngine on\n")
	fmt.Fprintf(&b, "    SSLCertificateFile \"%s\"\n", cert)
	fmt.Fprintf(&b, "    SSLCertificateKeyFile \"%s\"\n", key)
	b.WriteString("    ProxyRequests Off\n")
	b.WriteString("    ProxyPreserveHost On\n")
	b.WriteString("    RequestHeader set X-Forwarded-Proto \"https\"\n")
	fmt.Fprintf(&b, "    ProxyPass / http://127.0.0.1:%d/\n", port)
	fmt.Fprintf(&b, "    ProxyPassReverse / http://127.0.0.1:%d/\n", port)
	b.WriteString("    ProxyTimeout 900\n")
	b.WriteString("    # LoadInMe checks the upload size itself (Settings → max file size).\n")
	b.WriteString("    LimitRequestBody 0\n")
	b.WriteString("</VirtualHost>\n")
	if redirect80 {
		b.WriteString("<VirtualHost *:80>\n")
		fmt.Fprintf(&b, "    ServerName %s\n", domain)
		b.WriteString("    # Let's Encrypt renewals for LoadInMe (loadinme ssl renew).\n")
		fmt.Fprintf(&b, "    ProxyPass /.well-known/acme-challenge/ http://127.0.0.1:%d/.well-known/acme-challenge/\n", acmeLoopbackPort())
		fmt.Fprintf(&b, "    RedirectMatch 301 ^/(?!\\.well-known/acme-challenge/)(.*)$ https://%s/$1\n", domain)
		b.WriteString("</VirtualHost>\n")
	}
	return b.String()
}

func apacheConfigTest() error {
	ctl := apacheCtl()
	if ctl == "" {
		return errors.New("apachectl not found")
	}
	out, err := exec.Command(ctl, "configtest").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s configtest failed: %s", filepath.Base(ctl), strings.TrimSpace(lastLines(string(out), 3)))
	}
	return nil
}

func apacheReload() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		for _, u := range []string{"apache2", "httpd"} {
			if exec.Command("systemctl", "is-active", "--quiet", u).Run() == nil {
				if out, err := exec.Command("systemctl", "reload", u).CombinedOutput(); err != nil {
					return fmt.Errorf("systemctl reload %s: %v: %s", u, err, strings.TrimSpace(string(out)))
				}
				return nil
			}
		}
	}
	ctl := apacheCtl()
	if ctl == "" {
		return errors.New("apachectl not found")
	}
	if out, err := exec.Command(ctl, "graceful").CombinedOutput(); err != nil {
		return fmt.Errorf("%s graceful: %v: %s", filepath.Base(ctl), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyApache(cfg Config, plan exposePlan, out io.Writer) (ExposeInfo, error) {
	d := cfg.Domain
	file, link := apacheExposePaths(d)
	if link != "" {
		if _, err := exec.LookPath("a2enmod"); err == nil {
			if o, err := exec.Command("a2enmod", "-q", "proxy", "proxy_http", "ssl", "headers").CombinedOutput(); err != nil {
				return ExposeInfo{}, fmt.Errorf("could not enable the Apache modules (a2enmod proxy proxy_http ssl headers): %v: %s", err, strings.TrimSpace(string(o)))
			}
		}
	} else if ctl := apacheCtl(); ctl != "" {
		mods, _ := exec.Command(ctl, "-M").CombinedOutput()
		var missing []string
		for _, m := range []string{"ssl_module", "proxy_module", "proxy_http_module", "headers_module"} {
			if !strings.Contains(string(mods), m) {
				missing = append(missing, m)
			}
		}
		if len(missing) > 0 {
			return ExposeInfo{}, fmt.Errorf("Apache lacks %s (for ssl_module: sudo dnf install mod_ssl) — nothing changed", strings.Join(missing, ", "))
		}
	}
	if err := os.WriteFile(file, []byte(apacheExposeConf(d, cfg.Port, cfg.CertFile, cfg.KeyFile, plan.Redirect80)), 0o644); err != nil {
		return ExposeInfo{}, err
	}
	rollback := func() {
		if link != "" {
			_ = os.Remove(link)
		}
		_ = os.Remove(file)
	}
	if link != "" {
		_ = os.Remove(link)
		if err := os.Symlink("../sites-available/"+filepath.Base(file), link); err != nil {
			rollback()
			return ExposeInfo{}, err
		}
	}
	if err := apacheConfigTest(); err != nil {
		rollback()
		return ExposeInfo{}, fmt.Errorf("Apache did not accept the vhost, so it was removed again (nothing changed): %v", err)
	}
	if err := apacheReload(); err != nil {
		rollback()
		_ = apacheReload()
		return ExposeInfo{}, fmt.Errorf("Apache could not be reloaded, so the vhost was removed again: %v", err)
	}
	fmt.Fprintln(out, "✓ Added", file, "and reloaded Apache (configtest passed).")
	return ExposeInfo{Method: exposeApache, File: file, SiteLink: link, Redirect80: plan.Redirect80}, nil
}

// --- Caddy ---

func caddyBlock(domain string, port int) string {
	return fmt.Sprintf("# LoadInMe begin %[1]s (address without port; remove with: loadinme ssl unexpose)\n%[1]s {\n\treverse_proxy 127.0.0.1:%[2]d\n}\n# LoadInMe end %[1]s\n", domain, port)
}

// findCaddyfile finds the Caddyfile the running Caddy uses (its
// --config argument), else /etc/caddy/Caddyfile. "" when Caddy runs
// from JSON / the API. LOADINME_CADDYFILE overrides it.
func findCaddyfile(pid int) string {
	if f := os.Getenv("LOADINME_CADDYFILE"); f != "" {
		return f
	}
	if pid > 0 {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
			cfgArg, adapter := "", ""
			for i, a := range args {
				switch {
				case a == "--config" && i+1 < len(args):
					cfgArg = args[i+1]
				case strings.HasPrefix(a, "--config="):
					cfgArg = strings.TrimPrefix(a, "--config=")
				case a == "--adapter" && i+1 < len(args):
					adapter = args[i+1]
				case a == "--resume":
					return ""
				}
			}
			if cfgArg != "" {
				if strings.HasSuffix(cfgArg, ".json") || (adapter != "" && adapter != "caddyfile") {
					return ""
				}
				return cfgArg
			}
		}
	}
	if _, err := os.Stat("/etc/caddy/Caddyfile"); err == nil {
		return "/etc/caddy/Caddyfile"
	}
	return ""
}

// caddyfileHasSite reports whether a top-level site address in the
// Caddyfile is the domain (LoadInMe's own block does not count).
func caddyfileHasSite(content, domain string) bool {
	content = removeCaddyBlock(content, domain)
	depth := 0
	for _, line := range strings.Split(content, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		t := strings.TrimSpace(line)
		if depth == 0 && t != "" && !strings.HasPrefix(t, "(") {
			head := t
			if i := strings.Index(head, "{"); i >= 0 {
				head = head[:i]
			}
			for _, a := range strings.FieldsFunc(head, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
				a = strings.TrimPrefix(strings.TrimPrefix(a, "https://"), "http://")
				if h, _, err := net.SplitHostPort(a); err == nil {
					a = h
				}
				a = strings.TrimSuffix(a, "/")
				if strings.EqualFold(a, domain) {
					return true
				}
			}
		}
		depth += strings.Count(t, "{") - strings.Count(t, "}")
		if depth < 0 {
			depth = 0
		}
	}
	return false
}

// removeCaddyBlock drops LoadInMe's marked block for domain.
func removeCaddyBlock(content, domain string) string {
	begin := "# LoadInMe begin " + domain
	end := "# LoadInMe end " + domain
	lines := strings.Split(content, "\n")
	var out []string
	skip := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, begin) && (len(t) == len(begin) || t[len(begin)] == ' ') {
			skip = true
			// Drop one blank line LoadInMe put before the block.
			if n := len(out); n > 0 && strings.TrimSpace(out[n-1]) == "" {
				out = out[:n-1]
			}
			continue
		}
		if skip {
			if t == end {
				skip = false
			}
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func caddyValidate(file string) error {
	out, err := exec.Command("caddy", "validate", "--config", file, "--adapter", "caddyfile").CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddy validate failed: %s", strings.TrimSpace(lastLines(string(out), 3)))
	}
	return nil
}

func caddyReload(file string) error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if exec.Command("systemctl", "is-active", "--quiet", "caddy").Run() == nil {
			if out, err := exec.Command("systemctl", "reload", "caddy").CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl reload caddy: %v: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	out, err := exec.Command("caddy", "reload", "--config", file, "--adapter", "caddyfile").CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddy reload: %v: %s", err, strings.TrimSpace(lastLines(string(out), 3)))
	}
	return nil
}

func applyCaddy(cfg Config, plan exposePlan, out io.Writer) (ExposeInfo, error) {
	file := plan.Block
	fi, err := os.Stat(file)
	if err != nil {
		return ExposeInfo{}, err
	}
	orig, err := os.ReadFile(file)
	if err != nil {
		return ExposeInfo{}, err
	}
	content := strings.TrimRight(string(orig), "\n") + "\n\n" + caddyBlock(cfg.Domain, cfg.Port)
	if err := os.WriteFile(file, []byte(content), fi.Mode().Perm()); err != nil {
		return ExposeInfo{}, err
	}
	if err := caddyValidate(file); err != nil {
		_ = os.WriteFile(file, orig, fi.Mode().Perm())
		return ExposeInfo{}, fmt.Errorf("Caddy did not accept the block, so %s was restored (nothing changed): %v", file, err)
	}
	if err := caddyReload(file); err != nil {
		_ = os.WriteFile(file, orig, fi.Mode().Perm())
		_ = caddyReload(file)
		return ExposeInfo{}, fmt.Errorf("Caddy could not be reloaded, so %s was restored: %v", file, err)
	}
	fmt.Fprintln(out, "✓ Added the "+cfg.Domain+" block to", file, "and reloaded Caddy.")
	return ExposeInfo{Method: exposeCaddy, File: file}, nil
}

// --- the flow ---

type exposeRequest struct {
	Method string // "" / "auto", "nginx-manual", "apache-manual"
	Yes    bool
	In     *bufio.Scanner
	Out    io.Writer
}

func (r exposeRequest) confirm(q string, def bool) bool {
	if r.Yes {
		return true
	}
	return askYesNo(r.In, r.Out, q, def)
}

func (p exposePlan) needsRoot(cfg Config) bool {
	switch p.Method {
	case exposeDirect:
		ports := []int{httpsPort()}
		if p.Redirect80 {
			ports = append(ports, httpPort())
		}
		return setcapNeeded(cfg.DataDir, ports...)
	case exposeNginx, exposeApache, exposeCaddy:
		return !p.Manual
	}
	return false
}

// runExpose sets up the address without port. It does not restart the
// web UI (finishExpose does).
func runExpose(cfg *Config, req exposeRequest) error {
	out := req.Out
	d := cfg.Domain
	if d == "" {
		return errors.New("no domain yet — get SSL first (menu 6 → 1, or: loadinme ssl issue --domain …)")
	}
	if cfg.Expose != nil {
		fmt.Fprintln(out, "Already set up: https://"+d+" — "+exposeLabel(cfg.Expose.Method)+".")
		fmt.Fprintln(out, "To change it, undo it first (menu 6 → 6, or: loadinme ssl unexpose).")
		return nil
	}
	var plan exposePlan
	switch req.Method {
	case "", "auto":
		plan = planExpose(*cfg)
	case "nginx-manual", "apache-manual":
		plan = exposePlan{Method: exposeNginx, Manual: true}
		if req.Method == "apache-manual" {
			plan.Method = exposeApache
		}
		plan.Why = []string{"You added LoadInMe's block to your own " + strings.TrimSuffix(req.Method, "-manual") + " config.",
			"LoadInMe now listens on 127.0.0.1:" + strconv.Itoa(cfg.Port) + " only (plain http behind it); nothing else changes."}
	default:
		return fmt.Errorf("unknown method %q (auto, nginx-manual, apache-manual)", req.Method)
	}
	fmt.Fprintln(out, "Address without port for", d+":", exposeLabel(plan.Method))
	for _, l := range plan.Why {
		fmt.Fprintln(out, "  "+l)
	}
	fmt.Fprintln(out)
	switch plan.Method {
	case exposePlanAlready:
		return nil
	case exposePlanNoCert:
		return errors.New("get the SSL certificate first (menu 6 → 1 Get SSL), then set up the address without port")
	case exposePlanOther, exposePlanManual:
		for _, l := range plan.Hints {
			fmt.Fprintln(out, "  "+l)
		}
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Nothing was changed. LoadInMe stays at https://%s:%d.\n", d, cfg.Port)
		return errNoChange
	case exposePlanTaken:
		if plan.Server == "Caddy" {
			fmt.Fprintln(out, "Point that site at LoadInMe instead, then reload Caddy and choose this again:")
			for _, l := range indentLines("reverse_proxy 127.0.0.1:"+strconv.Itoa(cfg.Port), "    ") {
				fmt.Fprintln(out, l)
			}
			fmt.Fprintf(out, "\nNothing was changed. LoadInMe stays at https://%s:%d.\n", d, cfg.Port)
			return errNoChange
		}
		fmt.Fprintln(out, "To serve LoadInMe there, put this inside that block (in "+plan.Block+"), replacing its")
		fmt.Fprintln(out, "own `location /` if it has one:")
		fmt.Fprintln(out)
		block := nginxProxyLocation(cfg.Port)
		manual := "nginx-manual"
		if plan.Server == "Apache" {
			block = fmt.Sprintf("ProxyPreserveHost On\nRequestHeader set X-Forwarded-Proto \"https\"\nProxyPass / http://127.0.0.1:%d/\nProxyPassReverse / http://127.0.0.1:%d/\nLimitRequestBody 0", cfg.Port, cfg.Port)
			manual = "apache-manual"
		}
		for _, l := range indentLines(block, "    ") {
			fmt.Fprintln(out, l)
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  Then check and reload it yourself (nginx: sudo nginx -t && sudo systemctl reload nginx).")
		fmt.Fprintln(out, "  Once it is in, LoadInMe must listen on 127.0.0.1 only: choose this again and answer yes,")
		fmt.Fprintln(out, "  or run: loadinme ssl expose --method "+manual)
		fmt.Fprintln(out)
		if req.In == nil || req.Yes {
			fmt.Fprintf(out, "Nothing was changed. LoadInMe stays at https://%s:%d.\n", d, cfg.Port)
			return errNoChange
		}
		if !askYesNo(req.In, out, "Did you add it already (LoadInMe moves to 127.0.0.1 now)?", false) {
			fmt.Fprintf(out, "Nothing was changed. LoadInMe stays at https://%s:%d.\n", d, cfg.Port)
			return errNoChange
		}
		plan = exposePlan{Method: exposeNginx, Manual: true}
		if manual == "apache-manual" {
			plan.Method = exposeApache
		}
	}
	if plan.needsRoot(*cfg) && !isRoot() {
		return errNeedRoot
	}
	if !plan.Manual {
		q := "Go ahead?"
		switch plan.Method {
		case exposeDirect:
			q = "Serve https://" + d + " on port " + strconv.Itoa(httpsPort()) + " now?"
		case exposeNginx:
			q = "Add " + nginxExposePath(d) + " to nginx and reload nginx?"
		case exposeApache:
			f, _ := apacheExposePaths(d)
			q = "Add " + f + " to Apache and reload Apache?"
		case exposeCaddy:
			q = "Add the block to " + plan.Block + " and reload Caddy?"
		}
		if !req.confirm(q, true) {
			fmt.Fprintln(out, "Nothing was changed.")
			return errCancelled
		}
	}
	var info ExposeInfo
	var err error
	switch {
	case plan.Manual:
		info = ExposeInfo{Method: plan.Method, Manual: true}
	case plan.Method == exposeDirect:
		info = ExposeInfo{Method: exposeDirect, Redirect80: plan.Redirect80}
		ports := []int{httpsPort()}
		if plan.Redirect80 {
			ports = append(ports, httpPort())
		}
		if setcapNeeded(cfg.DataDir, ports...) {
			exe := selfExe()
			if err := setcapBind(exe); err != nil {
				return fmt.Errorf("could not allow LoadInMe to use port %d (%v) — install setcap (sudo apt install libcap2-bin) and try again. Nothing was changed", httpsPort(), err)
			}
			info.Setcap, info.SetcapExe = true, exe
			fmt.Fprintln(out, "✓ Allowed", exe, "to use ports below 1024 (setcap cap_net_bind_service=+ep).")
		}
	case plan.Method == exposeNginx:
		info, err = applyNginx(*cfg, plan, out)
	case plan.Method == exposeApache:
		info, err = applyApache(*cfg, plan, out)
	case plan.Method == exposeCaddy:
		info, err = applyCaddy(*cfg, plan, out)
	default:
		return fmt.Errorf("cannot set up %q", plan.Method)
	}
	if err != nil {
		return err
	}
	info.Since = time.Now().UTC()
	if info.Method != exposeDirect {
		info.PrevBind = cfg.BindAddress
		cfg.BindAddress = "127.0.0.1"
	}
	cfg.Expose = &info
	if err := saveConfig(*cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, "✓ Saved: https://"+d+" — "+exposeLabel(info.Method)+".")
	if info.Method != exposeDirect {
		fmt.Fprintf(out, "  LoadInMe now listens on 127.0.0.1:%d only (plain http behind %s).\n", cfg.Port, frontName(info.Method))
	}
	return nil
}

// errNoChange: the plan changes nothing (fallback); not a failure.
var errNoChange = errors.New("nothing changed")

func frontName(m string) string {
	switch m {
	case exposeNginx:
		return "nginx"
	case exposeApache:
		return "Apache"
	case exposeCaddy:
		return "Caddy"
	}
	return "LoadInMe"
}

// verifyExposed fetches https://<domain>/health through port 443 on
// this machine (so DNS and the firewall are not part of the check).
func verifyExposed(cfg Config, wait time.Duration) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort()))
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: cfg.Domain, InsecureSkipVerify: true}, //nolint:gosec // local check of our own setup; the CA may be a test CA
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	deadline := time.Now().Add(wait)
	var last error
	for {
		resp, err := client.Get("https://" + cfg.Domain + "/health")
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(b), `"status":"ok"`) {
				return nil
			}
			last = fmt.Errorf("got HTTP %d, not LoadInMe", resp.StatusCode)
		} else {
			last = err
		}
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// finishExpose restarts the web UI so the new listeners apply, and
// checks the address.
func finishExpose(cfg Config, out io.Writer) {
	fmt.Fprintln(out)
	restartWebUIAfterSSL(cfg, out)
	if cfg.Expose == nil {
		return
	}
	wait := 10 * time.Second
	if cfg.Expose.Method == exposeCaddy {
		wait = 45 * time.Second // Caddy may still be getting its certificate
	}
	if err := verifyExposed(cfg, wait); err != nil {
		fmt.Fprintln(out, "⚠ https://"+cfg.Domain+" did not answer on this server yet:", err)
		if cfg.Expose.Method == exposeCaddy {
			fmt.Fprintln(out, "  Caddy may still be getting its certificate — check again in a minute (6 → 6 → 1).")
		}
		fmt.Fprintln(out, "  Undo it any time: menu 6 → 6, or: loadinme ssl unexpose")
		return
	}
	fmt.Fprintln(out, "✓ https://"+cfg.Domain+" answers on this server (checked through port "+strconv.Itoa(httpsPort())+").")
	fmt.Fprintln(out, "  If it does not open from outside, allow port 443 (and 80) in the firewall,")
	fmt.Fprintln(out, "  e.g. sudo ufw allow 443/tcp && sudo ufw allow 80/tcp, and check the cloud provider's firewall.")
}

// unexposeSystem removes what LoadInMe added outside its data dir.
func unexposeSystem(info *ExposeInfo, out io.Writer) {
	switch info.Method {
	case exposeDirect:
		if info.Setcap {
			// The binary may have moved since (reinstalled elsewhere):
			// clear the one recorded and the one running.
			seen := map[string]bool{}
			for _, exe := range []string{info.SetcapExe, selfExe()} {
				if exe == "" || seen[exe] {
					continue
				}
				seen[exe] = true
				if _, err := os.Stat(exe); err != nil || !hasBindCap(exe) {
					continue
				}
				if err := setcapRemove(exe); err != nil {
					fmt.Fprintln(out, "⚠", err)
				} else {
					fmt.Fprintln(out, "Removed the port permission (setcap) from", exe)
				}
			}
		}
	case exposeNginx:
		if info.Manual {
			fmt.Fprintln(out, "Remember to take LoadInMe's `location /` back out of your own nginx server block.")
			return
		}
		if info.File != "" {
			_ = os.Remove(info.File)
			fmt.Fprintln(out, "Removed", info.File)
		}
		if err := nginxTest(); err != nil {
			fmt.Fprintln(out, "⚠ nginx -t failed after the removal (not reloaded):", err)
		} else if err := nginxReload(); err != nil {
			fmt.Fprintln(out, "⚠ Could not reload nginx:", err)
		} else {
			fmt.Fprintln(out, "Reloaded nginx.")
		}
	case exposeApache:
		if info.Manual {
			fmt.Fprintln(out, "Remember to take LoadInMe's ProxyPass lines back out of your own Apache vhost.")
			return
		}
		if info.SiteLink != "" {
			_ = os.Remove(info.SiteLink)
		}
		if info.File != "" {
			_ = os.Remove(info.File)
			fmt.Fprintln(out, "Removed", info.File)
		}
		if err := apacheConfigTest(); err != nil {
			fmt.Fprintln(out, "⚠ Apache configtest failed after the removal (not reloaded):", err)
		} else if err := apacheReload(); err != nil {
			fmt.Fprintln(out, "⚠ Could not reload Apache:", err)
		} else {
			fmt.Fprintln(out, "Reloaded Apache (the modules it enabled stay on; other sites may use them).")
		}
	case exposeCaddy:
		if info.File == "" {
			return
		}
		b, err := os.ReadFile(info.File)
		if err != nil {
			fmt.Fprintln(out, "⚠ Could not read", info.File+":", err)
			return
		}
		fi, _ := os.Stat(info.File)
		var domain string
		if m := regexp.MustCompile(`# LoadInMe begin (\S+)`).FindStringSubmatch(string(b)); m != nil {
			domain = m[1]
		}
		if domain == "" {
			return
		}
		cleaned := removeCaddyBlock(string(b), domain)
		if !strings.HasSuffix(cleaned, "\n") {
			cleaned += "\n"
		}
		if err := os.WriteFile(info.File, []byte(cleaned), fi.Mode().Perm()); err != nil {
			fmt.Fprintln(out, "⚠", err)
			return
		}
		fmt.Fprintln(out, "Removed the "+domain+" block from", info.File)
		if err := caddyReload(info.File); err != nil {
			fmt.Fprintln(out, "⚠ Could not reload Caddy:", err)
		} else {
			fmt.Fprintln(out, "Reloaded Caddy.")
		}
	}
}

func (i *ExposeInfo) undoNeedsRoot() bool {
	switch i.Method {
	case exposeDirect:
		return i.Setcap
	case exposeNginx, exposeApache, exposeCaddy:
		return !i.Manual
	}
	return false
}

// runUnexpose undoes the address without port: snippets removed, the
// bind address restored, setcap removed. The port never changed.
func runUnexpose(cfg *Config, out io.Writer) error {
	if cfg.Expose == nil {
		fmt.Fprintln(out, "The address without port is not set up — nothing to undo.")
		return nil
	}
	if cfg.Expose.undoNeedsRoot() && !isRoot() {
		return errNeedRoot
	}
	unexposeSystem(cfg.Expose, out)
	cfg.BindAddress = cfg.Expose.PrevBind
	cfg.Expose = nil
	if err := saveConfig(*cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, "✓ Undone. LoadInMe is back at", webAddressFor(*cfg))
	return nil
}

// reloadFrontAfterCert reloads nginx / Apache after the certificate
// changed: they read it only when they (re)load.
func reloadFrontAfterCert(cfg Config, out io.Writer) {
	if cfg.Expose == nil {
		return
	}
	var test, reload func() error
	switch cfg.Expose.Method {
	case exposeNginx:
		test, reload = nginxTest, nginxReload
	case exposeApache:
		test, reload = apacheConfigTest, apacheReload
	default:
		return
	}
	name := frontName(cfg.Expose.Method)
	if !isRoot() {
		fmt.Fprintf(out, "Reload %s so it serves the new certificate: sudo systemctl reload %s\n", name, strings.ToLower(name))
		return
	}
	if err := test(); err != nil {
		fmt.Fprintf(out, "⚠ %s config check failed, so it was not reloaded: %v\n", name, err)
		return
	}
	if err := reload(); err != nil {
		fmt.Fprintf(out, "⚠ Could not reload %s: %v\n", name, err)
		return
	}
	fmt.Fprintf(out, "✓ Reloaded %s so it serves the new certificate.\n", name)
}

// printExposeStatus is the "Address" line of the SSL status.
func printExposeStatus(cfg Config, out io.Writer) {
	if cfg.Domain == "" {
		return
	}
	if cfg.Expose != nil {
		fmt.Fprintln(out, "Address: https://"+cfg.Domain+" — no port, "+exposeLabel(cfg.Expose.Method))
		switch {
		case cfg.proxied():
			fmt.Fprintf(out, "         LoadInMe listens on 127.0.0.1:%d (plain http behind %s)\n", cfg.Port, frontName(cfg.Expose.Method))
		case cfg.Expose.Redirect80:
			fmt.Fprintf(out, "         also on port %d (own port) and port 80 (redirect to https://)\n", cfg.Port)
		default:
			fmt.Fprintf(out, "         also on port %d (own port)\n", cfg.Port)
		}
		return
	}
	if cfg.TLSEnabled {
		fmt.Fprintln(out, "Address:", webAddressFor(cfg), "— with a port (6 → 6 Address without port can drop it)")
	}
}

// removeExposePieces is the uninstall part: undo what is in the config
// and remove any leftover LoadInMe snippets (needs root).
func removeExposePieces(cfg *Config, out io.Writer) {
	if cfg.Expose != nil {
		unexposeSystem(cfg.Expose, out)
		cfg.BindAddress = cfg.Expose.PrevBind
		cfg.Expose = nil
		_ = saveConfig(*cfg)
	}
	reloadNginx := false
	if m, _ := filepath.Glob(filepath.Join(nginxConfDir(), "loadinme-*.conf")); len(m) > 0 {
		for _, f := range m {
			_ = os.Remove(f)
			fmt.Fprintln(out, "Removed leftover nginx file", f)
		}
		reloadNginx = true
	}
	if reloadNginx && nginxTest() == nil {
		_ = nginxReload()
	}
	root, debian := apacheRoot()
	var leftovers []string
	if debian {
		a, _ := filepath.Glob(filepath.Join(root, "sites-enabled", "loadinme-*.conf"))
		b, _ := filepath.Glob(filepath.Join(root, "sites-available", "loadinme-*.conf"))
		leftovers = append(a, b...)
	} else {
		leftovers, _ = filepath.Glob(filepath.Join(root, "conf.d", "loadinme-*.conf"))
	}
	for _, f := range leftovers {
		_ = os.Remove(f)
		fmt.Fprintln(out, "Removed leftover Apache file", f)
	}
	if len(leftovers) > 0 && apacheConfigTest() == nil {
		_ = apacheReload()
	}
}

func exposePiecesPresent(cfg Config) bool {
	if cfg.Expose != nil && cfg.Expose.undoNeedsRoot() {
		return true
	}
	if m, _ := filepath.Glob(filepath.Join(nginxConfDir(), "loadinme-*.conf")); len(m) > 0 {
		return true
	}
	root, debian := apacheRoot()
	pat := filepath.Join(root, "conf.d", "loadinme-*.conf")
	if debian {
		pat = filepath.Join(root, "sites-available", "loadinme-*.conf")
	}
	m, _ := filepath.Glob(pat)
	return len(m) > 0
}
