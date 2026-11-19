package main

import (
	"bufio"
	"context"
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
	"time"
)

// How LoadInMe proves the domain is yours (HTTP-01 needs port 80):
//
//	standalone      port 80 is free: LoadInMe answers on :80 itself for a few seconds
//	nginx           nginx owns port 80: a temporary conf.d snippet forwards only
//	                /.well-known/acme-challenge/ to LoadInMe on 127.0.0.1 (no downtime)
//	nginx-existing  nginx already has a server block for the domain, with the
//	                one-line challenge proxy the user added to it
//	stop-service    something else owns port 80: its systemd unit is stopped for
//	                the few seconds of the challenge and always started again
//	dns-cloudflare  DNS-01 through the Cloudflare API: port 80 not needed at all
//	loadinme-port80 LoadInMe itself holds port 80 (address without port,
//	                v0.8.0): its running :80 listener serves the challenge
//	                files the issuing process writes (nothing pauses)
//	apache-existing Apache owns port 80 and serves LoadInMe's port-80 vhost,
//	                which forwards the challenge to 127.0.0.1:41580
const (
	methodSelf80         = "loadinme-port80"
	methodApacheExisting = "apache-existing"
	methodStandalone     = "standalone"
	methodNginx          = "nginx"
	methodNginxExisting  = "nginx-existing"
	methodStopService    = "stop-service"
	methodDNSCloudflare  = "dns-cloudflare"
	// planNginxConflict is a plan, not a method: nginx already serves
	// the domain on port 80 and has no challenge line yet.
	planNginxConflict = "nginx-conflict"
	planBlocked       = "blocked"
)

func methodLabel(m string) string {
	switch m {
	case methodStandalone:
		return "HTTP on port 80 (LoadInMe answers itself)"
	case methodNginx:
		return "HTTP through nginx (temporary snippet, no downtime)"
	case methodNginxExisting:
		return "HTTP through your nginx server block"
	case methodStopService:
		return "HTTP on port 80 (the service on port 80 pauses for a few seconds)"
	case methodDNSCloudflare:
		return "DNS through Cloudflare"
	case methodSelf80:
		return "HTTP on port 80 (LoadInMe's own port-80 listener answers, nothing pauses)"
	case methodApacheExisting:
		return "HTTP through Apache (LoadInMe's port-80 vhost forwards the check)"
	case "certbot":
		return "certbot (old setup, outside LoadInMe)"
	case planNginxConflict:
		return "nginx already serves this domain — one line needed"
	case planBlocked:
		return "port 80 is busy and cannot be used"
	}
	return m
}

// acmeLoopbackPort is the fixed 127.0.0.1 port nginx forwards the
// challenge to when the user adds the proxy line to their own server
// block (the line is permanent, so the port must not change).
func acmeLoopbackPort() int {
	if v := os.Getenv("LOADINME_ACME_LOOPBACK_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 41580
}

func nginxConfDir() string {
	if d := os.Getenv("LOADINME_NGINX_CONF_DIR"); d != "" {
		return d
	}
	return "/etc/nginx/conf.d"
}

func nginxSnippetPath(domain string) string {
	return filepath.Join(nginxConfDir(), "loadinme-acme-"+strings.ToLower(domain)+".conf")
}

// nginxChallengeLine is the one line to add to an existing nginx
// server block (port 80) for the domain.
func nginxChallengeLine() string {
	return fmt.Sprintf("location /.well-known/acme-challenge/ { proxy_pass http://127.0.0.1:%d; }", acmeLoopbackPort())
}

// --- who owns port 80? ---

type portOwner struct {
	Free    bool
	PID     int
	Process string // e.g. "nginx"
	Unit    string // systemd unit, e.g. "apache2.service"
}

func (o portOwner) describe() string {
	if o.Free {
		return "nothing (port 80 is free)"
	}
	s := o.Process
	if s == "" {
		s = "an unknown program"
	}
	if o.PID > 0 {
		s += " (pid " + strconv.Itoa(o.PID) + ")"
	}
	if o.Unit != "" {
		s += ", systemd unit " + o.Unit
	}
	return s
}

// listeningOn reports whether some socket listens on TCP port, from
// /proc/net/tcp{,6} (works without root, unlike binding port 80).
// ok=false when /proc is not available.
func listeningOn(port int) (listening bool, inodes []string, ok bool) {
	hexPort := fmt.Sprintf(":%04X", port)
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		ok = true
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			if strings.HasSuffix(fields[1], hexPort) && fields[3] == "0A" { // 0A = LISTEN
				listening = true
				inodes = append(inodes, fields[9])
			}
		}
	}
	return listening, inodes, ok
}

var ssUserRe = regexp.MustCompile(`\(\("([^"]+)",pid=(\d+)`)

// detectPort80 finds out whether port 80 is free and, if not, which
// process (and systemd unit) holds it. Without root the PID may be
// unknown.
func detectPort80() portOwner { return detectPortOwner(80) }

// detectPortOwner is detectPort80 for any TCP port (v0.8.0 uses it
// for 443 too).
func detectPortOwner(port int) portOwner {
	listening, inodes, ok := listeningOn(port)
	if !ok {
		// No /proc (not Linux): fall back to a bind test.
		if portFree(port) {
			return portOwner{Free: true}
		}
		return portOwner{}
	}
	if !listening {
		return portOwner{Free: true}
	}
	o := portOwner{}
	// ss -tlnp names the process (root sees every process).
	if out, err := exec.Command("ss", "-H", "-tlnp", "sport = :"+strconv.Itoa(port)).Output(); err == nil {
		if m := ssUserRe.FindStringSubmatch(string(out)); m != nil {
			o.Process = m[1]
			o.PID, _ = strconv.Atoi(m[2])
		}
	}
	if o.PID == 0 {
		o.PID = pidForSocketInodes(inodes)
	}
	if o.PID > 0 {
		if o.Process == "" {
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", o.PID)); err == nil {
				o.Process = strings.TrimSpace(string(b))
			}
		}
		o.Unit = unitForPID(o.PID)
	}
	return o
}

// pidForSocketInodes scans /proc/*/fd for one of the socket inodes.
func pidForSocketInodes(inodes []string) int {
	want := map[string]bool{}
	for _, i := range inodes {
		want["socket:["+i+"]"] = true
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(filepath.Join("/proc", p.Name(), "fd", fd.Name())); err == nil && want[l] {
				return pid
			}
		}
	}
	return 0
}

// unitForPID reads the systemd unit from /proc/<pid>/cgroup
// ("0::/system.slice/apache2.service" → "apache2.service").
func unitForPID(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return unitFromCgroup(string(b))
}

func unitFromCgroup(s string) string {
	for _, line := range strings.Split(s, "\n") {
		i := strings.LastIndex(line, ":")
		if i < 0 {
			continue
		}
		parts := strings.Split(line[i+1:], "/")
		for j := len(parts) - 1; j >= 0; j-- {
			if strings.HasSuffix(parts[j], ".service") {
				return parts[j]
			}
		}
	}
	return ""
}

// --- nginx config inspection ---

type nginxServer struct {
	File        string
	Listens     []string
	ServerNames []string
	Body        string
}

// listensOn80 reports whether the server block takes plain HTTP on
// port 80 (no listen directive at all means port 80 too).
func (s nginxServer) listensOn80() bool { return s.listensOnPort("80") }

// listensOnPort reports whether the server block listens on port
// (an address with no port, or no listen directive at all, is 80).
func (s nginxServer) listensOnPort(want string) bool {
	if len(s.Listens) == 0 {
		return want == "80"
	}
	for _, l := range s.Listens {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "unix:") {
			continue
		}
		addr := f[0]
		port := addr
		if strings.HasPrefix(addr, "[") {
			if i := strings.LastIndex(addr, "]:"); i >= 0 {
				port = addr[i+2:]
			} else {
				port = "80"
			}
		} else if i := strings.LastIndex(addr, ":"); i >= 0 {
			port = addr[i+1:]
		} else if _, err := strconv.Atoi(addr); err != nil {
			port = "80" // an address with no port
		}
		if port == want {
			return true
		}
	}
	return false
}

func (s nginxServer) hasName(domain string) bool {
	for _, n := range s.ServerNames {
		if strings.EqualFold(n, domain) {
			return true
		}
	}
	return false
}

// hasChallengeProxy reports whether the block already forwards the
// challenge to LoadInMe's fixed loopback port.
func (s nginxServer) hasChallengeProxy() bool {
	return strings.Contains(s.Body, "/.well-known/acme-challenge") &&
		strings.Contains(s.Body, "127.0.0.1:"+strconv.Itoa(acmeLoopbackPort()))
}

// stripNginxComments drops # comments (outside quotes).
func stripNginxComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		inQ := byte(0)
		cut := len(line)
		for i := 0; i < len(line); i++ {
			c := line[i]
			if inQ != 0 {
				if c == inQ {
					inQ = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				inQ = c
			} else if c == '#' {
				cut = i
				break
			}
		}
		b.WriteString(line[:cut])
		b.WriteByte('\n')
	}
	return b.String()
}

var nginxFileMarker = regexp.MustCompile(`(?m)^# configuration file (.+):\s*$`)

// parseNginxServers finds the http server blocks in `nginx -T` output.
func parseNginxServers(dump string) []nginxServer {
	// Split by "# configuration file X:" markers so each block knows
	// its file.
	var out []nginxServer
	locs := nginxFileMarker.FindAllStringSubmatchIndex(dump, -1)
	type chunk struct{ file, text string }
	var chunks []chunk
	if len(locs) == 0 {
		chunks = append(chunks, chunk{"", dump})
	}
	for i, l := range locs {
		end := len(dump)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		chunks = append(chunks, chunk{dump[l[2]:l[3]], dump[l[1]:end]})
	}
	for _, c := range chunks {
		text := stripNginxComments(c.text)
		for i := 0; i < len(text); i++ {
			if !strings.HasPrefix(text[i:], "server") {
				continue
			}
			if i > 0 && !isNginxSpace(text[i-1]) && text[i-1] != '{' && text[i-1] != '}' && text[i-1] != ';' {
				continue
			}
			j := i + len("server")
			for j < len(text) && isNginxSpace(text[j]) {
				j++
			}
			if j >= len(text) || text[j] != '{' {
				continue
			}
			// Find the matching brace.
			depth := 0
			k := j
			for ; k < len(text); k++ {
				if text[k] == '{' {
					depth++
				} else if text[k] == '}' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if k >= len(text) {
				break
			}
			body := text[j+1 : k]
			srv := nginxServer{File: c.file, Body: body}
			for _, d := range topLevelDirectives(body) {
				f := strings.Fields(d)
				if len(f) == 0 {
					continue
				}
				switch f[0] {
				case "listen":
					srv.Listens = append(srv.Listens, strings.Join(f[1:], " "))
				case "server_name":
					srv.ServerNames = append(srv.ServerNames, f[1:]...)
				}
			}
			out = append(out, srv)
			i = k
		}
	}
	return out
}

func isNginxSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// topLevelDirectives returns the directives at depth 0 of a block
// body (nested blocks such as location { … } are skipped).
func topLevelDirectives(body string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				start = i + 1
			}
		case ';':
			if depth == 0 {
				out = append(out, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	return out
}

// findNginxBlockFor returns the enabled port-80 server block that
// uses domain as a server_name (skipping LoadInMe's own snippet).
func findNginxBlockFor(dump, domain string) (nginxServer, bool) {
	return findNginxBlockOn(dump, domain, "80", "loadinme-acme-")
}

// findNginxBlockOn returns the enabled server block listening on port
// with domain as a server_name, skipping files whose name contains
// any of skip.
func findNginxBlockOn(dump, domain, port string, skip ...string) (nginxServer, bool) {
	for _, s := range parseNginxServers(dump) {
		skipped := false
		for _, sk := range skip {
			if strings.Contains(filepath.Base(s.File), sk) {
				skipped = true
			}
		}
		if skipped {
			continue
		}
		if s.listensOnPort(port) && s.hasName(domain) {
			return s, true
		}
	}
	return nginxServer{}, false
}

func nginxDump() (string, error) {
	out, err := exec.Command("nginx", "-T").CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("nginx -T: %v: %s", err, strings.TrimSpace(lastLines(string(out), 3)))
	}
	return string(out), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// nginxReload reloads nginx through systemd when it manages nginx,
// otherwise with nginx -s reload.
func nginxReload() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if exec.Command("systemctl", "is-active", "--quiet", "nginx").Run() == nil {
			if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl reload nginx: %v: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	if out, err := exec.Command("nginx", "-s", "reload").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -s reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nginxTest() error {
	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %s", strings.TrimSpace(lastLines(string(out), 3)))
	}
	return nil
}

func nginxSnippet(domain string, port int, ipv6 bool) string {
	v6 := ""
	if ipv6 {
		v6 = "    listen [::]:80;\n"
	}
	return fmt.Sprintf(`# Written by LoadInMe for the few seconds it takes to get an SSL
# certificate for %[1]s. LoadInMe removes it again by itself; if you
# ever find it left behind, it is safe to delete.
server {
    listen 80;
%[3]s    server_name %[1]s;
    location /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:%[2]d;
        proxy_set_header Host $host;
    }
    location / {
        return 404;
    }
}
`, domain, port, v6)
}

// installNginxSnippet writes the temporary server block, checks the
// config and reloads nginx. The returned remove func deletes the file
// and reloads again; it is safe to call more than once.
func installNginxSnippet(domain string, port int, out io.Writer) (remove func(), err error) {
	path := nginxSnippetPath(domain)
	removed := false
	remove = func() {
		if removed {
			return
		}
		removed = true
		_ = os.Remove(path)
		if err := nginxReload(); err != nil {
			fmt.Fprintln(out, "Warning: could not reload nginx after removing", path+":", err)
		} else {
			fmt.Fprintln(out, "Removed the temporary nginx snippet and reloaded nginx.")
		}
	}
	try := func(ipv6 bool) error {
		if err := os.WriteFile(path, []byte(nginxSnippet(domain, port, ipv6)), 0o644); err != nil {
			return err
		}
		return nginxTest()
	}
	if err := try(true); err != nil {
		// IPv6 may be off on this host: try IPv4 only.
		if err2 := try(false); err2 != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("could not add the temporary nginx snippet %s: %v", path, err)
		}
	}
	// Make sure nginx actually includes conf.d.
	if dump, err := nginxDump(); err == nil && !strings.Contains(dump, "# configuration file "+path+":") {
		_ = os.Remove(path)
		return nil, fmt.Errorf("nginx does not include %s/*.conf, so the snippet would not be used", nginxConfDir())
	}
	if err := nginxReload(); err != nil {
		_ = os.Remove(path)
		_ = nginxReload()
		return nil, err
	}
	fmt.Fprintln(out, "Added", path, "and reloaded nginx (nothing else changes; it is removed right after).")
	return remove, nil
}

// --- systemd unit stop/start (strategy c) ---

func systemctlRoot(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitPortState waits until port 80 is free (wantFree) or taken.
func waitPort80(wantFree bool, max time.Duration) bool {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		l, _, ok := listeningOn(80)
		if !ok {
			l = !portFree(80)
		}
		if l != wantFree {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// --- pre-flight: does the domain point here? ---

// cloudflareIPv4 are Cloudflare's published proxy ranges
// (https://www.cloudflare.com/ips-v4).
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func isCloudflareIP(ip net.IP) bool {
	for _, c := range cloudflareRanges {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// localIPs lists this machine's interface addresses.
func localIPs() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP)
		}
	}
	return out
}

// publicIP asks a public echo service for this server's IPv4 address
// (LOADINME_PUBLIC_IP overrides it; "" when unknown).
func publicIP() string {
	if v := os.Getenv("LOADINME_PUBLIC_IP"); v != "" {
		return v
	}
	client := &http.Client{Timeout: 4 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil {
			return ip.String()
		}
	}
	return ""
}

type preflightResult struct {
	OK       bool
	Lines    []string
	Resolved []net.IP
}

// preflight resolves the domain and compares it with this server.
func preflight(domain string) preflightResult {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(addrs) == 0 {
		return preflightResult{Lines: []string{
			"⚠ " + domain + " does not resolve to any address yet (no A/AAAA record found).",
			"  Add an A record for " + domain + " pointing at this server's IP, wait a few minutes, then try again.",
		}}
	}
	var resolved []net.IP
	var shown []string
	for _, a := range addrs {
		resolved = append(resolved, a.IP)
		shown = append(shown, a.IP.String())
	}
	mine := map[string]bool{}
	for _, ip := range localIPs() {
		mine[ip.String()] = true
	}
	pub := publicIP()
	if pub != "" {
		mine[pub] = true
	}
	for _, ip := range resolved {
		if mine[ip.String()] {
			return preflightResult{OK: true, Resolved: resolved,
				Lines: []string{"✓ " + domain + " points to this server (" + strings.Join(shown, ", ") + ")."}}
		}
	}
	allCF := true
	for _, ip := range resolved {
		if !isCloudflareIP(ip) {
			allCF = false
		}
	}
	if allCF {
		return preflightResult{OK: true, Resolved: resolved, Lines: []string{
			"✓ " + domain + " points to Cloudflare (" + strings.Join(shown, ", ") + ") — the orange-cloud proxy.",
			"  That is fine for this check: Cloudflare passes the challenge on to this server over port 80.",
			"  Note: through the proxy, browsers can only reach HTTPS ports 443, 2053, 2083, 2087, 2096 and 8443.",
		}}
	}
	here := pub
	if here == "" {
		here = "(could not find out)"
	}
	return preflightResult{Resolved: resolved, Lines: []string{
		"⚠ " + domain + " points to " + strings.Join(shown, ", ") + ", but this server's public IP is " + here + ".",
		"  Let's Encrypt would knock on the wrong server, so the check would fail.",
		"  Fix the A record for " + domain + " (it should point at " + here + "), wait a few minutes, then try again.",
	}}
}

// --- renewal timer (root) ---

func systemdSystemDir() string {
	if d := os.Getenv("LOADINME_SYSTEMD_DIR"); d != "" {
		return d
	}
	return "/etc/systemd/system"
}

const renewTimerName = "loadinme-renew.timer"

func renewUnitFiles(exe, dataDir string) (service, timer string) {
	service = fmt.Sprintf(`[Unit]
Description=LoadInMe — renew the SSL certificate when it is close to expiry
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s ssl renew --data-dir %s
`, exe, dataDir)
	timer = `[Unit]
Description=LoadInMe — check the SSL certificate twice a day

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
`
	return service, timer
}

// installRenewTimer writes and enables loadinme-renew.timer (needs root).
func installRenewTimer(exe, dataDir string) error {
	dir := systemdSystemDir()
	svc, tmr := renewUnitFiles(exe, dataDir)
	if err := os.WriteFile(filepath.Join(dir, "loadinme-renew.service"), []byte(svc), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, renewTimerName), []byte(tmr), 0o644); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found, so the timer files were written to %s but not enabled", dir)
	}
	if err := systemctlRoot("daemon-reload"); err != nil {
		return err
	}
	return systemctlRoot("enable", "--now", renewTimerName)
}

func renewTimerInstalled() bool {
	_, err := os.Stat(filepath.Join(systemdSystemDir(), renewTimerName))
	return err == nil
}

func renewTimerActive() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", renewTimerName).Run() == nil
}

// removeSystemPieces removes the renewal timer and any leftover nginx
// snippet (needs root). It reports what it removed.
func removeSystemPieces(out io.Writer) {
	if renewTimerInstalled() {
		if _, err := exec.LookPath("systemctl"); err == nil {
			_ = exec.Command("systemctl", "disable", "--now", renewTimerName).Run()
		}
		_ = os.Remove(filepath.Join(systemdSystemDir(), renewTimerName))
		_ = os.Remove(filepath.Join(systemdSystemDir(), "loadinme-renew.service"))
		if _, err := exec.LookPath("systemctl"); err == nil {
			_ = exec.Command("systemctl", "daemon-reload").Run()
		}
		fmt.Fprintln(out, "Removed the renewal timer ("+renewTimerName+").")
	}
	matches, _ := filepath.Glob(filepath.Join(nginxConfDir(), "loadinme-acme-*.conf"))
	if len(matches) > 0 {
		for _, m := range matches {
			_ = os.Remove(m)
			fmt.Fprintln(out, "Removed leftover nginx snippet", m)
		}
		if nginxTest() == nil {
			_ = nginxReload()
		}
	}
}

// systemPiecesPresent reports whether uninstall has root-owned pieces
// to remove.
func systemPiecesPresent() bool {
	if renewTimerInstalled() {
		return true
	}
	m, _ := filepath.Glob(filepath.Join(nginxConfDir(), "loadinme-acme-*.conf"))
	return len(m) > 0
}

// askYesNo is a small prompt helper for the SSL flow: "0" cancels
// (returns false), an empty answer takes def. A nil scanner means
// non-interactive: the default is taken.
func askYesNo(sc *bufio.Scanner, out io.Writer, q string, def bool) bool {
	if sc == nil {
		return def
	}
	d := "n"
	if def {
		d = "y"
	}
	fmt.Fprintf(out, "%s (y/n) [%s] (0 to cancel): ", q, d)
	if !sc.Scan() {
		return def
	}
	a := strings.ToLower(strings.TrimSpace(sc.Text()))
	switch a {
	case "":
		return def
	case "y", "yes":
		return true
	}
	return false
}
