package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SSH menu — what you see when you SSH into your Ubuntu server and run
// `loadinme menu` (or just `loadinme` with no arguments on a server
// where the service is not running).
//
// The web address is always on top, so you can copy it into your browser.
//
// Menu:
//   1 Start   2 Stop   3 Restart   4 Status   5 Change port
//   6 Domain & SSL (1 Get SSL, 2 List & revoke, 3 Clear saved domain)
//   7 Update
//   8 Reset / change username & password   9 View settings
//   10 Show web UI link   11 Uninstall   0 Exit (silent, no farewell)

func webAddressFor(cfg Config) string {
	if cfg.Domain != "" {
		if cfg.TLSEnabled {
			return "https://" + cfg.Domain
		}
		if cfg.Port == 80 {
			return "http://" + cfg.Domain
		}
		return fmt.Sprintf("http://%s:%d", cfg.Domain, cfg.Port)
	}
	if ip := outboundIP(); ip != "" {
		return fmt.Sprintf("http://%s:%d", ip, cfg.Port)
	}
	hostname, _ := os.Hostname()
	if hostname != "" {
		return fmt.Sprintf("http://%s:%d  (or http://localhost:%d)", hostname, cfg.Port, cfg.Port)
	}
	return fmt.Sprintf("http://localhost:%d", cfg.Port)
}

func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

func printMenuHeader(cfg Config) {
	running := isServiceRunning(cfg)
	fmt.Print("\033[H\033[2J")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  ⬆ LoadInMe  —  Web UI: %s\n", webAddressFor(cfg))
	if running {
		fmt.Println("  Status: web UI is RUNNING  ·  open the address above in your browser")
	} else {
		fmt.Println("  Status: web UI is stopped  ·  choose 1 to start it")
	}
	if cfg.TLSEnabled {
		fmt.Println("  SSL: on")
	} else if cfg.Domain != "" {
		fmt.Println("  SSL: off  ·  domain:", cfg.Domain)
	}
	fmt.Printf("  Port: %d  ·  Data: %s\n", cfg.Port, cfg.DataDir)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}

func pause(scanner *bufio.Scanner) {
	fmt.Print("\nPress Enter to return to the menu… ")
	scanner.Scan()
}

// promptCancel asks for a value. Typing exactly "0" cancels the step
// (returns cancelled=true) — "0" is never accepted as a value, so it
// can never become a port, a domain, an email or an answer. An empty
// answer keeps the default, as before; EOF also keeps the default.
func promptCancel(scanner *bufio.Scanner, label, def string) (string, bool) {
	if def != "" {
		fmt.Printf("%s [%s] (0 to cancel): ", label, def)
	} else {
		fmt.Printf("%s (0 to cancel): ", label)
	}
	if !scanner.Scan() {
		return def, false
	}
	v := strings.TrimSpace(scanner.Text())
	if v == "0" {
		return "", true
	}
	if v == "" {
		return def, false
	}
	return v, false
}

// --- service control: systemd user service when available,
// otherwise a nohup background process tracked by a PID file. ---

func pidFile(cfg Config) string { return filepath.Join(cfg.DataDir, "loadinme.pid") }

func hasSystemdUser() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "--user", "status").Run() == nil ||
		os.Getenv("XDG_RUNTIME_DIR") != ""
}

func serviceFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "loadinme.service")
}

func installServiceFile(cfg Config) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	content := `[Unit]
Description=LoadInMe — file and text sharing
After=network-online.target
Wants=network-online.target
# systemd refuses to start a unit "too often" (default: 5 starts
# in 10s) and leaves it in a failed state until someone runs
# reset-failed. Menu restarts and installer restarts must never be
# refused that way — and neither must a test suite that starts and
# stops the same unit many times in a row (CI run #25 tripped this).
# StartLimitIntervalSec=0 disables the rate limit entirely.
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=` + filepath.Dir(exe) + `
ExecStart=` + exe + ` serve --port ` + strconv.Itoa(cfg.Port) + ` --data-dir ` + cfg.DataDir + `
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`
	path := serviceFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

// errAlreadyRunning is returned by startService when the web UI is
// already answering /health.
var errAlreadyRunning = errors.New("web UI is already running")

// probeHealth reports whether the web UI answers /health on localhost.
// A live /health response is the definitive proof the UI is up, however
// it was started (systemd, nohup, or by hand).
func probeHealth(cfg Config) bool {
	scheme := "http"
	if cfg.TLSEnabled {
		scheme = "https"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if cfg.TLSEnabled {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // localhost probe of our own server
	}
	resp, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/health", scheme, cfg.Port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// waitHealthy waits up to ~10s for the web UI to answer /health.
func waitHealthy(cfg Config) bool {
	for i := 0; i < 20; i++ {
		if probeHealth(cfg) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// pidAlive reports whether a process with this PID exists (signal 0).
// The old code used p.Signal(os.Signal(nil)), which always errors, so
// the menu never reported the nohup process as running.
// A zombie still answers signal 0 but is already dead, so on Linux a
// process in state Z (see /proc/<pid>/stat) counts as not alive —
// otherwise a lingering zombie would look like a live web UI and a
// stop-wait would time out for a process that is already gone.
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if p.Signal(syscall.Signal(0)) != nil {
		return false
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		if i := strings.LastIndex(string(b), ") "); i >= 0 && len(string(b)) > i+2 {
			return string(b)[i+2] != 'Z'
		}
	}
	return true
}

// waitStopped waits up to 5s for the process to die AND the port to go
// quiet. A stop that returns while the old process still holds the
// port (or the database lock) makes the next start fail — either it
// sees /health still answering and returns errAlreadyRunning, or the
// new daemon cannot bind / open the DB and exits.
func waitStopped(cfg Config, pid int) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !pidAlive(pid) && !probeHealth(cfg) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("web UI did not stop within 5s: process %d still alive or port %d still answering /health", pid, cfg.Port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitServiceStopped is the same wait for the systemd path, where
// there is no PID to watch — it polls isServiceRunning instead.
func waitServiceStopped(cfg Config) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !isServiceRunning(cfg) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("web UI did not stop within 5s: port %d still answering /health", cfg.Port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func pidFromFile(cfg Config) (int, bool) {
	b, err := os.ReadFile(pidFile(cfg))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// startService starts the web UI (systemd user service when available,
// otherwise a nohup background process) and waits until /health
// answers. It is idempotent: if the UI is already up it returns
// errAlreadyRunning instead of starting a second copy.
func startService(cfg Config) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return startServiceExe(cfg, exe)
}

func startServiceExe(cfg Config, exe string) error {
	exe, _ = filepath.EvalSymlinks(exe)
	if probeHealth(cfg) {
		return errAlreadyRunning
	}
	// A fresh install has no data dir yet — the log file (and the
	// daemon's database) need it to exist first.
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	// Drop a stale PID file so it cannot mask a fresh start.
	if pid, ok := pidFromFile(cfg); ok && !pidAlive(pid) {
		_ = os.Remove(pidFile(cfg))
	}
	if hasSystemdUser() {
		if err := installServiceFile(cfg); err != nil {
			return fmt.Errorf("could not install service file: %w", err)
		}
		// Clear a failed state left by an earlier attempt (e.g. a
		// rate-limited start before this fix), or enable --now below
		// refuses to start the unit at all.
		_ = exec.Command("systemctl", "--user", "reset-failed", "loadinme.service").Run()
		cmd := exec.Command("systemctl", "--user", "enable", "--now", "loadinme.service")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		if !waitHealthy(cfg) {
			return fmt.Errorf("service started but the web UI did not answer on port %d — check: systemctl --user status loadinme.service", cfg.Port)
		}
		return nil
	}
	// Fallback: nohup background process.
	logPath := filepath.Join(cfg.DataDir, "loadinme.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command(exe, "serve", "--port", strconv.Itoa(cfg.Port), "--data-dir", cfg.DataDir)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := os.WriteFile(pidFile(cfg), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		return err
	}
	if !waitHealthy(cfg) {
		// The child never came up (port still held, DB lock, …) —
		// kill it and drop the PID file so a half-started process
		// cannot linger holding the port / database lock.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(pidFile(cfg))
		return fmt.Errorf("web UI did not start on port %d (is the port already in use?) — check the log: %s", cfg.Port, logPath)
	}
	return nil
}

func stopService(cfg Config) error {
	if hasSystemdUser() {
		cmd := exec.Command("systemctl", "--user", "stop", "loadinme.service")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		// systemctl stop can return while the process still lingers;
		// wait until it is actually gone before reporting stopped.
		return waitServiceStopped(cfg)
	}
	b, err := os.ReadFile(pidFile(cfg))
	if err != nil {
		return fmt.Errorf("not running (no PID file)")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = p.Signal(os.Interrupt)
	time.Sleep(500 * time.Millisecond)
	_ = p.Kill()
	// Wait until the process is actually dead and the port is free
	// before returning — only then remove the PID file.
	if err := waitStopped(cfg, pid); err != nil {
		return err
	}
	_ = os.Remove(pidFile(cfg))
	return nil
}

func isServiceRunning(cfg Config) bool {
	// A live /health response wins: the UI is up however it was started
	// (installer, systemd, nohup, or by hand).
	if probeHealth(cfg) {
		return true
	}
	if hasSystemdUser() {
		return exec.Command("systemctl", "--user", "is-active", "--quiet", "loadinme.service").Run() == nil
	}
	if pid, ok := pidFromFile(cfg); ok {
		return pidAlive(pid)
	}
	return false
}

func restartService(cfg Config) error {
	_ = stopService(cfg)
	time.Sleep(time.Second)
	return startService(cfg)
}

// restartFailedError is returned by withServiceStopped when the web UI
// could not be restarted after fn ran. fnErr is the error fn returned
// (nil when the password change itself succeeded), so the caller can
// tell the user the reset worked but the UI is down — instead of
// swallowing the restart failure in a WARNING and exiting 0 while
// the server is actually down (CI run #23: the menu exited fine, but
// /health never came back and the test could only say so).
type restartFailedError struct {
	fnErr error
	err   error
}

func (e *restartFailedError) Error() string {
	if e.fnErr != nil {
		return fmt.Sprintf("password change failed (%v) and the web UI could not be restarted: %v", e.fnErr, e.err)
	}
	return fmt.Sprintf("password change may have succeeded, but the web UI could not be restarted: %v", e.err)
}

// Unwrap returns fn's error so errors.Is(err, errCancelled) still
// works when the user cancelled the password prompt.
func (e *restartFailedError) Unwrap() error { return e.fnErr }

// withServiceStopped stops the web UI if it is running, runs fn, then
// restarts the UI if it was running. This is REQUIRED for any
// operation that opens the database from another process (e.g.
// changing the password): bbolt takes an exclusive lock, so while the
// daemon holds the database open, no other process can open it at all
// — a plain open just fails with "could not open data store: timeout".
// The UI is restarted even if fn fails or is cancelled, so a reset
// never leaves the server down. If the restart fails, that error is
// RETURNED (not swallowed) — the caller must surface it, because the
// server is down at that point.
func withServiceStopped(cfg Config, fn func() error) error {
	wasRunning := isServiceRunning(cfg)
	if !wasRunning {
		return fn()
	}
	fmt.Println("Stopping the web UI first — it holds the database open…")
	if err := stopService(cfg); err != nil {
		return fmt.Errorf("could not stop the web UI (%v) — stop it first (loadinme stop), then try again", err)
	}
	fnErr := fn()
	fmt.Println("Restarting the web UI…")
	if err := startService(cfg); err != nil {
		return &restartFailedError{fnErr: fnErr, err: err}
	}
	return fnErr
}

// letsEncryptDir is the base directory of the Let's Encrypt data
// (/etc/letsencrypt/live/<domain>/ holds each certificate). It is a
// variable, not a constant, so tests can point it at a temp dir —
// the real /etc/letsencrypt is root-owned and may not exist here.
var letsEncryptDir = "/etc/letsencrypt"

// findCerts looks for a Let's Encrypt certificate for a domain: first
// a lineage folder named after the domain, then any certificate whose
// covered domains include it. A lineage name can differ from the
// domain it covers (a multi-domain cert, or a lineage named
// example.com-0001), so matching by folder name alone would miss it.
func findCerts(domain string) (cert, key string, ok bool) {
	cert = filepath.Join(letsEncryptDir, "live", domain, "fullchain.pem")
	key = filepath.Join(letsEncryptDir, "live", domain, "privkey.pem")
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			return cert, key, true
		}
	}
	for _, c := range findCertsByDomain(domain) {
		return c.certPath(), c.keyPath(), true
	}
	return "", "", false
}

// findCertsByDomain returns every lineage whose certificate covers
// domain (case-insensitive), in display order.
func findCertsByDomain(domain string) []certInfo {
	certs, err := listCerts()
	if err != nil {
		return nil
	}
	var out []certInfo
	for _, c := range certs {
		if c.covers(domain) {
			out = append(out, c)
		}
	}
	return out
}

// domainSSLMenu is the "Domain & SSL" submenu (menu option 6):
// 1 gets an SSL certificate, 2 lists certificates and revokes one,
// 3 clears the saved domain, 0 goes back to the main menu (never
// exits the app).
func domainSSLMenu(cfg *Config, scanner *bufio.Scanner) {
	for {
		fmt.Println("  Domain & SSL")
		if cfg.Domain != "" {
			ssl := "off"
			if cfg.TLSEnabled {
				ssl = "on"
			}
			fmt.Println("  Domain:", cfg.Domain, " ·  SSL:", ssl)
		} else {
			fmt.Println("  Domain: (none set)")
		}
		fmt.Println("  1  Get SSL (enter domain, then email)")
		fmt.Println("  2  List certificates & revoke one")
		fmt.Println("  3  Clear saved domain")
		fmt.Println("  0  Back to main menu")
		fmt.Println()
		fmt.Print("  Choose [0-3]: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		fmt.Println()
		switch choice {
		case "1":
			getSSLCert(cfg, scanner)
		case "2":
			listAndRevokeCerts(cfg, scanner)
		case "3":
			clearSavedDomain(cfg)
		case "0":
			return
		default:
			fmt.Println("Please choose 0-3.")
		}
	}
}

// getSSLCert is submenu 1: enter a domain, then an email, and get a
// Let's Encrypt certificate for it (or enable HTTPS with one that
// already exists). The domain is saved as soon as it is entered, so
// the next visit already knows it.
func getSSLCert(cfg *Config, scanner *bufio.Scanner) {
	domain, cancelled := promptCancel(scanner, "Domain (example: files.example.com)", cfg.Domain)
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		fmt.Println("A domain is required. Nothing changed.")
		return
	}
	cfg.Domain = domain
	_ = saveConfig(*cfg)
	// Match by the domains a certificate covers, not by folder name:
	// the domain may already have a certificate under a different
	// lineage name, and running certbot for it again would ask
	// whether to change that certificate's key type.
	matches := findCertsByDomain(domain)
	if len(matches) > 0 {
		var chosen certInfo
		if len(matches) == 1 {
			chosen = matches[0]
			fmt.Println("Certificate already found:")
			fmt.Println("  ", chosen.certPath())
			fmt.Println("  ", chosen.keyPath())
		} else {
			fmt.Println("More than one certificate covers", domain+":")
			var ok bool
			chosen, ok = pickCert(scanner, matches, *cfg)
			if !ok {
				return
			}
		}
		ans, cancelled := promptCancel(scanner, "Enable HTTPS with this certificate? (y/n)", "y")
		if cancelled {
			fmt.Println("Cancelled.")
			return
		}
		if strings.ToLower(ans) == "y" || strings.ToLower(ans) == "yes" {
			enableSSL(cfg, chosen.certPath(), chosen.keyPath())
		}
		return
	}
	fmt.Println("No certificate found yet for", domain)
	fmt.Println("You need: a domain pointing at this server, and ports 80 and 443 open.")
	if _, err := exec.LookPath("certbot"); err != nil {
		fmt.Println("certbot is not installed. Run these commands on the server:")
		fmt.Println("  sudo apt update && sudo apt install -y certbot")
		fmt.Println("  sudo certbot certonly --standalone -d " + domain + " --cert-name " + domain)
		fmt.Println("Then come back here — I will find the certificate and turn SSL on.")
		return
	}
	fmt.Println("certbot is installed.")
	email, cancelled := promptCancel(scanner, "Email for Let's Encrypt (expiry notices)", "")
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	if email == "" {
		fmt.Println("An email is required by certbot. Nothing changed.")
		return
	}
	wasRunning := isServiceRunning(*cfg)
	if wasRunning {
		fmt.Println("Stopping the web UI first — certbot needs port 80 free.")
		_ = stopService(*cfg)
	}
	fmt.Println("Running certbot — this may ask for sudo…")
	// --cert-name names the new lineage after the domain, so future
	// lookups by domain find it by folder name too.
	cmd := exec.Command("sudo", "certbot", "certonly", "--standalone", "-d", domain,
		"--cert-name", domain, "--agree-tos", "--non-interactive", "--email", email)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Println("certbot failed:", err)
		fmt.Println("Check that the domain points at this server and port 80 is open, then try again.")
		if wasRunning {
			restartAfterSSL(cfg)
		}
		return
	}
	cert, key, ok := findCerts(domain)
	if !ok {
		fmt.Println("certbot finished but I cannot find the certificate. Check " + filepath.Join(letsEncryptDir, "live", domain) + "/")
		if wasRunning {
			restartAfterSSL(cfg)
		}
		return
	}
	enableSSL(cfg, cert, key)
}

// enableSSL turns TLS on with the given certificate and restarts the
// web UI when it was running, so https serves right away instead of
// waiting for a manual restart.
func enableSSL(cfg *Config, cert, key string) {
	cfg.TLSEnabled = true
	cfg.CertFile, cfg.KeyFile = cert, key
	_ = saveConfig(*cfg)
	fmt.Println("SSL is on — certificate found at", cert)
	if isServiceRunning(*cfg) {
		fmt.Println("Restarting the web UI to serve https://" + cfg.Domain + "…")
		if err := restartService(*cfg); err != nil {
			fmt.Println("SSL is on, but the web UI could not be restarted:", err)
			fmt.Println("Start it with option 1.")
			return
		}
		fmt.Println("Web UI is now serving https://" + cfg.Domain)
	} else {
		fmt.Println("Start the web UI with option 1 to serve https://" + cfg.Domain)
	}
}

// restartAfterSSL restarts the web UI after an SSL step that stopped
// it but did not enable SSL (e.g. certbot failed) — the UI must not
// be left down.
func restartAfterSSL(cfg *Config) {
	fmt.Println("Restarting the web UI…")
	if err := restartService(*cfg); err != nil {
		fmt.Println("The web UI could not be restarted:", err)
		fmt.Println("Start it with option 1.")
	}
}

// certInfo is one certificate found under <letsEncryptDir>/live/.
// lineage is the folder name (certbot's name for the certificate);
// domains are the names the certificate actually covers, read from
// the certificate itself. The two can differ (a multi-domain cert,
// or a lineage named example.com-0001), so matching is always by
// domain, never by folder name alone.
type certInfo struct {
	lineage   string
	domains   []string
	expiry    time.Time
	hasExpiry bool
}

// certPath is the certificate file for this lineage.
func (c certInfo) certPath() string {
	return filepath.Join(letsEncryptDir, "live", c.lineage, "fullchain.pem")
}

// keyPath is the private key file for this lineage.
func (c certInfo) keyPath() string {
	return filepath.Join(letsEncryptDir, "live", c.lineage, "privkey.pem")
}

// primaryDomain is the first domain the certificate covers, or the
// lineage name when the certificate could not be parsed.
func (c certInfo) primaryDomain() string {
	if len(c.domains) > 0 {
		return c.domains[0]
	}
	return c.lineage
}

// covers reports whether the certificate covers domain
// (case-insensitive).
func (c certInfo) covers(domain string) bool {
	for _, d := range c.domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// describeCert is one line for the certificate list: the domains it
// covers, its expiry date, and whether it is the one in use.
func describeCert(c certInfo, cfg Config) string {
	name := c.primaryDomain()
	if len(c.domains) > 1 {
		name += " (also covers: " + strings.Join(c.domains[1:], ", ") + ")"
	}
	if c.lineage != c.primaryDomain() {
		name += " [certificate " + c.lineage + "]"
	}
	expiry := "expiry unknown"
	if c.hasExpiry {
		expiry = "expires " + c.expiry.Format("2006-01-02")
	}
	inUse := ""
	if cfg.TLSEnabled && c.covers(cfg.Domain) {
		inUse = "  (in use)"
	}
	return fmt.Sprintf("  %s — %s%s", name, expiry, inUse)
}

// pickCert asks the user to choose one of several certificates by
// number. It returns false when the user cancels with 0.
func pickCert(scanner *bufio.Scanner, certs []certInfo, cfg Config) (certInfo, bool) {
	for i, c := range certs {
		fmt.Printf("  %d  %s\n", i+1, describeCert(c, cfg))
	}
	ans, cancelled := promptCancel(scanner, "Which one", "")
	if cancelled {
		fmt.Println("Cancelled.")
		return certInfo{}, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(ans))
	if err != nil || n < 1 || n > len(certs) {
		fmt.Println("That is not one of the certificates. Nothing changed.")
		return certInfo{}, false
	}
	return certs[n-1], true
}

// listCerts returns every certificate under <letsEncryptDir>/live/.
// Each subdirectory is one certificate; the covered domains and the
// expiry are read from the certificate itself (crypto/x509, no
// openssl needed). A certificate that cannot be parsed is still
// listed by its folder name, with no domains and unknown expiry.
func listCerts() ([]certInfo, error) {
	liveDir := filepath.Join(letsEncryptDir, "live")
	entries, err := os.ReadDir(liveDir)
	if err != nil {
		return nil, err
	}
	var out []certInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info := certInfo{lineage: e.Name()}
		if b, err := os.ReadFile(filepath.Join(liveDir, e.Name(), "fullchain.pem")); err == nil {
			if block, _ := pem.Decode(b); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					info.expiry = cert.NotAfter
					info.hasExpiry = true
					info.domains = cert.DNSNames
					if len(info.domains) == 0 && cert.Subject.CommonName != "" {
						info.domains = []string{cert.Subject.CommonName}
					}
				}
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].primaryDomain() != out[j].primaryDomain() {
			return out[i].primaryDomain() < out[j].primaryDomain()
		}
		return out[i].lineage < out[j].lineage
	})
	return out, nil
}

// listAndRevokeCerts is submenu 2: show every Let's Encrypt
// certificate with its expiry date, and revoke one by domain. A
// certificate is found by the domains it covers, not by its folder
// name, so one stored under another name still shows up and can be
// revoked by typing the domain it covers.
func listAndRevokeCerts(cfg *Config, scanner *bufio.Scanner) {
	liveDir := filepath.Join(letsEncryptDir, "live")
	certs, err := listCerts()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No certificates found (checked", liveDir+").")
			return
		}
		fmt.Println("Could not read", liveDir, "—", err)
		fmt.Println("The certificate directory is usually only readable as root: run the menu with sudo (sudo loadinme menu) and try again.")
		return
	}
	if len(certs) == 0 {
		fmt.Println("No certificates found (checked", liveDir+").")
		return
	}
	fmt.Println("Certificates in", liveDir+":")
	for _, c := range certs {
		fmt.Println(describeCert(c, *cfg))
	}
	domain, cancelled := promptCancel(scanner, "Domain to revoke", "")
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		fmt.Println("No domain given. Nothing revoked.")
		return
	}
	matches := findCertsByDomain(domain)
	if len(matches) == 0 {
		fmt.Println("No certificate covers", domain+". Nothing revoked.")
		return
	}
	var chosen certInfo
	if len(matches) == 1 {
		chosen = matches[0]
	} else {
		fmt.Println("More than one certificate covers", domain+":")
		var ok bool
		chosen, ok = pickCert(scanner, matches, *cfg)
		if !ok {
			return
		}
	}
	ans, cancelled := promptCancel(scanner, "Revoke the certificate for "+chosen.primaryDomain()+"? This cannot be undone (y/n)", "n")
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	if strings.ToLower(ans) != "y" && strings.ToLower(ans) != "yes" {
		fmt.Println("Not revoked.")
		return
	}
	revokeCert(cfg, chosen)
}

// clearSavedDomain is submenu 3: forget the saved domain, so it
// stops showing on top of the menu. If SSL was on for that domain,
// it is switched off too and the web UI restarts on plain http.
func clearSavedDomain(cfg *Config) {
	if cfg.Domain == "" && !cfg.TLSEnabled {
		fmt.Println("No saved domain to clear.")
		return
	}
	domain := cfg.Domain
	wasTLS := cfg.TLSEnabled
	cfg.Domain = ""
	cfg.TLSEnabled = false
	cfg.CertFile, cfg.KeyFile = "", ""
	_ = saveConfig(*cfg)
	if wasTLS {
		fmt.Println("Saved domain cleared and SSL switched off (it was for " + domain + ").")
		if isServiceRunning(*cfg) {
			fmt.Println("Restarting the web UI to serve http again…")
			if err := restartService(*cfg); err != nil {
				fmt.Println("SSL is off, but the web UI could not be restarted:", err)
				fmt.Println("Start it with option 1.")
				return
			}
			fmt.Println("Web UI is now serving http on port", cfg.Port)
		} else {
			fmt.Println("The web UI is stopped; start it with option 1 when ready.")
		}
	} else {
		fmt.Println("Saved domain cleared. The web link now shows your server IP.")
	}
}

// revokeCert revokes a certificate with certbot, and turns SSL off in
// the config when it was the one in use. cert identifies the lineage
// (its folder name may differ from the domain it covers).
func revokeCert(cfg *Config, cert certInfo) {
	certPath := filepath.Join(letsEncryptDir, "live", cert.lineage, "cert.pem")
	if _, err := exec.LookPath("certbot"); err != nil {
		fmt.Println("certbot is not installed — nothing was revoked and nothing was deleted.")
		fmt.Println("To revoke this certificate by hand, run:")
		fmt.Println("  sudo certbot revoke --cert-path " + certPath + " --delete-after-revoke")
		fmt.Println("  sudo rm -rf " + filepath.Join(letsEncryptDir, "live", cert.lineage) + " " + filepath.Join(letsEncryptDir, "archive", cert.lineage) + " " + filepath.Join(letsEncryptDir, "renewal", cert.lineage+".conf"))
		return
	}
	fmt.Println("Running certbot revoke — this may ask for sudo…")
	cmd := exec.Command("sudo", "certbot", "revoke", "--cert-path", certPath, "--delete-after-revoke", "--non-interactive")
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Println("certbot revoke failed:", err)
		fmt.Println("Nothing was changed.")
		return
	}
	fmt.Println("Certificate for", cert.primaryDomain(), "revoked.")
	if cert.lineage != cert.primaryDomain() {
		fmt.Println("(certificate " + cert.lineage + ")")
	}
	if cfg.TLSEnabled && cert.covers(cfg.Domain) {
		cfg.TLSEnabled = false
		cfg.CertFile, cfg.KeyFile = "", ""
		_ = saveConfig(*cfg)
		fmt.Println("SSL is now off — that was the certificate in use.")
		if isServiceRunning(*cfg) {
			fmt.Println("Restarting the web UI to serve http again…")
			if err := restartService(*cfg); err != nil {
				fmt.Println("SSL is off, but the web UI could not be restarted:", err)
				fmt.Println("Start it with option 1.")
				return
			}
			fmt.Println("Web UI is now serving http://" + cfg.Domain)
		} else {
			fmt.Println("The web UI is stopped; start it with option 1 when ready.")
		}
	}
}

// selfUpdate downloads the latest release binary, replaces the
// running one, and restarts the web UI so the new version applies.
// Safe order: stop the old process BEFORE replacing the binary, then
// start the new one and verify /health. It never leaves the old
// version running after an update.
func selfUpdate(cfg Config) error {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported architecture %s (only amd64/arm64 releases exist)", arch)
	}
	url := "https://github.com/sahfar363/loadinme/releases/latest/download/loadinme-linux-" + arch
	fmt.Println("Downloading", url)
	tmp, err := os.CreateTemp("", "loadinme-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	downloaded := false
	if _, err := exec.LookPath("curl"); err == nil {
		cmd := exec.Command("curl", "-fsSL", "-o", tmpPath, url)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err == nil {
			downloaded = true
		} else {
			fmt.Println("curl failed, trying a direct download…")
		}
	}
	if !downloaded {
		if err := downloadFile(url, tmpPath); err != nil {
			return fmt.Errorf("download failed (no release yet? create a release first): %w", err)
		}
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	if out, err := exec.Command(tmpPath, "--help").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "loadinme") && !strings.Contains(string(out), "Usage") {
			return fmt.Errorf("downloaded binary did not pass --help check: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	// Stop the old process BEFORE replacing the binary, so the new
	// one is what runs afterwards.
	wasRunning := isServiceRunning(cfg)
	if wasRunning {
		fmt.Println("Stopping the web UI so the update can replace it…")
		if err := stopService(cfg); err != nil {
			fmt.Println("Warning: could not stop the web UI:", err)
		}
		time.Sleep(time.Second)
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		return fmt.Errorf("could not replace %s (do you have write permission there?): %w", exe, err)
	}
	newVersion := strings.TrimSpace(versionString(exe))
	if wasRunning {
		if err := startService(cfg); err != nil {
			return fmt.Errorf("updated to %s, but the web UI could not be restarted: %v (start it with option 1)", newVersion, err)
		}
		if !waitHealthy(cfg) {
			return fmt.Errorf("updated to %s, but the web UI did not answer /health after restart — check the log", newVersion)
		}
		fmt.Printf("Updated and restarted: %s — the web UI is running the new version at %s\n", newVersion, webAddressFor(cfg))
		return nil
	}
	fmt.Printf("Updated: %s — the web UI was not running; start it with option 1.\n", newVersion)
	return nil
}

// versionString runs `binary version` and returns its output
// ("loadinme 0.4.0"), or "" if it cannot run.
func versionString(exe string) string {
	out, err := exec.Command(exe, "version").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// uninstall stops LoadInMe and removes the binary and the service.
// It returns false when the user cancels (typing 0 at the question),
// in which case nothing is stopped or removed.
func uninstall(cfg Config, scanner *bufio.Scanner) bool {
	fmt.Println("This will stop LoadInMe and remove the binary and the service.")
	keep, cancelled := promptCancel(scanner, "Keep your data (files, clips, settings, login) in "+cfg.DataDir+"? (y/n)", "y")
	if cancelled {
		fmt.Println("Cancelled.")
		return false
	}
	_ = stopService(cfg)
	if hasSystemdUser() {
		_ = exec.Command("systemctl", "--user", "disable", "--now", "loadinme.service").Run()
		_ = os.Remove(serviceFilePath())
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	}
	exe, err := os.Executable()
	if err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
		if err := os.Remove(exe); err != nil {
			fmt.Println("Could not remove binary:", err)
		} else {
			fmt.Println("Removed binary:", exe)
		}
	}
	if strings.ToLower(keep) == "n" || strings.ToLower(keep) == "no" {
		if err := os.RemoveAll(cfg.DataDir); err != nil {
			fmt.Println("Could not remove data dir:", err)
		} else {
			fmt.Println("Removed data:", cfg.DataDir)
		}
	} else {
		fmt.Println("Kept data in", cfg.DataDir, "— reinstall later and it will still be there.")
	}
	fmt.Println("LoadInMe is uninstalled.")
	return true
}

// withStore opens the database for one short operation and closes it
// again. The menu must NOT hold the database open: bbolt takes an
// exclusive lock, so a menu holding it open would make the web UI
// daemon fail to start with "could not open data store: timeout"
// (v0.1.0 bug — the menu printed "Web UI started" while the daemon
// had actually died).
func withStore(cfg *Config, fn func(*Store) error) error {
	store, err := OpenStore(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	return fn(store)
}

func runMenu(cfg *Config) {
	// Tests point the certificate directory at a temp dir (via env,
	// which the menu child process inherits) so the list / revoke
	// flows do not depend on the machine's real /etc/letsencrypt.
	if d := os.Getenv("LOADINME_LETSENCRYPT_DIR"); d != "" {
		letsEncryptDir = d
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for {
		printMenuHeader(*cfg)
		fmt.Println("  1  Start web UI")
		fmt.Println("  2  Stop web UI")
		fmt.Println("  3  Restart web UI")
		fmt.Println("  4  Status")
		fmt.Println("  5  Change port")
		fmt.Println("  6  Domain & SSL")
		fmt.Println("  7  Update LoadInMe")
		fmt.Println("  8  Reset / change username & password")
		fmt.Println("  9  View settings")
		fmt.Println("  10 Show web UI link")
		fmt.Println("  11 Uninstall")
		fmt.Println("  0  Exit")
		fmt.Println()
		fmt.Print("  Choose [0-11]: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		fmt.Println()
		switch choice {
		case "1":
			if err := startService(*cfg); err != nil {
				if errors.Is(err, errAlreadyRunning) {
					fmt.Println("Web UI is already running at", webAddressFor(*cfg))
				} else {
					fmt.Println("Could not start web UI:", err)
				}
			} else {
				fmt.Println("Web UI started at", webAddressFor(*cfg))
			}
			pause(scanner)
		case "2":
			if err := stopService(*cfg); err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Web UI stopped.")
			}
			pause(scanner)
		case "3":
			if err := restartService(*cfg); err != nil {
				fmt.Println("Could not restart web UI:", err)
			} else {
				fmt.Println("Web UI restarted at", webAddressFor(*cfg))
			}
			pause(scanner)
		case "4":
			fmt.Println("Web UI address:", webAddressFor(*cfg))
			fmt.Println("Running:", isServiceRunning(*cfg))
			fmt.Println("Port:", cfg.Port)
			fmt.Println("Domain:", cfg.Domain)
			fmt.Println("SSL:", cfg.TLSEnabled)
			fmt.Println("Data dir:", cfg.DataDir)
			if err := withStore(cfg, func(store *Store) error {
				if st, err := store.GetSettings(); err == nil {
					fmt.Printf("Limits: %d items max, %d MB per file, %d h default expiry\n",
						st.MaxItems, st.MaxFileMB, st.DefaultExpiryHours)
				}
				if n, err := store.CountItems(); err == nil {
					fmt.Println("Items stored:", n)
				}
				return nil
			}); err != nil {
				fmt.Println("Limits / items: not available while the web UI is running — see them in the web UI (gear icon).")
			}
			pause(scanner)
		case "5":
			portStr, cancelled := promptCancel(scanner, "Web port", strconv.Itoa(cfg.Port))
			if cancelled {
				fmt.Println("Cancelled.")
				pause(scanner)
				continue
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				fmt.Println("That is not a valid port (1-65535). Nothing changed.")
			} else {
				cfg.Port = port
				_ = saveConfig(*cfg)
				fmt.Printf("Web port is now %d.\n", port)
				if isServiceRunning(*cfg) {
					fmt.Println("Restarting web UI on the new port…")
					if err := restartService(*cfg); err != nil {
						fmt.Println("Restart failed:", err)
					} else {
						fmt.Println("Web UI is now at", webAddressFor(*cfg))
					}
				}
			}
			pause(scanner)
		case "6":
			domainSSLMenu(cfg, scanner)
			pause(scanner)
		case "7":
			if err := selfUpdate(*cfg); err != nil {
				fmt.Println("Update failed:", err)
				fmt.Println("You can also run the installer again:")
				fmt.Println("  curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash")
			}
			pause(scanner)
		case "8":
			// The UI must be stopped first: while it runs, its
			// exclusive database lock blocks any password change.
			// withServiceStopped restarts it afterwards, even on cancel.
			err := withServiceStopped(*cfg, func() error {
				return withStore(cfg, func(store *Store) error {
					return setPasswordCLI(store, "", scanner)
				})
			})
			if err != nil {
				var rerr *restartFailedError
				if errors.As(err, &rerr) {
					if rerr.fnErr == nil {
						fmt.Printf("Password was reset, but the web UI could not be restarted: %v — start it with option 1.\n", rerr.err)
					} else if errors.Is(rerr.fnErr, errCancelled) {
						fmt.Printf("Cancelled, but the web UI could not be restarted: %v — start it with option 1.\n", rerr.err)
					} else {
						fmt.Printf("Could not change password: %v — and the web UI could not be restarted: %v — start it with option 1.\n", rerr.fnErr, rerr.err)
					}
				} else if errors.Is(err, errCancelled) {
					fmt.Println("Cancelled.")
				} else {
					fmt.Println("Could not change password:", err)
				}
			}
			pause(scanner)
		case "9":
			err := withStore(cfg, func(store *Store) error {
				st, err := store.GetSettings()
				if err != nil {
					fmt.Println("Could not read settings:", err)
					return nil
				}
				fmt.Printf("Max items: %d\nMax file size: %d MB\nDefault expiry: %d hours\n",
					st.MaxItems, st.MaxFileMB, st.DefaultExpiryHours)
				if name, _, _ := store.GetUser(); name != "" {
					fmt.Println("Login user:", name)
				} else {
					fmt.Println("Login user: (none set yet — open the web UI to create one)")
				}
				return nil
			})
			if err != nil {
				fmt.Println("Could not open data store: the web UI is running and holds the database — stop it first (option 2), or check Settings in the web UI.")
			}
			pause(scanner)
		case "10":
			fmt.Println("Web UI:", webAddressFor(*cfg))
			fmt.Println("Local:  http://localhost:" + strconv.Itoa(cfg.Port))
			pause(scanner)
		case "11":
			if uninstall(*cfg, scanner) {
				pause(scanner)
				return
			}
			pause(scanner)
		case "0", "q", "quit", "exit":
			return
		default:
			fmt.Println("Please choose 0-11.")
			pause(scanner)
		}
	}
}
