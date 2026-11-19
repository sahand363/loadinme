package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
//   6 Domain & SSL (1 Get SSL, 2 SSL status, 3 Renew now,
//     4 Turn SSL off / remove certificate, 5 Clear saved domain)
//   7 Update
//   8 Reset / change username & password   9 View settings
//   10 Show web UI link   11 Uninstall   0 Exit (silent, no farewell)

func webAddressFor(cfg Config) string {
	if cfg.Domain != "" {
		if cfg.TLSEnabled {
			// HTTPS serves on the chosen port, not on 443 (unless
			// the user chose 443): a link without the port would
			// open in the browser on 443, where nothing listens.
			if cfg.Port == 443 {
				return "https://" + cfg.Domain
			}
			return fmt.Sprintf("https://%s:%d", cfg.Domain, cfg.Port)
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
	// Until a login exists, the setup page asks for this one-time
	// code, so only someone who can see this terminal can claim the
	// install.
	if code := readSetupCode(cfg.DataDir); code != "" {
		fmt.Println("  Setup code: " + code + "  ·  enter it on the setup page to create your login")
	}
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
	if u, ok := sudoInvoker(); ok {
		// Root through sudo: the app user's own manager counts,
		// not root's (and root's XDG_RUNTIME_DIR says nothing).
		if _, err := os.Stat("/run/user/" + strconv.Itoa(u.uid)); err == nil {
			return true
		}
		return userSystemctl("status").Run() == nil
	}
	return userSystemctl("status").Run() == nil ||
		os.Getenv("XDG_RUNTIME_DIR") != ""
}

func serviceFilePath() string {
	home := appHome()
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
	chownToApp(cfg.DataDir, filepath.Join(appHome(), ".config"), filepath.Join(appHome(), ".config", "systemd"),
		filepath.Dir(path), path)
	_ = userSystemctl("daemon-reload").Run()
	return nil
}

// errAlreadyRunning is returned by startService when the web UI is
// already answering /health.
var errAlreadyRunning = errors.New("web UI is already running")

// probeHealth reports whether the web UI answers /health on localhost.
// A live /health response is the definitive proof the UI is up, however
// it was started (systemd, nohup, or by hand).
func probeHealth(cfg Config) bool {
	// Try the scheme the config says first, then the other one: right
	// after SSL is switched on or off, the running UI still speaks
	// the old scheme until it restarts.
	first, second := "http", "https"
	if cfg.TLSEnabled {
		first, second = "https", "http"
	}
	return probeHealthScheme(cfg, first) || probeHealthScheme(cfg, second)
}

func probeHealthScheme(cfg Config, scheme string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	if scheme == "https" {
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
		_ = userSystemctl("reset-failed", "loadinme.service").Run()
		cmd := userSystemctl("enable", "--now", "loadinme.service")
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
	chownToApp(cfg.DataDir, cfg.DataDir, logPath)
	cmd := exec.Command(exe, "serve", "--port", strconv.Itoa(cfg.Port), "--data-dir", cfg.DataDir)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Stdin = nil
	// As root through sudo, the web UI still runs as the real user.
	if u, ok := sudoInvoker(); ok {
		setRunAs(cmd, u.uid, u.gid)
		cmd.Env = append(os.Environ(), "HOME="+u.home)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := os.WriteFile(pidFile(cfg), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		return err
	}
	chownToApp(cfg.DataDir, pidFile(cfg))
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
		cmd := userSystemctl("stop", "loadinme.service")
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
		return userSystemctl("is-active", "--quiet", "loadinme.service").Run() == nil
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

// letsEncryptDir is where certbot keeps its certificates. LoadInMe
// no longer uses certbot (v0.7.0), but configs from earlier versions
// can still point there; they keep working and the menu suggests
// re-issuing. A variable so tests can point it elsewhere.
var letsEncryptDir = "/etc/letsencrypt"

// portFree reports whether a TCP port can be bound right now: it
// tries to bind the port and lets go at once.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// clearSavedDomain is submenu 5: forget the saved domain, so it
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
	url := "https://github.com/sahand363/loadinme/releases/latest/download/loadinme-linux-" + arch
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
	// Root-owned pieces from Get SSL: the renewal timer and any
	// leftover nginx snippet.
	if systemPiecesPresent() {
		if isRoot() {
			removeSystemPieces(os.Stdout)
		} else {
			fmt.Println("Removing the SSL renewal timer / nginx snippet needs root — asking sudo…")
			if err := runAsRoot("ssl", "cleanup-system"); err != nil {
				fmt.Println("Could not remove them:", err)
				fmt.Println("Run: sudo systemctl disable --now loadinme-renew.timer; sudo rm -f /etc/systemd/system/loadinme-renew.* /etc/nginx/conf.d/loadinme-acme-*.conf")
			}
		}
	}
	if hasSystemdUser() {
		_ = userSystemctl("disable", "--now", "loadinme.service").Run()
		_ = os.Remove(serviceFilePath())
		_ = userSystemctl("daemon-reload").Run()
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
	// No login yet and the web UI not running (it makes the code
	// itself when it starts): make the one-time setup code now, so
	// the header can show it.
	if readSetupCode(cfg.DataDir) == "" && !isServiceRunning(*cfg) {
		_ = withStore(cfg, func(store *Store) error {
			if has, _ := store.HasUser(); !has {
				_, _ = ensureSetupCode(cfg.DataDir)
			}
			return nil
		})
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
			// No pause here: leaving the submenu (0) already
			// returns to this menu, so asking for Enter as well
			// would be confirming the same step twice.
		case "7":
			if err := selfUpdate(*cfg); err != nil {
				fmt.Println("Update failed:", err)
				fmt.Println("You can also run the installer again:")
				fmt.Println("  curl -fsSL https://raw.githubusercontent.com/sahand363/loadinme/main/install.sh | bash")
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
			if cfg.TLSEnabled {
				fmt.Println("Local:  https://localhost:" + strconv.Itoa(cfg.Port) + "  (the certificate is for " + cfg.Domain + ")")
			} else {
				fmt.Println("Local:  http://localhost:" + strconv.Itoa(cfg.Port))
			}
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
