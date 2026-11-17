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
//   6 Set domain   7 SSL with Let's Encrypt   8 Update
//   9 Change username/password   10 View settings
//   11 Show web UI link   12 Uninstall   0 Exit

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

func prompt(scanner *bufio.Scanner, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	if !scanner.Scan() {
		return def
	}
	v := strings.TrimSpace(scanner.Text())
	if v == "" {
		return def
	}
	return v
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
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
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
		return fmt.Errorf("web UI did not start on port %d (is the port already in use?) — check the log: %s", cfg.Port, logPath)
	}
	return nil
}

func stopService(cfg Config) error {
	if hasSystemdUser() {
		cmd := exec.Command("systemctl", "--user", "stop", "loadinme.service")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
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

// findCerts looks for a Let's Encrypt certificate for a domain.
func findCerts(domain string) (cert, key string, ok bool) {
	cert = filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	key = filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")
	if _, err := os.Stat(cert); err != nil {
		return "", "", false
	}
	if _, err := os.Stat(key); err != nil {
		return "", "", false
	}
	return cert, key, true
}

func setupSSL(cfg *Config, scanner *bufio.Scanner) {
	if strings.TrimSpace(cfg.Domain) == "" {
		fmt.Println("Set a domain first (menu option 6), then come back here.")
		return
	}
	domain := cfg.Domain
	if cert, key, ok := findCerts(domain); ok {
		fmt.Println("Certificate already found:")
		fmt.Println("  ", cert)
		fmt.Println("  ", key)
		ans := prompt(scanner, "Enable HTTPS with this certificate? (y/n)", "y")
		if strings.ToLower(ans) == "y" || strings.ToLower(ans) == "yes" {
			cfg.TLSEnabled = true
			cfg.CertFile, cfg.KeyFile = cert, key
			_ = saveConfig(*cfg)
			fmt.Println("SSL is on. Restart the web UI (option 3) to serve https://" + domain)
		}
		return
	}
	fmt.Println("No certificate found yet for", domain)
	fmt.Println("You need: a domain pointing at this server, and ports 80 and 443 open.")
	if _, err := exec.LookPath("certbot"); err != nil {
		fmt.Println("certbot is not installed. Run these commands on the server:")
		fmt.Println("  sudo apt update && sudo apt install -y certbot")
		fmt.Println("  sudo certbot certonly --standalone -d " + domain)
		fmt.Println("Then come back here — I will find the certificate and turn SSL on.")
		return
	}
	fmt.Println("certbot is installed.")
	email := prompt(scanner, "Email for Let's Encrypt (expiry notices)", "")
	if email == "" {
		fmt.Println("An email is required by certbot. Nothing changed.")
		return
	}
	if isServiceRunning(*cfg) {
		fmt.Println("Stopping the web UI first — certbot needs port 80 free.")
		_ = stopService(*cfg)
	}
	fmt.Println("Running certbot — this may ask for sudo…")
	cmd := exec.Command("sudo", "certbot", "certonly", "--standalone", "-d", domain,
		"--agree-tos", "--non-interactive", "--email", email)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Println("certbot failed:", err)
		fmt.Println("Check that the domain points at this server and port 80 is open, then try again.")
		return
	}
	cert, key, ok := findCerts(domain)
	if !ok {
		fmt.Println("certbot finished but I cannot find the certificate. Check /etc/letsencrypt/live/" + domain + "/")
		return
	}
	cfg.TLSEnabled = true
	cfg.CertFile, cfg.KeyFile = cert, key
	_ = saveConfig(*cfg)
	fmt.Println("SSL is on — certificate found at", cert)
	fmt.Println("Restart the web UI (option 3) to serve https://" + domain)
}

func selfUpdate() error {
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
			return fmt.Errorf("download failed (no release yet? create a v0.1.0 release first): %w", err)
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
	if err := os.Rename(tmpPath, exe); err != nil {
		return fmt.Errorf("could not replace %s (do you have write permission there?): %w", exe, err)
	}
	fmt.Println("Updated:", exe)
	return nil
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

func uninstall(cfg Config, scanner *bufio.Scanner) {
	fmt.Println("This will stop LoadInMe and remove the binary and the service.")
	keep := prompt(scanner, "Keep your data (files, clips, settings, login) in "+cfg.DataDir+"? (y/n)", "y")
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
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for {
		printMenuHeader(*cfg)
		fmt.Println("  1  Start web UI")
		fmt.Println("  2  Stop web UI")
		fmt.Println("  3  Restart web UI")
		fmt.Println("  4  Status")
		fmt.Println("  5  Change port")
		fmt.Println("  6  Set domain")
		fmt.Println("  7  SSL with Let's Encrypt")
		fmt.Println("  8  Update LoadInMe")
		fmt.Println("  9  Change username / password")
		fmt.Println("  10 View settings")
		fmt.Println("  11 Show web UI link")
		fmt.Println("  12 Uninstall")
		fmt.Println("  0  Exit")
		fmt.Println()
		fmt.Print("  Choose [0-12]: ")
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
			_ = withStore(cfg, func(store *Store) error {
				if st, err := store.GetSettings(); err == nil {
					fmt.Printf("Limits: %d items max, %d MB per file, %d h default expiry\n",
						st.MaxItems, st.MaxFileMB, st.DefaultExpiryHours)
				}
				if n, err := store.CountItems(); err == nil {
					fmt.Println("Items stored:", n)
				}
				return nil
			})
			pause(scanner)
		case "5":
			portStr := prompt(scanner, "Web port", strconv.Itoa(cfg.Port))
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
			domain := prompt(scanner, "Domain (example: files.example.com, blank to clear)", cfg.Domain)
			cfg.Domain = strings.TrimSpace(domain)
			_ = saveConfig(*cfg)
			if cfg.Domain == "" {
				fmt.Println("Domain cleared. The web link now shows your server IP.")
			} else {
				fmt.Println("Domain set to", cfg.Domain)
				fmt.Println("Web link is now:", webAddressFor(*cfg))
				fmt.Println("For https, set up SSL with option 7.")
			}
			pause(scanner)
		case "7":
			setupSSL(cfg, scanner)
			pause(scanner)
		case "8":
			if err := selfUpdate(); err != nil {
				fmt.Println("Update failed:", err)
				fmt.Println("You can also run the installer again:")
				fmt.Println("  curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash")
			} else {
				fmt.Println("Update done. Restart the web UI (option 3) to use the new version.")
			}
			pause(scanner)
		case "9":
			err := withStore(cfg, func(store *Store) error {
				return setPasswordCLI(store, "")
			})
			if err != nil {
				fmt.Println("Could not change password:", err)
			}
			pause(scanner)
		case "10":
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
				fmt.Println("Could not open data store:", err)
			}
			pause(scanner)
		case "11":
			fmt.Println("Web UI:", webAddressFor(*cfg))
			fmt.Println("Local:  http://localhost:" + strconv.Itoa(cfg.Port))
			pause(scanner)
		case "12":
			uninstall(*cfg, scanner)
			pause(scanner)
			return
		case "0", "q", "quit", "exit":
			fmt.Println("Bye.")
			return
		default:
			fmt.Println("Please choose 0-12.")
			pause(scanner)
		}
	}
}
