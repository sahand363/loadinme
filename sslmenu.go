package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// domainSSLMenu is menu option 6 "Domain & SSL":
//
//	1 Get SSL (domain → email → strategy picked automatically → issue →
//	  HTTPS on → web UI restarted)
//	2 SSL status   3 Renew now   4 Turn SSL off / remove certificate
//	5 Clear saved domain   6 Address without port (v0.8.0)
//	0 Back (no extra "Press Enter")
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
		if cfg.TLSEnabled && isLegacyCert(*cfg) {
			fmt.Println("  Note: this certificate comes from certbot (before v0.7.0) — choose 1 to re-issue it")
			fmt.Println("        the new way, so renewals work with nginx on port 80.")
		}
		fmt.Println("  1  Get SSL (enter domain, then email)")
		fmt.Println("  2  SSL status")
		fmt.Println("  3  Renew now")
		fmt.Println("  4  Turn SSL off / remove certificate")
		fmt.Println("  5  Clear saved domain")
		fmt.Println("  6  Address without port (https://" + domainOr(cfg.Domain, "your-domain") + ")")
		fmt.Println("  0  Back to main menu")
		fmt.Println()
		fmt.Print("  Choose [0-6]: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		fmt.Println()
		switch choice {
		case "1":
			menuGetSSL(cfg, scanner)
		case "2":
			printSSLStatus(*cfg, os.Stdout)
		case "3":
			menuRenewNow(cfg)
		case "4":
			menuSSLOff(cfg, scanner)
		case "5":
			clearSavedDomain(cfg)
		case "6":
			menuExposeAddress(cfg, scanner)
		case "0":
			return
		default:
			fmt.Println("Please choose 0-6.")
		}
		fmt.Println()
	}
}

// reloadConfigFromDisk picks up what a sudo child process saved,
// keeping this menu's port (it may be a one-off --port override).
func reloadConfigFromDisk(cfg *Config) {
	fresh, err := loadConfig(cfg.DataDir)
	if err != nil {
		return
	}
	fresh.DataDir = cfg.DataDir
	fresh.Port = cfg.Port
	*cfg = fresh
}

// menuGetSSL is submenu 1.
func menuGetSSL(cfg *Config, scanner *bufio.Scanner) {
	domain, cancelled := promptCancel(scanner, "Domain (example: files.example.com)", cfg.Domain)
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /:") {
		fmt.Println("That does not look like a domain (example: files.example.com). Nothing changed.")
		return
	}
	cfg.Domain = domain
	_ = saveConfig(*cfg)
	defEmail := ""
	if ri, err := readRenewalInfo(cfg.DataDir, domain); err == nil {
		defEmail = ri.Email
	}
	email, cancelled := promptCancel(scanner, "Email for Let's Encrypt (expiry notices)", defEmail)
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	email = strings.TrimSpace(email)
	if email == "" || !strings.Contains(email, "@") {
		fmt.Println("An email address is required. Nothing changed.")
		return
	}
	fmt.Println("How should Let's Encrypt check that the domain is yours?")
	fmt.Println("  1  Automatic over HTTP (recommended — LoadInMe picks the way that fits this server)")
	fmt.Println("  2  DNS with a Cloudflare API token (when port 80 cannot be used at all)")
	how, cancelled := promptCancel(scanner, "Choose", "1")
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	method := "auto"
	switch strings.TrimSpace(how) {
	case "1":
	case "2":
		method = methodDNSCloudflare
		if !menuCloudflareToken(cfg, scanner) {
			return
		}
	default:
		fmt.Println("Please choose 1 or 2. Nothing changed.")
		return
	}
	fmt.Println()

	var err error
	if isRoot() || method == methodDNSCloudflare {
		err = runIssue(cfg, issueRequest{Domain: domain, Email: email, Method: method, In: scanner, Out: os.Stdout})
	} else {
		// The HTTP methods need root (port 80, nginx, systemd): run
		// just this step through sudo, on this terminal.
		fmt.Println("This step needs root (port 80 / nginx / systemd), so it runs through sudo —")
		fmt.Println("you may be asked for your password.")
		fmt.Println()
		err = runAsRoot("ssl", "issue", "--domain", domain, "--email", email, "--method", method,
			"--data-dir", cfg.DataDir, "--no-restart")
		reloadConfigFromDisk(cfg)
		if err != nil {
			fmt.Println()
			fmt.Println("No new certificate (see above). Nothing else was changed.")
			fmt.Println("You can also run it directly: sudo loadinme ssl issue --domain " + domain + " --email " + email)
			return
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, errCancelled):
			fmt.Println("Cancelled.")
		case errors.Is(err, errNeedRoot):
			fmt.Println("This needs root. Run the menu with sudo (sudo loadinme menu), or:")
			fmt.Println("  sudo loadinme ssl issue --domain " + domain + " --email " + email)
		default:
			fmt.Println("Could not get the certificate:", err)
			fmt.Println("Nothing else was changed.")
		}
		return
	}
	fmt.Println()
	restartWebUIAfterSSL(*cfg, os.Stdout)
	// Offer the address without port right away.
	if cfg.Expose == nil && cfg.TLSEnabled && cfg.Port != httpsPort() {
		fmt.Println()
		fmt.Println("Next: make it reachable at https://" + cfg.Domain + " with no port? LoadInMe checks who uses")
		fmt.Println("port 443 and picks the way; it asks before changing another web server's config.")
		ans, cancelled := promptCancel(scanner, "Set up the address without port now? (y/n)", "y")
		if cancelled {
			fmt.Println("Skipped — it is in this menu as 6 any time.")
			return
		}
		if a := strings.ToLower(ans); a == "y" || a == "yes" {
			fmt.Println()
			menuRunExpose(cfg, scanner)
		} else {
			fmt.Println("Skipped — it is in this menu as 6 any time.")
		}
	}
}

func domainOr(d, def string) string {
	if d == "" {
		return def
	}
	return d
}

// menuExposeAddress is submenu 6: Address without port.
func menuExposeAddress(cfg *Config, scanner *bufio.Scanner) {
	fmt.Println("  Address without port")
	if cfg.Expose != nil {
		fmt.Println("  Now: https://" + cfg.Domain + " — " + exposeLabel(cfg.Expose.Method))
		if cfg.proxied() {
			fmt.Printf("       LoadInMe listens on 127.0.0.1:%d behind %s\n", cfg.Port, frontName(cfg.Expose.Method))
		}
		fmt.Println("  1  Check that it answers")
		fmt.Printf("  2  Undo — back to https://%s:%d\n", cfg.Domain, cfg.Port)
		fmt.Println("  0  Back")
		fmt.Println()
		fmt.Print("  Choose [0-2]: ")
		if !scanner.Scan() {
			return
		}
		fmt.Println()
		switch strings.TrimSpace(scanner.Text()) {
		case "1":
			if err := verifyExposed(*cfg, 5*time.Second); err != nil {
				fmt.Println("⚠ https://"+cfg.Domain+" does not answer on this server:", err)
				if !isServiceRunning(*cfg) {
					fmt.Println("  The web UI is stopped — start it with option 1 of the main menu.")
				}
			} else {
				fmt.Println("✓ https://" + cfg.Domain + " answers on this server (port " + fmt.Sprint(httpsPort()) + ").")
			}
		case "2":
			ans, cancelled := promptCancel(scanner, "Remove the address without port? (y/n)", "y")
			if cancelled {
				fmt.Println("Cancelled.")
				return
			}
			if a := strings.ToLower(ans); a != "y" && a != "yes" {
				fmt.Println("Nothing changed.")
				return
			}
			menuRunUnexpose(cfg)
		case "0", "":
		default:
			fmt.Println("Please choose 0-2.")
		}
		return
	}
	if cfg.Domain == "" || !cfg.TLSEnabled {
		fmt.Println("  First get SSL for your domain (1 Get SSL) — then LoadInMe can drop the port.")
		return
	}
	fmt.Println("  Now: " + webAddressFor(*cfg) + " (with a port)")
	fmt.Println("  1  Set it up (LoadInMe looks at who uses port 443 and picks the way)")
	fmt.Println("  0  Back")
	fmt.Println()
	fmt.Print("  Choose [0-1]: ")
	if !scanner.Scan() {
		return
	}
	fmt.Println()
	switch strings.TrimSpace(scanner.Text()) {
	case "1":
		menuRunExpose(cfg, scanner)
	case "0", "":
	default:
		fmt.Println("Please choose 0-1.")
	}
}

// menuRunExpose runs the expose step (through sudo when needed) and
// restarts the web UI.
func menuRunExpose(cfg *Config, scanner *bufio.Scanner) {
	var err error
	if isRoot() {
		err = runExpose(cfg, exposeRequest{In: scanner, Out: os.Stdout})
	} else {
		fmt.Println("This step needs root (ports 443/80, or another web server's config), so it runs")
		fmt.Println("through sudo — you may be asked for your password.")
		fmt.Println()
		if rerr := runAsRoot("ssl", "expose", "--data-dir", cfg.DataDir, "--no-restart"); rerr != nil {
			fmt.Println("Not set up (see above).")
		}
		reloadConfigFromDisk(cfg)
	}
	switch {
	case err == nil, errors.Is(err, errNoChange):
	case errors.Is(err, errCancelled):
		fmt.Println("Cancelled.")
	case errors.Is(err, errNeedRoot):
		fmt.Println("This needs root. Run the menu with sudo (sudo loadinme menu), or: sudo loadinme ssl expose")
	default:
		fmt.Println("Could not set it up:", err)
	}
	if cfg.Expose != nil {
		finishExpose(*cfg, os.Stdout)
	}
}

func menuRunUnexpose(cfg *Config) {
	var err error
	if isRoot() || !cfg.Expose.undoNeedsRoot() {
		err = runUnexpose(cfg, os.Stdout)
	} else {
		fmt.Println("Undoing needs root (it removes the web server config / port permission), so it runs")
		fmt.Println("through sudo — you may be asked for your password.")
		if rerr := runAsRoot("ssl", "unexpose", "--data-dir", cfg.DataDir, "--no-restart"); rerr != nil {
			fmt.Println("Could not undo it (see above).")
		}
		reloadConfigFromDisk(cfg)
	}
	if err != nil {
		fmt.Println("Could not undo it:", err)
		return
	}
	if cfg.Expose == nil {
		fmt.Println()
		restartWebUIAfterSSL(*cfg, os.Stdout)
	}
}

// menuCloudflareToken makes sure a working Cloudflare token is saved.
func menuCloudflareToken(cfg *Config, scanner *bufio.Scanner) bool {
	if readCloudflareToken(cfg.DataDir) != "" {
		ans, cancelled := promptCancel(scanner, "Use the saved Cloudflare API token? (y/n)", "y")
		if cancelled {
			fmt.Println("Cancelled.")
			return false
		}
		if a := strings.ToLower(ans); a == "y" || a == "yes" {
			return true
		}
	}
	fmt.Println("Create a token at https://dash.cloudflare.com/profile/api-tokens with the template")
	fmt.Println("\"Edit zone DNS\", limited to this domain's zone. It is saved (readable only by you) in")
	fmt.Println(cloudflareTokenPath(cfg.DataDir) + ".")
	token, cancelled := promptCancel(scanner, "Cloudflare API token", "")
	if cancelled || strings.TrimSpace(token) == "" {
		fmt.Println("Cancelled.")
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := newCloudflareDNS(strings.TrimSpace(token), nil).Verify(ctx); err != nil {
		fmt.Println("Cloudflare did not accept that token:", err)
		fmt.Println("Nothing changed.")
		return false
	}
	if err := saveCloudflareToken(cfg.DataDir, token); err != nil {
		fmt.Println("Could not save the token:", err)
		return false
	}
	fmt.Println("✓ Token works and is saved.")
	return true
}

// menuRenewNow is submenu 3: renew right away.
func menuRenewNow(cfg *Config) {
	if cfg.Domain == "" || cfg.CertFile == "" {
		fmt.Println("No certificate yet — choose 1 Get SSL first.")
		return
	}
	needsRoot := true
	if ri, err := readRenewalInfo(cfg.DataDir, cfg.Domain); err == nil && ri.Method == methodDNSCloudflare {
		needsRoot = false
	}
	if isLegacyCert(*cfg) {
		needsRoot = false // runRenew only explains
	}
	if isRoot() || !needsRoot {
		if err := runRenew(cfg, true, os.Stdout); err != nil {
			fmt.Println("Renewal failed:", err)
		}
		return
	}
	fmt.Println("Renewing needs root (port 80 / nginx), so it runs through sudo —")
	fmt.Println("you may be asked for your password.")
	if err := runAsRoot("ssl", "renew", "--force", "--data-dir", cfg.DataDir); err != nil {
		fmt.Println("Renewal failed (see above).")
	}
	reloadConfigFromDisk(cfg)
}

// menuSSLOff is submenu 4: HTTPS off, optionally deleting the files.
func menuSSLOff(cfg *Config, scanner *bufio.Scanner) {
	if !cfg.TLSEnabled && cfg.CertFile == "" {
		fmt.Println("SSL is already off and there is no certificate.")
		return
	}
	if cfg.Expose != nil {
		sslOff(cfg, false, os.Stdout) // explains, changes nothing
		return
	}
	ans, cancelled := promptCancel(scanner, "Turn SSL off? (y/n)", "y")
	if cancelled {
		fmt.Println("Cancelled.")
		return
	}
	if a := strings.ToLower(ans); a != "y" && a != "yes" {
		fmt.Println("Nothing changed.")
		return
	}
	remove := false
	if cfg.CertFile != "" && !isLegacyCert(*cfg) {
		ans, cancelled = promptCancel(scanner, "Also delete the certificate files for "+cfg.Domain+"? (y/n)", "n")
		if cancelled {
			fmt.Println("Cancelled.")
			return
		}
		a := strings.ToLower(ans)
		remove = a == "y" || a == "yes"
	}
	wasRunning := isServiceRunning(*cfg)
	if !sslOff(cfg, remove, os.Stdout) {
		return
	}
	if wasRunning {
		restartWebUIAfterSSL(*cfg, os.Stdout)
	} else {
		fmt.Println("The web UI is stopped; start it with option 1 when ready.")
	}
}
