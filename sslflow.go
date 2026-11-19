package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// renewWindow: `loadinme ssl renew` renews when fewer days are left.
const renewWindow = 30 * 24 * time.Hour

// errNeedRoot means the step must run as root (port 80, nginx, systemd).
var errNeedRoot = errors.New("this step needs root")

// renewalInfo is saved next to the certificate: how it was issued, so
// `loadinme ssl renew` can do the same again unattended.
type renewalInfo struct {
	Domain    string    `json:"domain"`
	Email     string    `json:"email"`
	Method    string    `json:"method"`
	Unit      string    `json:"unit,omitempty"`
	Directory string    `json:"directory"`
	IssuedAt  time.Time `json:"issuedAt"`
	NotAfter  time.Time `json:"notAfter"`
}

func renewalInfoPath(dataDir, domain string) string {
	return filepath.Join(certDir(dataDir, domain), "renewal.json")
}

func readRenewalInfo(dataDir, domain string) (renewalInfo, error) {
	var ri renewalInfo
	b, err := os.ReadFile(renewalInfoPath(dataDir, domain))
	if err != nil {
		return ri, err
	}
	err = json.Unmarshal(b, &ri)
	return ri, err
}

func writeRenewalInfo(dataDir string, ri renewalInfo) error {
	b, _ := json.MarshalIndent(ri, "", "  ")
	p := renewalInfoPath(dataDir, ri.Domain)
	if err := writeFileAtomic(p, b, 0o600); err != nil {
		return err
	}
	chownToApp(dataDir, p)
	return nil
}

// isLegacyCert reports whether the config points at a certbot
// certificate (/etc/letsencrypt), from before v0.7.0.
func isLegacyCert(cfg Config) bool {
	return cfg.CertFile != "" && strings.HasPrefix(cfg.CertFile, letsEncryptDir+string(filepath.Separator))
}

// sslPlan is how the domain will be proven, and why.
type sslPlan struct {
	Method   string
	Why      []string
	Owner    portOwner
	Unit     string // stop-service: the unit to pause
	StopSelf bool   // standalone, but LoadInMe's own web UI is on port 80
	Block    string // nginx-conflict: file of the existing server block
}

func (p sslPlan) needsRoot() bool { return p.Method != methodDNSCloudflare }

func nginxRunning() bool {
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if b, err := os.ReadFile(filepath.Join("/proc", p.Name(), "comm")); err == nil && strings.TrimSpace(string(b)) == "nginx" {
			return true
		}
	}
	return false
}

// planHTTP picks the HTTP-01 strategy for this server.
func planHTTP(domain string) sslPlan {
	o := detectPort80()
	if o.Free {
		return sslPlan{Method: methodStandalone, Owner: o, Why: []string{
			"Port 80 is free on this server, so LoadInMe answers Let's Encrypt on port 80 itself",
			"for the few seconds of the check. Nothing else is touched.",
		}}
	}
	isNginx := o.Process == "nginx" || (o.Process == "" && nginxRunning())
	if isNginx {
		dump, err := nginxDump()
		if err == nil {
			if blk, found := findNginxBlockFor(dump, domain); found {
				if blk.hasChallengeProxy() {
					return sslPlan{Method: methodNginxExisting, Owner: o, Block: blk.File, Why: []string{
						"nginx owns port 80 and already serves " + domain + " (in " + blk.File + "),",
						"with the challenge line for LoadInMe in it. nginx keeps running; it forwards only",
						"the check to LoadInMe on 127.0.0.1:" + fmt.Sprint(acmeLoopbackPort()) + ".",
					}}
				}
				return sslPlan{Method: planNginxConflict, Owner: o, Block: blk.File, Why: []string{
					"nginx owns port 80 and already has a server block for " + domain + " in " + blk.File + ".",
					"A second block for the same name would be ignored by nginx, so LoadInMe cannot add",
					"its temporary one.",
				}}
			}
		}
		return sslPlan{Method: methodNginx, Owner: o, Why: []string{
			"nginx owns port 80. LoadInMe adds a tiny temporary nginx config for " + domain + " that forwards",
			"only /.well-known/acme-challenge/ to LoadInMe on 127.0.0.1, reloads nginx (no downtime),",
			"and removes it again right after.",
		}}
	}
	if o.Process == "loadinme" {
		return sslPlan{Method: methodStandalone, StopSelf: true, Owner: o, Why: []string{
			"LoadInMe's own web UI is on port 80. It pauses for the few seconds of the check",
			"while LoadInMe answers Let's Encrypt on port 80, then starts again.",
		}}
	}
	if strings.Contains(o.Process, "docker") {
		return sslPlan{Method: planBlocked, Owner: o, Why: []string{
			"Port 80 is published by a Docker container (" + o.describe() + ").",
			"LoadInMe will not stop Docker. Use the DNS method (Cloudflare) instead.",
		}}
	}
	if o.Unit != "" {
		return sslPlan{Method: methodStopService, Unit: o.Unit, Owner: o, Why: []string{
			"Port 80 is used by " + o.describe() + ".",
			"LoadInMe can stop it for the few seconds of the check and start it again right after",
			"(always, even if the check fails). Visitors of that service may wait a few seconds.",
		}}
	}
	return sslPlan{Method: planBlocked, Owner: o, Why: []string{
		"Port 80 is used by " + o.describe() + ", and LoadInMe cannot tell which service to pause.",
		"Free port 80 for a minute, or use the DNS method (Cloudflare) instead.",
	}}
}

// obtainWithPlan sets up the challenge path for the plan, runs the
// ACME order, and always undoes the setup (snippet removed, service
// started again) — also on failure or Ctrl-C.
func obtainWithPlan(cfg Config, domain, email string, plan sslPlan, out io.Writer) (*issued, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	opts := issueOptions{DataDir: cfg.DataDir, Domain: domain, Email: email, Out: out}
	if plan.needsRoot() && !isRoot() {
		return nil, errNeedRoot
	}
	switch plan.Method {
	case methodStandalone:
		if plan.StopSelf {
			fmt.Fprintln(out, "Pausing LoadInMe's web UI for a few seconds (it is on port 80)…")
			_ = stopService(cfg)
			defer func() {
				if err := startService(cfg); err != nil && !errors.Is(err, errAlreadyRunning) {
					fmt.Fprintln(out, "Warning: could not start the web UI again:", err)
				}
			}()
			waitPort80(true, 10*time.Second)
		}
		cs, err := startChallengeServer(":80")
		if err != nil {
			return nil, fmt.Errorf("could not use port 80: %v", err)
		}
		defer cs.Close()
		opts.HTTP, opts.SelfCheck = cs, true
	case methodNginx:
		cs, err := startChallengeServer("127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer cs.Close()
		remove, err := installNginxSnippet(domain, cs.port(), out)
		if err != nil {
			return nil, err
		}
		defer remove()
		opts.HTTP, opts.SelfCheck = cs, true
	case methodNginxExisting:
		cs, err := startChallengeServer(fmt.Sprintf("127.0.0.1:%d", acmeLoopbackPort()))
		if err != nil {
			return nil, fmt.Errorf("could not listen on 127.0.0.1:%d: %v", acmeLoopbackPort(), err)
		}
		defer cs.Close()
		opts.HTTP, opts.SelfCheck = cs, true
	case methodStopService:
		if plan.Unit == "" {
			return nil, errors.New("no service to pause was saved")
		}
		fmt.Fprintf(out, "Stopping %s for a few seconds…\n", plan.Unit)
		if err := systemctlRoot("stop", plan.Unit); err != nil {
			return nil, err
		}
		// Registered first, so it runs last: after the challenge
		// server has let go of port 80.
		defer func() {
			if err := systemctlRoot("start", plan.Unit); err != nil {
				fmt.Fprintf(out, "WARNING: could not start %s again: %v — start it by hand: sudo systemctl start %s\n", plan.Unit, err, plan.Unit)
			} else {
				fmt.Fprintf(out, "Started %s again.\n", plan.Unit)
			}
		}()
		if !waitPort80(true, 15*time.Second) {
			return nil, fmt.Errorf("port 80 was still in use after stopping %s", plan.Unit)
		}
		cs, err := startChallengeServer(":80")
		if err != nil {
			return nil, fmt.Errorf("could not use port 80: %v", err)
		}
		defer cs.Close()
		opts.HTTP, opts.SelfCheck = cs, true
	case methodDNSCloudflare:
		token := readCloudflareToken(cfg.DataDir)
		if token == "" {
			return nil, errors.New("no Cloudflare API token saved (menu 6 → 1 → DNS asks for one)")
		}
		opts.DNS = newCloudflareDNS(token, out)
	default:
		return nil, fmt.Errorf("cannot issue with method %q", plan.Method)
	}
	return obtainCertificate(ctx, opts)
}

// issueRequest is one "get a certificate" run (menu 6 → 1 or
// `loadinme ssl issue`).
type issueRequest struct {
	Domain string
	Email  string
	Method string // "" / "auto", or one of the method constants
	Yes    bool   // answer yes to confirmations (non-interactive)
	In     *bufio.Scanner
	Out    io.Writer
}

func (r issueRequest) confirm(q string, def bool) bool {
	if r.Yes {
		return true
	}
	return askYesNo(r.In, r.Out, q, def)
}

// runIssue gets a certificate and turns HTTPS on. It does not restart
// the web UI (the caller does).
func runIssue(cfg *Config, req issueRequest) error {
	out := req.Out
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		return errors.New("a domain is required")
	}
	if req.Email == "" {
		if ri, err := readRenewalInfo(cfg.DataDir, domain); err == nil {
			req.Email = ri.Email
		}
	}
	method := req.Method
	if method == "" {
		method = "auto"
	}
	fmt.Fprintf(out, "Getting an SSL certificate for %s", domain)
	if d := acmeDirectoryURL(); d != letsEncryptProduction {
		fmt.Fprintf(out, " from the test CA at %s", d)
	} else {
		fmt.Fprint(out, " from Let's Encrypt")
	}
	fmt.Fprintln(out, ".")

	// 1. Pre-flight: does the domain point here? (DNS-01 does not care.)
	if method != methodDNSCloudflare {
		pf := preflight(domain)
		for _, l := range pf.Lines {
			fmt.Fprintln(out, l)
		}
		if !pf.OK && !req.confirm("Try anyway?", false) {
			return errCancelled
		}
	}

	// 2. Strategy.
	var plan sslPlan
	switch method {
	case "auto":
		plan = planHTTP(domain)
	case methodDNSCloudflare:
		plan = sslPlan{Method: methodDNSCloudflare, Why: []string{
			"Using DNS: LoadInMe adds a TXT record through the Cloudflare API, waits until it is",
			"visible, and removes it afterwards. Port 80 is not needed.",
		}}
	case methodStandalone, methodNginx, methodNginxExisting:
		plan = sslPlan{Method: method, Why: []string{"Using the method you chose: " + methodLabel(method) + "."}}
	case methodStopService:
		plan = planHTTP(domain)
		if plan.Method == planNginxConflict || plan.Method == methodNginx || plan.Method == methodNginxExisting {
			unit := plan.Owner.Unit
			if unit == "" {
				unit = "nginx.service"
			}
			plan = sslPlan{Method: methodStopService, Unit: unit, Owner: plan.Owner, Why: []string{
				"Port 80 is used by nginx; it is stopped for the few seconds of the check and started again right after."}}
		}
		if plan.Method != methodStopService {
			return fmt.Errorf("stop-service needs a systemd service on port 80, but: %s", strings.Join(plan.Why, " "))
		}
	default:
		return fmt.Errorf("unknown method %q (auto, standalone, nginx, nginx-existing, stop-service, dns-cloudflare)", method)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "How LoadInMe will prove the domain is yours:", methodLabel(plan.Method))
	for _, l := range plan.Why {
		fmt.Fprintln(out, "  "+l)
	}
	fmt.Fprintln(out)

	switch plan.Method {
	case planNginxConflict:
		fmt.Fprintln(out, "Option A (no downtime, also for every renewal): add this one line inside that")
		fmt.Fprintln(out, "server block (the one for port 80 in "+plan.Block+"):")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "    "+nginxChallengeLine())
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  If the block has a server-wide `return 301 …` redirect, move it into `location / { … }`,")
		fmt.Fprintln(out, "  and if it already has a `location /.well-known/acme-challenge/` (from certbot), replace that one.")
		fmt.Fprintln(out, "  Then run: sudo nginx -t && sudo systemctl reload nginx — and choose Get SSL again.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Option B: stop nginx for the few seconds of the check (and every renewal), then start it again.")
		if req.In == nil && !req.Yes {
			return errors.New("nginx already serves this domain: add the line above, or run again with --method stop-service --yes")
		}
		if !req.confirm("Use option B now (stop nginx for a few seconds)?", false) {
			fmt.Fprintln(out, "OK — add the line, then choose Get SSL again. Nothing was changed.")
			return errCancelled
		}
		o := plan.Owner
		unit := o.Unit
		if unit == "" {
			unit = "nginx.service"
		}
		plan = sslPlan{Method: methodStopService, Unit: unit, Owner: o}
	case planBlocked:
		return errors.New("port 80 cannot be used here — choose the DNS method (Cloudflare) in the menu, or free port 80 and try again")
	case methodStopService:
		if !req.confirm("Stop "+plan.Unit+" for a few seconds now?", false) {
			fmt.Fprintln(out, "Nothing was changed.")
			return errCancelled
		}
	}
	if plan.needsRoot() && !isRoot() {
		return errNeedRoot
	}

	// 3. Issue.
	cert, err := obtainWithPlan(*cfg, domain, req.Email, plan, out)
	if err != nil {
		return err
	}
	certPath, keyPath, err := saveCertFiles(cfg.DataDir, domain, cert.CertPEM, cert.KeyPEM)
	if err != nil {
		return fmt.Errorf("certificate issued but could not be saved: %w", err)
	}
	_ = writeRenewalInfo(cfg.DataDir, renewalInfo{
		Domain: domain, Email: req.Email, Method: plan.Method, Unit: plan.Unit,
		Directory: acmeDirectoryURL(), IssuedAt: time.Now().UTC(), NotAfter: cert.NotAfter,
	})
	fmt.Fprintf(out, "✓ Certificate issued by %s, valid until %s.\n", cert.Issuer, cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintln(out, "  Saved in", filepath.Dir(certPath))

	// 4. HTTPS on.
	cfg.Domain = domain
	cfg.TLSEnabled = true
	cfg.CertFile, cfg.KeyFile = certPath, keyPath
	if err := saveConfig(*cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, "✓ HTTPS is on:", webAddressFor(*cfg))

	// 5. Automatic renewal.
	ensureRenewTimer(cfg.DataDir, out)
	return nil
}

func selfExe() string {
	exe, err := os.Executable()
	if err != nil {
		return "loadinme"
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		return p
	}
	return exe
}

// ensureRenewTimer installs loadinme-renew.timer (as root directly,
// otherwise through sudo).
func ensureRenewTimer(dataDir string, out io.Writer) {
	if isRoot() {
		if err := installRenewTimer(selfExe(), dataDir); err != nil {
			fmt.Fprintln(out, "⚠ Could not set up automatic renewal:", err)
			fmt.Fprintln(out, "  Renew by hand before expiry: sudo loadinme ssl renew --data-dir "+dataDir)
			return
		}
		fmt.Fprintln(out, "✓ Automatic renewal is on (loadinme-renew.timer checks twice a day; renews 30 days before expiry).")
		return
	}
	fmt.Fprintln(out, "Setting up automatic renewal needs root — asking sudo…")
	if err := runAsRoot("ssl", "install-timer", "--data-dir", dataDir); err != nil {
		fmt.Fprintln(out, "⚠ Could not set up automatic renewal:", err)
		fmt.Fprintln(out, "  Run: sudo loadinme ssl install-timer --data-dir "+dataDir)
	}
}

// runAsRoot runs this binary again through sudo with the given args,
// on this terminal. LOADINME_* settings are passed along (sudo drops
// the environment).
func runAsRoot(args ...string) error {
	full := []string{"env"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LOADINME_") {
			full = append(full, kv)
		}
	}
	full = append(full, selfExe())
	full = append(full, args...)
	cmd := exec.Command("sudo", full...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// planForRenewal turns the saved method back into a plan. It never
// asks anything: it runs from the timer.
func planForRenewal(ri renewalInfo, out io.Writer) (sslPlan, error) {
	switch ri.Method {
	case methodDNSCloudflare:
		return sslPlan{Method: methodDNSCloudflare}, nil
	case methodStopService:
		return sslPlan{Method: methodStopService, Unit: ri.Unit}, nil
	case methodStandalone, methodNginx, methodNginxExisting:
		// Re-detect: the server may have changed since (nginx
		// installed, a block added), but never pause a service
		// unattended unless that was the saved choice.
		p := planHTTP(ri.Domain)
		switch p.Method {
		case methodStandalone, methodNginx, methodNginxExisting:
			return p, nil
		}
		if ri.Method == methodStandalone && p.Method == methodStopService {
			return p, fmt.Errorf("port 80 is now used by %s; renewal does not stop services it was not told to — run menu 6 → 1 once to choose a method", p.Owner.describe())
		}
		return p, fmt.Errorf("%s", strings.Join(p.Why, " "))
	}
	return sslPlan{}, fmt.Errorf("unknown renewal method %q", ri.Method)
}

// runRenew renews the certificate when fewer than 30 days are left
// (or always with force), with the method saved at issue time.
func runRenew(cfg *Config, force bool, out io.Writer) error {
	if cfg.Domain == "" || cfg.CertFile == "" {
		fmt.Fprintln(out, "No certificate configured — nothing to renew.")
		return nil
	}
	if isLegacyCert(*cfg) {
		fmt.Fprintln(out, "The certificate in use comes from certbot ("+cfg.CertFile+"), not from LoadInMe.")
		fmt.Fprintln(out, "Re-issue it with LoadInMe (loadinme menu → 6 → 1) so renewals are automatic.")
		return nil
	}
	ri, err := readRenewalInfo(cfg.DataDir, cfg.Domain)
	if err != nil {
		return fmt.Errorf("no renewal settings for %s (%v) — get the certificate again with menu 6 → 1", cfg.Domain, err)
	}
	if leaf, err := readLeaf(cfg.CertFile); err == nil {
		left := time.Until(leaf.NotAfter)
		if !force && left > renewWindow {
			fmt.Fprintf(out, "Certificate for %s is valid until %s (%d days left) — no renewal needed yet (renews when fewer than 30 days are left).\n",
				cfg.Domain, leaf.NotAfter.Format("2006-01-02"), int(left.Hours()/24))
			return nil
		}
	}
	plan, err := planForRenewal(ri, out)
	if err != nil {
		return err
	}
	if plan.needsRoot() && !isRoot() {
		return errNeedRoot
	}
	fmt.Fprintf(out, "Renewing the certificate for %s (%s)…\n", cfg.Domain, methodLabel(plan.Method))
	cert, err := obtainWithPlan(*cfg, cfg.Domain, ri.Email, plan, out)
	if err != nil {
		return err
	}
	certPath, keyPath, err := saveCertFiles(cfg.DataDir, cfg.Domain, cert.CertPEM, cert.KeyPEM)
	if err != nil {
		return err
	}
	ri.Method = plan.Method
	if plan.Unit != "" {
		ri.Unit = plan.Unit
	}
	ri.IssuedAt, ri.NotAfter = time.Now().UTC(), cert.NotAfter
	ri.Directory = acmeDirectoryURL()
	_ = writeRenewalInfo(cfg.DataDir, ri)
	if cfg.CertFile != certPath || cfg.KeyFile != keyPath {
		cfg.CertFile, cfg.KeyFile = certPath, keyPath
		_ = saveConfig(*cfg)
	}
	fmt.Fprintf(out, "✓ Renewed: valid until %s. The web UI picks it up within a minute — no restart needed.\n", cert.NotAfter.Format("2006-01-02"))
	return nil
}

// printSSLStatus shows domain, issuer, expiry, method and the timer.
func printSSLStatus(cfg Config, out io.Writer) {
	if cfg.Domain == "" {
		fmt.Fprintln(out, "Domain:  (none set)")
	} else {
		fmt.Fprintln(out, "Domain: ", cfg.Domain)
	}
	if !cfg.TLSEnabled {
		fmt.Fprintln(out, "SSL:     off")
	} else {
		fmt.Fprintln(out, "SSL:     on —", webAddressFor(cfg))
	}
	if cfg.CertFile != "" {
		fmt.Fprintln(out, "Cert:   ", cfg.CertFile)
		if leaf, err := readLeaf(cfg.CertFile); err == nil {
			left := int(time.Until(leaf.NotAfter).Hours() / 24)
			fmt.Fprintln(out, "Issuer: ", issuerName(leaf))
			fmt.Fprintf(out, "Expires: %s (%d days left)\n", leaf.NotAfter.Format("2006-01-02"), left)
		} else {
			fmt.Fprintln(out, "Cert:    could not be read:", err)
		}
	}
	if isLegacyCert(cfg) {
		fmt.Fprintln(out, "Method: ", methodLabel("certbot"))
	} else if cfg.Domain != "" {
		if ri, err := readRenewalInfo(cfg.DataDir, cfg.Domain); err == nil {
			label := methodLabel(ri.Method)
			if ri.Unit != "" {
				label += " — pauses " + ri.Unit
			}
			fmt.Fprintln(out, "Method: ", label)
		}
	}
	switch {
	case renewTimerActive():
		fmt.Fprintln(out, "Renewal: automatic — loadinme-renew.timer is active (checks twice a day)")
	case renewTimerInstalled():
		fmt.Fprintln(out, "Renewal: loadinme-renew.timer is installed but NOT active — run: sudo systemctl enable --now loadinme-renew.timer")
	default:
		fmt.Fprintln(out, "Renewal: no renewal timer installed (Get SSL sets it up)")
	}
	if isLegacyCert(cfg) {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "This certificate comes from certbot (from before v0.7.0). certbot's renewals often")
		fmt.Fprintln(out, "fail on a server with nginx on port 80, and LoadInMe may not be allowed to read")
		fmt.Fprintln(out, "/etc/letsencrypt. Choose 1 Get SSL to re-issue it the new way.")
	}
}

// sslOff turns HTTPS off; with removeFiles it also deletes LoadInMe's
// certificate files for the domain.
func sslOff(cfg *Config, removeFiles bool, out io.Writer) {
	wasOn := cfg.TLSEnabled
	cfg.TLSEnabled = false
	if removeFiles && cfg.Domain != "" && !isLegacyCert(*cfg) {
		if err := os.RemoveAll(certDir(cfg.DataDir, cfg.Domain)); err == nil {
			fmt.Fprintln(out, "Deleted the certificate files in", certDir(cfg.DataDir, cfg.Domain))
		}
		cfg.CertFile, cfg.KeyFile = "", ""
	}
	if removeFiles && isLegacyCert(*cfg) {
		fmt.Fprintln(out, "The certificate is certbot's ("+cfg.CertFile+"); LoadInMe leaves it alone.")
		cfg.CertFile, cfg.KeyFile = "", ""
	}
	_ = saveConfig(*cfg)
	if wasOn {
		fmt.Fprintln(out, "SSL is off — the web UI serves plain http.")
	} else {
		fmt.Fprintln(out, "SSL was already off.")
	}
}

// restartWebUIAfterSSL restarts the web UI when it runs (or starts it
// when it does not), so the new setting applies right away.
func restartWebUIAfterSSL(cfg Config, out io.Writer) {
	if isServiceRunning(cfg) {
		fmt.Fprintln(out, "Restarting the web UI…")
		if err := restartService(cfg); err != nil {
			fmt.Fprintln(out, "The web UI could not be restarted:", err)
			fmt.Fprintln(out, "Start it with option 1.")
			return
		}
	} else {
		fmt.Fprintln(out, "Starting the web UI…")
		if err := startService(cfg); err != nil && !errors.Is(err, errAlreadyRunning) {
			fmt.Fprintln(out, "The web UI could not be started:", err)
			fmt.Fprintln(out, "Start it with option 1.")
			return
		}
	}
	fmt.Fprintln(out, "Web UI is now serving", webAddressFor(cfg))
}
