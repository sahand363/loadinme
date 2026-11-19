package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

func sslUsage() {
	fmt.Print(`Usage:
  loadinme ssl issue  --domain DOMAIN [--email EMAIL] [--method auto] [--yes] [--data-dir DIR]
  loadinme ssl renew  [--force] [--data-dir DIR]
  loadinme ssl status [--data-dir DIR]
  loadinme ssl off    [--remove] [--data-dir DIR]
  loadinme ssl expose   [--method auto] [--yes] [--data-dir DIR]
  loadinme ssl unexpose [--data-dir DIR]

  issue   get a Let's Encrypt certificate and turn HTTPS on (needs root for
          the HTTP methods: sudo loadinme ssl issue …). --method is auto
          (default), standalone, nginx, nginx-existing, stop-service or
          dns-cloudflare. --yes answers yes to the questions.
  renew   renew when fewer than 30 days are left (--force: now), with the
          method saved at issue time. The renewal timer runs this twice a day.
  status  domain, issuer, expiry, method, renewal timer
  off     turn HTTPS off (--remove also deletes the certificate files)
  expose  address without port: make LoadInMe reachable at https://DOMAIN
          (no port). It looks at who owns port 443: free → LoadInMe serves
          443 itself (+ a port-80 redirect); nginx / Apache / Caddy → a
          small site config that forwards to LoadInMe on 127.0.0.1 (it asks
          first); anything else (Docker, xray/x-ui, HAProxy…) → nothing is
          touched and it explains why. Needs root (sudo) for most cases.
          --method nginx-manual / apache-manual: you added the block to your
          own server config; LoadInMe only moves to 127.0.0.1.
  unexpose  undo expose: removes the site config / setcap and restores the
          bind address (the port never changes)
`)
}

// runSSLCLI implements `loadinme ssl …` and returns the exit code.
func runSSLCLI(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		sslUsage()
		return 0
	}
	sub := args[0]
	fs := flag.NewFlagSet("loadinme ssl "+sub, flag.ContinueOnError)
	dataFlag := fs.String("data-dir", "", "data directory")
	domain := fs.String("domain", "", "domain")
	email := fs.String("email", "", "email for Let's Encrypt")
	method := fs.String("method", "auto", "how to prove the domain / how to expose")
	yes := fs.Bool("yes", false, "answer yes to questions")
	force := fs.Bool("force", false, "renew now")
	remove := fs.Bool("remove", false, "also delete the certificate files")
	noRestart := fs.Bool("no-restart", false, "do not restart the web UI afterwards")
	fs.Usage = sslUsage
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	dataDir := *dataFlag
	if dataDir == "" {
		dataDir = defaultDataDir()
	}
	cfg, err := loadConfig(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadinme: could not load config:", err)
		return 1
	}
	cfg.DataDir = dataDir
	out := os.Stdout
	switch sub {
	case "issue":
		d := *domain
		if d == "" {
			d = cfg.Domain
		}
		if d == "" {
			fmt.Fprintln(os.Stderr, "loadinme: --domain is required")
			return 2
		}
		sc := bufio.NewScanner(os.Stdin)
		err := runIssue(&cfg, issueRequest{Domain: d, Email: *email, Method: *method, Yes: *yes, In: sc, Out: out})
		if err != nil {
			return sslCLIError(err, "issue --domain "+d)
		}
		if !*noRestart && isServiceRunning(cfg) {
			restartWebUIAfterSSL(cfg, out)
		}
		if !*noRestart && cfg.Expose == nil && cfg.Port != httpsPort() {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Next (optional): reach it at https://"+cfg.Domain+" with no port — run: sudo loadinme ssl expose")
		}
		return 0
	case "expose":
		sc := bufio.NewScanner(os.Stdin)
		err := runExpose(&cfg, exposeRequest{Method: *method, Yes: *yes, In: sc, Out: out})
		if errors.Is(err, errNoChange) {
			return 0
		}
		if err != nil {
			return sslCLIError(err, "expose")
		}
		if !*noRestart && cfg.Expose != nil {
			finishExpose(cfg, out)
		}
		return 0
	case "unexpose":
		if err := runUnexpose(&cfg, out); err != nil {
			return sslCLIError(err, "unexpose")
		}
		if !*noRestart && isServiceRunning(cfg) {
			restartWebUIAfterSSL(cfg, out)
		}
		return 0
	case "renew":
		if err := runRenew(&cfg, *force, out); err != nil {
			return sslCLIError(err, "renew")
		}
		return 0
	case "status":
		printSSLStatus(cfg, out)
		return 0
	case "off":
		if !sslOff(&cfg, *remove, out) {
			return 1
		}
		if !*noRestart && isServiceRunning(cfg) {
			restartWebUIAfterSSL(cfg, out)
		}
		return 0
	case "install-timer":
		if !isRoot() {
			return sslCLIError(errNeedRoot, "install-timer")
		}
		if err := installRenewTimer(selfExe(), dataDir); err != nil {
			fmt.Fprintln(os.Stderr, "loadinme: could not set up the renewal timer:", err)
			return 1
		}
		fmt.Println("✓ Automatic renewal is on (loadinme-renew.timer checks twice a day; renews 30 days before expiry).")
		return 0
	case "cleanup-system":
		if !isRoot() {
			return sslCLIError(errNeedRoot, "cleanup-system")
		}
		removeSystemPieces(out)
		removeExposePieces(&cfg, out)
		return 0
	}
	fmt.Fprintln(os.Stderr, "loadinme: unknown ssl command:", sub)
	sslUsage()
	return 2
}

func sslCLIError(err error, cmd string) int {
	switch {
	case errors.Is(err, errCancelled):
		fmt.Println("Cancelled.")
		return 1
	case errors.Is(err, errNeedRoot):
		fmt.Fprintln(os.Stderr, "loadinme: this needs root (ports 80/443 / nginx / Apache / Caddy / systemd). Run it with sudo:")
		fmt.Fprintln(os.Stderr, "  sudo loadinme ssl "+strings.TrimSpace(cmd))
		return 1
	}
	fmt.Fprintln(os.Stderr, "loadinme: "+err.Error())
	return 1
}
