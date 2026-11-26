// LoadInMe — a small Go file/text sharing app for a VPS.
//
// Two panels in one web page: files on the left (Windows Explorer style)
// and a clipboard on the right. Everything expires after 24 hours by
// default unless you tick "Keep forever", and anything can be deleted
// by hand. Login protects the whole UI.
//
// Usage:
//
//	loadinme serve [--port 8080] [--data-dir ~/.loadinme]
//	loadinme menu            # SSH menu (web link on top)
//	loadinme set-password [username]
//	loadinme reset-password [username]   # alias of set-password
//	loadinme ssl issue|renew|status|off  # built-in Let's Encrypt (ACME)
//	loadinme ssl expose|unexpose         # https://<domain> with no port
//	loadinme version
//	loadinme --help
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
)

const version = "0.8.1"

func usage() {
	fmt.Printf(`LoadInMe %s — file & text sharing for your VPS

Usage:
  loadinme serve [--port 8080] [--data-dir DIR]
  loadinme start [--port 8080] [--data-dir DIR]
  loadinme stop [--data-dir DIR]
  loadinme menu
  loadinme set-password [username]
  loadinme reset-password [username]   # same as set-password: resets
         # the login without asking for the old password, and logs
         # out every browser/device
  loadinme ssl issue|renew|status|off [--data-dir DIR]   # see: loadinme ssl --help
  loadinme ssl expose|unexpose [--data-dir DIR]   # https://DOMAIN with no port
  loadinme version
  loadinme --help

  start  start the web UI in the background (waits until it answers
         /health) — this is what the installer runs for you
  stop   stop the background web UI

Flags:
  --port      web port (default 8080, or LOADINME_PORT)
  --data-dir  data directory (default ~/.loadinme, or LOADINME_DATA)

The web UI shows two panels: files on the left (drag & drop, or
click Upload) and a clipboard on the right (Ctrl+V anywhere to save
a clip). Items expire after 24 hours unless kept forever; change the
limits in the web UI with the gear icon, or from the SSH menu.
`, version)
}

func main() {
	// Tests point the old certbot directory at a temp dir.
	if d := os.Getenv("LOADINME_LETSENCRYPT_DIR"); d != "" {
		letsEncryptDir = d
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h", "help":
			usage()
			return
		case "--version", "-v", "version":
			fmt.Println("loadinme", version)
			return
		case "ssl":
			os.Exit(runSSLCLI(os.Args[2:]))
		}
	}

	// Find the subcommand (serve is the default).
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "serve", "start", "stop", "menu", "set-password", "reset-password", "version":
			cmd = args[0]
			args = args[1:]
		}
	}

	fs := flag.NewFlagSet("loadinme", flag.ExitOnError)
	fs.Usage = usage
	portFlag := fs.Int("port", 0, "web port")
	dataFlag := fs.String("data-dir", "", "data directory")
	_ = fs.Parse(args)

	dataDir := *dataFlag
	if dataDir == "" {
		dataDir = defaultDataDir()
	}
	cfg, err := loadConfig(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadinme: could not load config:", err)
		os.Exit(1)
	}
	// Whether a config file already exists: an override must never
	// clobber a saved port, but a first run with no config file yet
	// still has to persist the port the UI actually runs on — later
	// commands (menu, reset-password, restart) load the port from
	// this file, and without it they would restart the UI on the
	// 8080 default instead of the port it was running on.
	_, statErr := os.Stat(configPath(dataDir))
	configExists := statErr == nil
	cfg.DataDir = dataDir
	// A --port flag or LOADINME_PORT is a one-off override for this
	// run only: it must never be written back over an existing
	// saved config. The saved config is the source of truth for the
	// port — v0.4.0 clobbered it, because serve saved the config
	// after the override was applied, so an update that started the
	// UI on the 8080 default permanently overwrote the user's
	// saved 5234.
	portOverridden := false
	if *portFlag != 0 {
		cfg.Port = *portFlag
		portOverridden = true
	} else if p := os.Getenv("LOADINME_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			cfg.Port = n
			portOverridden = true
		}
	}
	if cmd == "version" {
		fmt.Println("loadinme", version)
		return
	}

	// The database is opened only by the commands that need it for a
	// long time (serve, set-password). The menu, start and stop must
	// NOT hold it open: bbolt takes an exclusive lock, so a menu or
	// start process holding the DB would make the web UI daemon fail
	// with "could not open data store: timeout" (v0.1.0 bug).
	// The menu opens the DB briefly, per option, via withStore.
	openStore := func() (*Store, error) { return OpenStore(dataDir) }

	switch cmd {
	case "set-password", "reset-password":
		username := ""
		if fs.NArg() > 0 {
			username = fs.Arg(0)
		}
		// Same lock problem as the menu: if the web UI is running,
		// stop it first, change the password, then restart it.
		err := withServiceStopped(cfg, func() error {
			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()
			return setPasswordCLI(store, username, nil)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "loadinme:", err)
			os.Exit(1)
		}
	case "menu":
		runMenu(&cfg)
	case "start":
		if err := startService(cfg); err != nil {
			if errors.Is(err, errAlreadyRunning) {
				fmt.Println("Web UI is already running at", webAddressFor(cfg))
				return
			}
			fmt.Fprintln(os.Stderr, "loadinme:", err)
			os.Exit(1)
		}
		fmt.Println("Web UI started at", webAddressFor(cfg))
	case "stop":
		if err := stopService(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "loadinme:", err)
			os.Exit(1)
		}
		fmt.Println("Web UI stopped.")
	default: // serve
		store, err := openStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "loadinme: could not open data store:", err)
			os.Exit(1)
		}
		defer store.Close()
		// Persist the config — except when the port came from a
		// one-off --port / LOADINME_PORT override AND a config file
		// already exists: saving then would make the one-off port
		// permanent and wipe the user's saved port (v0.5.0). With
		// no config file yet, always save, so the port the UI runs
		// on is recorded for later commands.
		if !portOverridden || !configExists {
			if err := saveConfig(cfg); err != nil {
				fmt.Fprintln(os.Stderr, "loadinme: could not save config:", err)
			}
		}
		has, _ := store.HasUser()
		if !has {
			code, err := ensureSetupCode(dataDir)
			fmt.Println("No login user yet — open the web UI and create one on the setup page,")
			if err == nil {
				fmt.Println("using this one-time setup code:", code)
			}
			fmt.Println("or run: loadinme set-password")
		} else {
			removeSetupCode(dataDir)
		}
		if err := serve(store, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "loadinme:", err)
			os.Exit(1)
		}
	}
}
