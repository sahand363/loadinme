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
//	loadinme version
//	loadinme --help
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

const version = "0.1.0"

func usage() {
	fmt.Printf(`LoadInMe %s — file & text sharing for your VPS

Usage:
  loadinme serve [--port 8080] [--data-dir DIR]
  loadinme menu
  loadinme set-password [username]
  loadinme version
  loadinme --help

Flags for serve:
  --port      web port (default 8080, or LOADINME_PORT)
  --data-dir  data directory (default ~/.loadinme, or LOADINME_DATA)

The web UI shows two panels: files on the left (drag & drop, or
click Upload) and a clipboard on the right (Ctrl+V anywhere to save
a clip). Items expire after 24 hours unless kept forever; change the
limits in the web UI with the gear icon, or from the SSH menu.
`, version)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h", "help":
			usage()
			return
		case "--version", "-v", "version":
			fmt.Println("loadinme", version)
			return
		}
	}

	// Find the subcommand (serve is the default).
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "serve", "menu", "set-password", "version":
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
	cfg.DataDir = dataDir
	if *portFlag != 0 {
		cfg.Port = *portFlag
	} else if p := os.Getenv("LOADINME_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			cfg.Port = n
		}
	}
	if cmd == "version" {
		fmt.Println("loadinme", version)
		return
	}

	store, err := OpenStore(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadinme: could not open data store:", err)
		os.Exit(1)
	}
	defer store.Close()

	switch cmd {
	case "set-password":
		username := ""
		if fs.NArg() > 0 {
			username = fs.Arg(0)
		}
		if err := setPasswordCLI(store, username); err != nil {
			fmt.Fprintln(os.Stderr, "loadinme:", err)
			os.Exit(1)
		}
	case "menu":
		runMenu(&cfg, store)
	default: // serve
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "loadinme: could not save config:", err)
		}
		has, _ := store.HasUser()
		if !has {
			fmt.Println("No login user yet — open the web UI and create one on the setup page,")
			fmt.Println("or run: loadinme set-password")
		}
		if err := serve(store, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "loadinme:", err)
			os.Exit(1)
		}
	}
}
