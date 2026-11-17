# LoadInMe ⬆

A small Go app for sharing files and text from your own VPS. One web page,
two panels: **files on the left** (Windows Explorer style) and a
**clipboard on the right**. Everything expires after 24 hours unless you
keep it forever, and anything can be deleted by hand. A login page
protects the whole thing.

- **Files** — drag & drop files or a whole folder, or click Upload. Each
  file shows a progress bar with %. Click a file to download it.
- **Clipboard** — press Ctrl+V anywhere on the page to save a clip, or
  type in the box and click Add. Copy and Delete buttons on every clip.
- **Expiry** — files and clips expire after 24 hours by default, unless
  "Keep forever" is ticked. A background sweeper deletes expired items
  every 60 seconds (files from disk too).
- **Limits** — max 200 items in total, max 100 MB per file. Change both,
  plus the default expiry, in Settings (gear ⚙️ on top).
- **Login** — first run shows a setup page to create your username and
  password. Change it later in Settings or from the SSH menu.
- **Light** — one static Go binary, no database server. Metadata lives in
  a small embedded database (`~/.loadinme/loadinme.db`), files in
  `~/.loadinme/uploads/`. Fits a 1 GB RAM server easily.

## Install (Ubuntu server, one line)

```
curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash
```

No Go, no clone, no compile on the server — GitHub Actions builds the
binary and the installer just downloads it. The installer then starts
the web UI by itself (default port 8080) and opens the SSH menu, with
the web UI link right on top. Open the link in your browser and create
your login on the setup page — no terminal setup needed after that.

If there is no terminal (a scripted install), the installer starts the
web UI in the background, prints the address, and exits; run
`loadinme menu` later to open the menu. `LOADINME_NO_MENU=1` skips the
menu, `LOADINME_NO_WEB=1` skips starting the web UI.

Specific version: `curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash -s -- --version v0.2.0`

## SSH menu

Run `loadinme menu`. The web UI link is printed first, then:

| # | Action |
|---|--------|
| 1 | Start web UI |
| 2 | Stop web UI |
| 3 | Restart web UI |
| 4 | Status (address, port, limits, item count) |
| 5 | Change port |
| 6 | Set domain |
| 7 | SSL with Let's Encrypt (needs a domain + certbot) |
| 8 | Update LoadInMe (downloads the latest release binary) |
| 9 | Change username / password |
| 10 | View settings |
| 11 | Show web UI link |
| 12 | Uninstall (asks whether to keep your data) |
| 0 | Exit |

The menu uses a systemd user service (`loadinme.service`) when
systemctl is available, and falls back to a background process with a
PID file otherwise.

## Commands

```
loadinme serve [--port 8080] [--data-dir ~/.loadinme]
loadinme start [--port 8080] [--data-dir ~/.loadinme]
loadinme stop [--data-dir ~/.loadinme]
loadinme menu
loadinme set-password [username]
loadinme version
loadinme --help
```

`start` starts the web UI in the background and waits until it answers
`/health` (it does nothing if the UI is already running); `stop` stops
it. The menu no longer holds the database open while the UI runs — in
v0.1.0 the menu's open database made the daemon fail to start with
"could not open data store: timeout" while the menu still printed
"Web UI started".

Environment: `LOADINME_PORT`, `LOADINME_DATA`.

## Settings (defaults)

| Setting | Default | Range |
|---|---|---|
| Max items (files + clips) | 200 | 1–10000 |
| Max file size | 100 MB | 1–1024 MB |
| Default expiry | 24 hours | 1–720 hours |

Change them from the gear menu in the web UI (saved in the database),
or view them from the SSH menu (option 10).

## Data layout

```
~/.loadinme/
  config.json     # port, domain, SSL
  loadinme.db     # items, clips, settings, users, sessions
  uploads/        # uploaded files, stored by item ID
```

## Build from source

```
go vet ./...
go test ./...
go build -o loadinme .
```

Requires Go 1.23. Releases are built by GitHub Actions on every `v*`
tag (linux amd64 + arm64, windows amd64).
