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

## v0.6.1

- **Certificates are matched by the domains they cover, not by folder
  name** — a certificate's folder under `/etc/letsencrypt/live/` can
  differ from the domain it covers (a multi-domain certificate, or a
  lineage named `example.com-0001`). The list in menu 6 → 2 now shows
  each certificate under the domains it actually covers, with its
  expiry date; Get SSL (6 → 1) finds a certificate that already
  covers the domain and offers to enable HTTPS with it instead of
  running certbot again (certbot used to ask, in red, whether to
  change that certificate's key type from ECDSA to RSA — that question
  was only ever about that one certificate, never about the others,
  but it should never have been asked at all); revoking by domain
  finds the right certificate the same way. When several certificates
  cover one domain, you pick one by number. New certificates are made
  with `--cert-name <domain>` so their folder is named after the
  domain from now on.
- **Clear saved domain (menu 6 → 3)** — the saved domain shown on top
  of the menu can now be cleared; if SSL was on for it, SSL is
  switched off too and the web UI restarts on plain `http://` when it
  was running.

## v0.6.0

- **Domain & SSL in one menu option** — getting SSL used to take two
  options (6 for the domain, then 7 for the email and the certificate).
  Option 6 is now "Domain & SSL" with a submenu: 1 Get SSL (enter the
  domain, then the email, and the certificate is fetched), 2 List
  certificates & revoke one (shows every certificate with its expiry
  date and which one is in use; type a domain to revoke it, with a
  confirmation question first). Turning SSL on restarts the web UI
  automatically when it was running, so `https://` serves right away;
  revoking the certificate in use turns SSL off and restarts the UI
  back on `http://`. Pressing 0 in the submenu goes back to the main
  menu, and 0 at any prompt cancels that step.
- **Menu renumbered** — with SSL folded into option 6, Update is now
  7, Reset / change password is 8, View settings is 9, Show web UI
  link is 10, and Uninstall is 11 (1–5 and 0 are unchanged).

## v0.5.0

- **Copy button fixed** — it did nothing over plain `http://<server-IP>` because `navigator.clipboard` only exists in secure contexts. It now falls back to the classic textarea + `execCommand('copy')` approach, shows 'Copied!' only on real success, and 'Copy failed' if copying really fails.
- **Updates no longer reset your port** — an update used to start the UI on the 8080 default and permanently overwrite the saved port (the user's 5234 was lost this way in v0.4.0). Two causes fixed: the installer now reads the saved port from `config.json` even without python3 (grep fallback), and a `--port` / `LOADINME_PORT` override is one-off — starting the UI with one never writes it back to `config.json` again.

## v0.4.0

- **Password reset from SSH, any time** — SSH menu option 8 is now
  "Reset / change username & password", and `loadinme reset-password`
  does the same from the command line. It never asks for the old
  password (a reset works even when the old one is forgotten), and it
  logs out every browser/device, so the new password is required
  everywhere.
- **0 always exits the SSH menu** — pressing 0 exits the menu (no
  farewell message), and typing 0 at any menu question cancels that
  step instead of becoming a value (it can never set the port to 0, the
  domain to "0", or the password to "0").
- **Always restart after an update** — after a quick install or a menu
  update (option 7), the web UI is stopped and started again with the
  new version, and the running version is printed, so updates always
  apply.

## v0.3.0

- **Image preview** — image files show a real thumbnail in the file list;
  click it for a full-size lightbox (Download + Close, Esc or click the
  backdrop to close). Other files keep their big type icon.
- **Bigger file icons** — 56×56 px tiles with a centred emoji.
- **Equal panels** — Files and Clipboard are the same width and height;
  each list scrolls inside its own panel.
- **Fancy panel colours** — indigo/blue header for Files, emerald/teal
  header for Clipboard, matching accents for their buttons.

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

Specific version: `curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash -s -- --version v0.4.0`

After installing or updating, the installer always restarts the web UI
with the new version (stopping the old process first if it was
running), so an update always applies. The menu's Update (option 7)
does the same.

## SSH menu

Run `loadinme menu`. The web UI link is printed first, then:

| # | Action |
|---|--------|
| 1 | Start web UI |
| 2 | Stop web UI |
| 3 | Restart web UI |
| 4 | Status (address, port, limits, item count) |
| 5 | Change port |
| 6 | Domain & SSL (1 Get SSL, 2 List certificates & revoke one, 3 Clear saved domain) |
| 7 | Update LoadInMe (downloads the latest release binary, then restarts the web UI with it) |
| 8 | Reset / change username & password (no old password needed; logs out all browsers) |
| 9 | View settings |
| 10 | Show web UI link |
| 11 | Uninstall (asks whether to keep your data) |
| 0 | Exit |

Pressing 0 exits the menu, and typing 0 at any question cancels that
step instead of becoming a value.

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
loadinme reset-password [username]
loadinme version
loadinme --help
```

`set-password` and `reset-password` are the same: they set a new
password without asking for the old one, and log out every
browser/device (all sessions are cleared). Use them any time, not
just on first setup — from the SSH menu (option 8) or the command line.

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
or view them from the SSH menu (option 9).

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
