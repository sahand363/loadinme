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
  password (at least 8 characters). The setup page asks for a one-time
  setup code that only the server shows, so nobody else can claim a
  fresh install. Change the login later in Settings or from the SSH menu.
- **SSL** — LoadInMe gets its own Let's Encrypt certificate (no certbot),
  works next to nginx on port 80, and renews it by itself.
- **Light** — one static Go binary, no database server. Metadata lives in
  a small embedded database (`~/.loadinme/loadinme.db`), files in
  `~/.loadinme/uploads/`. Fits a 1 GB RAM server easily.

## v0.7.0

- **SSL rebuilt from scratch — no more certbot** — LoadInMe now gets
  its Let's Encrypt certificate itself (a built-in ACME client, ECDSA
  P-256 keys). The certificate lives in `~/.loadinme/certs/<domain>/`,
  readable only by you (0600) and owned by the user LoadInMe runs as —
  certbot kept it in `/etc/letsencrypt`, which LoadInMe often was not
  allowed to read.
- **Works next to nginx** — Let's Encrypt checks your domain over port
  80, which nginx usually holds. Get SSL now looks at who owns port 80
  and picks the right way by itself, and tells you which one and why:
  - port 80 is free → LoadInMe answers on port 80 itself for the few
    seconds of the check;
  - nginx owns port 80 → LoadInMe adds a tiny temporary nginx config
    for your domain that forwards only `/.well-known/acme-challenge/`
    to LoadInMe, reloads nginx (no downtime), and removes it right
    after — also when something fails. If nginx already has a server
    block for that domain, the menu prints the one line to add to it
    (`location /.well-known/acme-challenge/ { proxy_pass http://127.0.0.1:41580; }`),
    or offers to pause nginx for a few seconds instead;
  - something else owns port 80 → it names the service, asks first,
    stops it for the few seconds of the check and always starts it
    again;
  - port 80 can't be used at all → choose DNS with a Cloudflare API
    token (saved in `~/.loadinme/acme/`, readable only by you).
  Before asking Let's Encrypt, it checks that the domain points at
  this server and says so plainly if it doesn't (a Cloudflare
  orange-cloud proxy is fine).
- **Renewals that actually happen** — `loadinme ssl renew` renews 30
  days before expiry with the same method, and Get SSL sets up a
  `loadinme-renew.timer` that runs it twice a day. The web UI picks up
  a renewed certificate by itself within a minute — no restart.
- **Domain & SSL menu (6) rebuilt** — 1 Get SSL (domain → email → the
  check is picked for you → certificate → HTTPS on → web UI
  restarted), 2 SSL status (domain, issuer, expiry, method, is the
  renewal timer on?), 3 Renew now, 4 Turn SSL off / remove
  certificate, 5 Clear saved domain. The steps that need root ask sudo
  for just that step, or run the whole menu with `sudo loadinme menu`
  (it still uses your own `~/.loadinme` and keeps the web UI running
  as you). New commands: `loadinme ssl issue|renew|status|off`.
- **Old certbot setups keep working** — a config that points to
  `/etc/letsencrypt` still serves HTTPS; the menu suggests re-issuing
  with 6 → 1 so renewals work.
- **Safer login** — a fresh install can no longer be claimed by
  whoever opens `/setup` first: the setup page asks for a one-time
  setup code that the server prints (installer output, top of
  `loadinme menu`, `~/.loadinme/setup-code`). After 5 wrong logins
  from one address, that address waits 1 minute, then 2, 4, … up to 30
  minutes. New passwords need at least 8 characters (existing ones
  keep working). The login cookie is marked Secure when HTTPS is on.
  Uploads are cut off at the max file size (plus a little room) before
  they are read, so an oversized upload can't fill the disk.
- **New home** — the project lives at
  [github.com/sahand363/loadinme](https://github.com/sahand363/loadinme);
  the installer, the menu's Update and the links all point there.

## v0.6.2

- **HTTPS links now carry your chosen port** — with SSL on and a port
  like 2343, the menu used to show `https://your-domain` with no port,
  which a browser opens on 443, where LoadInMe is not listening (it
  serves HTTPS on the port you chose). The link now shows
  `https://your-domain:2343` (and plain `https://your-domain` only
  when the port really is 443). The same fix applies to the address
  printed when the server starts.
- **Get SSL checks port 80 first** — certbot's standalone mode needs
  port 80 free for a few seconds to prove the domain is yours (a Let's
  Encrypt rule). On a server that already runs other websites port 80
  is usually taken, so certbot would only fail. The menu now checks
  first and, when port 80 is busy, says so plainly: certbot only needs
  port 80 for a few seconds, and freeing it that briefly is safe (the
  service just pauses and comes back — nothing breaks). It prints the
  exact steps — `sudo ss -tlnp | grep ':80'` to see what is using it,
  stop that service briefly, run Get SSL again, start it back — and
  restarts the web UI instead of running certbot. The app never stops
  the other service itself; that stays your call.
- **No more double-confirm after leaving a submenu** — pressing 0 to
  go back from Domain & SSL (or 0 to cancel changing the port) used to
  be followed by "Press Enter to return to the menu". That extra Enter
  is gone; the main menu comes back straight away. The pause stays
  after screens that print results worth reading (Status, settings,
  update, and so on).

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
curl -fsSL https://raw.githubusercontent.com/sahand363/loadinme/main/install.sh | bash
```

No Go, no clone, no compile on the server — GitHub Actions builds the
binary and the installer just downloads it. The installer then starts
the web UI by itself (default port 8080) and opens the SSH menu, with
the web UI link right on top. Open the link in your browser and create
your login on the setup page, using the setup code the installer prints
(it is also on top of `loadinme menu`) — no terminal setup needed after
that.

If there is no terminal (a scripted install), the installer starts the
web UI in the background, prints the address, and exits; run
`loadinme menu` later to open the menu. `LOADINME_NO_MENU=1` skips the
menu, `LOADINME_NO_WEB=1` skips starting the web UI.

Specific version: `curl -fsSL https://raw.githubusercontent.com/sahand363/loadinme/main/install.sh | bash -s -- --version v0.4.0`

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
| 6 | Domain & SSL (1 Get SSL, 2 SSL status, 3 Renew now, 4 Turn SSL off / remove certificate, 5 Clear saved domain) |
| 7 | Update LoadInMe (downloads the latest release binary, then restarts the web UI with it) |
| 8 | Reset / change username & password (no old password needed; logs out all browsers) |
| 9 | View settings |
| 10 | Show web UI link |
| 11 | Uninstall (asks whether to keep your data; removes the renewal timer) |
| 0 | Exit |

Pressing 0 exits the menu, and typing 0 at any question cancels that
step instead of becoming a value.

Until a login exists, the menu header also shows the one-time setup
code the setup page asks for.

## SSL (menu 6 → 1)

Point an A record for your domain at the server, then run
`loadinme menu` → 6 → 1 and enter the domain and an email. LoadInMe
picks how to prove the domain is yours (see v0.7.0 above), gets the
certificate, turns HTTPS on and restarts the web UI. The steps that
need root ask sudo for your password; `sudo loadinme menu` works too.
HTTPS keeps your chosen port (`https://your-domain:2343`).

Renewal is automatic: `loadinme-renew.timer` runs `loadinme ssl renew`
twice a day and renews 30 days before expiry; the web UI picks up the
new certificate within a minute. Check it any time with 6 → 2 or
`loadinme ssl status`.

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
loadinme ssl issue --domain DOMAIN --email EMAIL [--method auto] [--yes]
loadinme ssl renew [--force]
loadinme ssl status
loadinme ssl off [--remove]
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

`ssl issue` gets a certificate and turns HTTPS on (run it with sudo
for the HTTP methods); `--method` is `auto` (default), `standalone`,
`nginx`, `nginx-existing`, `stop-service` or `dns-cloudflare`. `ssl renew`
renews when fewer than 30 days are left (`--force`: now). `ssl off`
turns HTTPS off (`--remove` also deletes the certificate files).

Environment: `LOADINME_PORT`, `LOADINME_DATA`. For testing against
another ACME server: `LOADINME_ACME_DIR` (directory URL) and
`LOADINME_ACME_CA_FILE` (its CA certificate).

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
  setup-code      # one-time setup code (only until a login exists)
  acme/           # Let's Encrypt account key, Cloudflare token (0600)
  certs/<domain>/ # fullchain.pem, privkey.pem (0600), renewal.json
```

## Build from source

```
go vet ./...
go test ./...
go build -o loadinme .
```

Requires Go 1.23. Releases are built by GitHub Actions on every `v*`
tag (linux amd64 + arm64, windows amd64).
