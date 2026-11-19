package main

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- one-time setup code ---
//
// A fresh install has no login yet, so whoever opens /setup first
// would get to create it. To stop a stranger from claiming a new
// server, the setup page asks for a one-time code that only someone
// with shell access can see: the server writes it to
// <data-dir>/setup-code and prints it in the terminal, the installer
// output and the SSH menu header. The file is removed once a login
// exists.

const minPasswordLen = 8

// setupCodeAlphabet has no look-alike characters (no 0/O, 1/I/L).
const setupCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func setupCodePath(dataDir string) string { return filepath.Join(dataDir, "setup-code") }

func newSetupCode() (string, error) {
	// Rejection sampling keeps every character equally likely.
	limit := 256 - 256%len(setupCodeAlphabet)
	out := make([]byte, 0, 9)
	buf := make([]byte, 1)
	for len(out) < 9 {
		if len(out) == 4 {
			out = append(out, '-')
			continue
		}
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out = append(out, setupCodeAlphabet[int(buf[0])%len(setupCodeAlphabet)])
	}
	return string(out), nil
}

// readSetupCode returns the saved setup code, or "" when there is none.
func readSetupCode(dataDir string) string {
	b, err := os.ReadFile(setupCodePath(dataDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ensureSetupCode returns the saved setup code, creating one when
// there is none yet.
func ensureSetupCode(dataDir string) (string, error) {
	if c := readSetupCode(dataDir); c != "" {
		return c, nil
	}
	code, err := newSetupCode()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(setupCodePath(dataDir), []byte(code+"\n"), 0o600); err != nil {
		return "", err
	}
	chownToApp(dataDir, setupCodePath(dataDir))
	return code, nil
}

func removeSetupCode(dataDir string) { _ = os.Remove(setupCodePath(dataDir)) }

// normalizeSetupCode makes typing forgiving: case, spaces and dashes
// do not matter.
func normalizeSetupCode(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
}

func setupCodeMatches(want, got string) bool {
	w, g := normalizeSetupCode(want), normalizeSetupCode(got)
	if w == "" || g == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(w), []byte(g)) == 1
}

// --- login rate limit ---
//
// Per client IP: after 5 failed attempts the IP is locked out for a
// minute; every further lockout doubles the wait, up to 30 minutes.
// A successful login clears the IP's record.

const (
	loginMaxFailures = 5
	loginBaseLockout = time.Minute
	loginMaxLockout  = 30 * time.Minute
	loginForgetAfter = 24 * time.Hour
)

type loginRecord struct {
	failures    int
	lockouts    int
	lockedUntil time.Time
	lastSeen    time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	records map[string]*loginRecord
	now     func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{records: map[string]*loginRecord{}, now: time.Now}
}

// blocked reports whether ip is locked out right now, and for how long.
func (l *loginLimiter) blocked(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.records[ip]
	if r == nil {
		return 0, false
	}
	if wait := r.lockedUntil.Sub(l.now()); wait > 0 {
		return wait, true
	}
	return 0, false
}

// fail records a failed attempt and returns the lockout it started
// (0 when the IP is not locked yet).
func (l *loginLimiter) fail(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gc(now)
	r := l.records[ip]
	if r == nil {
		r = &loginRecord{}
		l.records[ip] = r
	}
	r.lastSeen = now
	r.failures++
	if r.failures < loginMaxFailures {
		return 0
	}
	wait := loginBaseLockout << r.lockouts
	if wait > loginMaxLockout || wait <= 0 {
		wait = loginMaxLockout
	}
	r.lockouts++
	r.failures = 0
	r.lockedUntil = now.Add(wait)
	return wait
}

func (l *loginLimiter) succeed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, ip)
}

// gc forgets IPs not seen for a day (and not locked), so the map
// cannot grow forever.
func (l *loginLimiter) gc(now time.Time) {
	if len(l.records) < 1000 {
		return
	}
	for ip, r := range l.records {
		if now.Sub(r.lastSeen) > loginForgetAfter && now.After(r.lockedUntil) {
			delete(l.records, ip)
		}
	}
}

// clientIP is the address the rate limit counts. X-Forwarded-For is
// only believed when the request comes from this machine (a reverse
// proxy such as nginx on loopback); anyone else could fake it. The
// right-most entry is the one the local proxy added.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if p := net.ParseIP(strings.TrimSpace(parts[i])); p != nil {
					return p.String()
				}
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}

// requestIsHTTPS reports whether the browser reached us over HTTPS:
// directly (TLS on) or through a local reverse proxy that says so.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}
