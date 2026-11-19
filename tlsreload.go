package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// certReloader serves the certificate through tls.Config.GetCertificate
// and reloads it from disk when the files change, so a renewed
// certificate applies without restarting the web UI. The files are
// checked at most once per interval (a minute by default), and a
// broken or half-written pair never replaces a working certificate:
// the old one keeps serving and the next check tries again.
type certReloader struct {
	certFile, keyFile string
	interval          time.Duration
	now               func() time.Time

	mu        sync.Mutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	lastCheck time.Time
	lastErr   error
}

// defaultCertCheckInterval is how often the files are looked at.
// LOADINME_CERT_CHECK_INTERVAL (a Go duration, e.g. "2s") overrides it
// for tests.
func defaultCertCheckInterval() time.Duration {
	if v := os.Getenv("LOADINME_CERT_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Minute
}

// newCertReloader loads the certificate once (an error here means
// HTTPS cannot start at all) and returns the reloader.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, interval: defaultCertCheckInterval(), now: time.Now}
	if err := r.load(); err != nil {
		return nil, err
	}
	r.lastCheck = r.now()
	return r, nil
}

func modTime(path string) (time.Time, error) {
	fi, err := os.Stat(path) // follows symlinks (certbot's live/ links)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

func (r *certReloader) load() error {
	cm, err := modTime(r.certFile)
	if err != nil {
		return err
	}
	km, err := modTime(r.keyFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	if len(c.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = leaf
		}
	}
	r.cert = &c
	r.certMod, r.keyMod = cm, km
	r.lastErr = nil
	return nil
}

// maybeReload checks the files' modification times (at most once per
// interval) and loads them again when either changed.
func (r *certReloader) maybeReload() {
	now := r.now()
	if now.Sub(r.lastCheck) < r.interval {
		return
	}
	r.lastCheck = now
	cm, err1 := modTime(r.certFile)
	km, err2 := modTime(r.keyFile)
	if err1 != nil || err2 != nil {
		return // keep serving the certificate we have
	}
	if cm.Equal(r.certMod) && km.Equal(r.keyMod) {
		return
	}
	if err := r.load(); err != nil {
		r.lastErr = err
		fmt.Fprintln(os.Stderr, "loadinme: certificate changed on disk but could not be loaded yet (keeping the old one):", err)
		return
	}
	if r.cert.Leaf != nil {
		fmt.Printf("Loaded the renewed certificate for %v (valid until %s)\n", r.cert.Leaf.DNSNames, r.cert.Leaf.NotAfter.Format("2006-01-02"))
	}
}

// GetCertificate is the tls.Config hook.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maybeReload()
	return r.cert, nil
}
