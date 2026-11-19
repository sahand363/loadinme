package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Built-in ACME client (Let's Encrypt). No certbot: LoadInMe gets its
// own certificate, keeps it in its own data directory (readable by the
// user it runs as), and renews it with `loadinme ssl renew`.
//
// Layout:
//   <data-dir>/acme/account.key            ACME account key (ECDSA P-256, 0600)
//   <data-dir>/acme/cloudflare.token       Cloudflare API token for DNS-01 (0600, optional)
//   <data-dir>/certs/<domain>/fullchain.pem certificate + chain (0600)
//   <data-dir>/certs/<domain>/privkey.pem   private key, ECDSA P-256 (0600)
//   <data-dir>/certs/<domain>/renewal.json  how it was issued (method, email, CA)

// letsEncryptProduction is the default ACME directory.
const letsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"

// acmeDirectoryURL is Let's Encrypt production unless LOADINME_ACME_DIR
// points somewhere else (a test CA such as Pebble, or LE staging).
func acmeDirectoryURL() string {
	if d := strings.TrimSpace(os.Getenv("LOADINME_ACME_DIR")); d != "" {
		return d
	}
	return letsEncryptProduction
}

// acmeHTTPClient trusts the system roots, plus the PEM file in
// LOADINME_ACME_CA_FILE when set (a test CA's own HTTPS certificate).
func acmeHTTPClient() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if f := os.Getenv("LOADINME_ACME_CA_FILE"); f != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("LOADINME_ACME_CA_FILE: %w", err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("LOADINME_ACME_CA_FILE: no PEM certificates in %s", f)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

func acmeDir(dataDir string) string { return filepath.Join(dataDir, "acme") }

func certDir(dataDir, domain string) string {
	return filepath.Join(dataDir, "certs", strings.ToLower(domain))
}

func certPaths(dataDir, domain string) (cert, key string) {
	d := certDir(dataDir, domain)
	return filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem")
}

// writeFileAtomic writes data to a temp file next to path and renames
// it into place, so a reader (the web UI's certificate reloader) never
// sees a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func marshalECKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// loadOrCreateAccountKey returns the ACME account key, creating it on
// first use.
func loadOrCreateAccountKey(dataDir string) (*ecdsa.PrivateKey, error) {
	dir := acmeDir(dataDir)
	path := filepath.Join(dir, "account.key")
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s is not a PEM key", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBytes, err := marshalECKey(k)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	chownToApp(dataDir, dir, path)
	return k, nil
}

// saveCertFiles stores a certificate and its key (0600, owned by the
// user LoadInMe runs as). The key is written first, then the
// certificate, each atomically.
func saveCertFiles(dataDir, domain string, certPEM, keyPEM []byte) (certPath, keyPath string, err error) {
	dir := certDir(dataDir, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	certPath, keyPath = certPaths(dataDir, domain)
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	chownToApp(dataDir, filepath.Join(dataDir, "certs"), dir, keyPath, certPath)
	return certPath, keyPath, nil
}

// --- HTTP-01: the small challenge server ---

// challengeServer answers /.well-known/acme-challenge/<token> with the
// key authorization, and 404 for everything else. It runs only while a
// certificate is being issued: on :80 itself (standalone), or on a
// loopback port that nginx forwards to.
type challengeServer struct {
	mu     sync.Mutex
	tokens map[string]string
	ln     net.Listener
	srv    *http.Server
}

func startChallengeServer(addr string) (*challengeServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cs := &challengeServer{tokens: map[string]string{}, ln: ln}
	cs.srv = &http.Server{Handler: cs, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = cs.srv.Serve(ln) }()
	return cs, nil
}

func (cs *challengeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	cs.mu.Lock()
	ka, ok := cs.tokens[token]
	cs.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, ka)
}

func (cs *challengeServer) set(token, keyAuth string) {
	cs.mu.Lock()
	cs.tokens[token] = keyAuth
	cs.mu.Unlock()
}

func (cs *challengeServer) port() int { return cs.ln.Addr().(*net.TCPAddr).Port }

func (cs *challengeServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = cs.srv.Shutdown(ctx)
}

// selfCheckHTTP01 fetches the challenge the way Let's Encrypt will
// (http://<domain>/.well-known/acme-challenge/<token>, but sent to
// this machine's port 80), so a broken setup is caught here instead of
// counting as a failed validation at Let's Encrypt.
func selfCheckHTTP01(domain, token, keyAuth string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var lastErr error
	answered := false
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:80/.well-known/acme-challenge/"+token, nil)
		req.Host = domain
		resp, err := client.Do(req)
		if err == nil {
			answered = true
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.TrimSpace(string(body)) == keyAuth {
				return nil
			}
			lastErr = fmt.Errorf("port 80 answered %s instead of the challenge", resp.Status)
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				lastErr = fmt.Errorf("port 80 redirects the challenge to %s (a redirect for the whole site catches it first)", resp.Header.Get("Location"))
			}
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !answered {
		// Nothing answers on 127.0.0.1:80 (e.g. nginx listens on the
		// public IP only): we cannot double-check from here, which
		// does not mean the outside check will fail.
		return errSelfCheckUnreachable
	}
	return lastErr
}

var errSelfCheckUnreachable = errors.New("port 80 does not answer on 127.0.0.1, so the challenge could not be double-checked locally")

// --- DNS-01 ---

// dnsSolver publishes and removes the _acme-challenge TXT record.
type dnsSolver interface {
	Present(ctx context.Context, domain, value string) (cleanup func(), err error)
}

// --- issuance ---

type issueOptions struct {
	DataDir string
	Domain  string
	Email   string
	// Exactly one of HTTP / DNS is set.
	HTTP      *challengeServer
	SelfCheck bool // run selfCheckHTTP01 before telling the CA to validate
	DNS       dnsSolver
	Out       io.Writer
}

// issued is a freshly issued certificate.
type issued struct {
	CertPEM, KeyPEM []byte
	NotAfter        time.Time
	Issuer          string
}

func (o issueOptions) logf(format string, a ...any) {
	if o.Out != nil {
		fmt.Fprintf(o.Out, format+"\n", a...)
	}
}

// explainACMEError turns an ACME error into one plain sentence.
func explainACMEError(err error) string {
	var ae *acme.AuthorizationError
	if errors.As(err, &ae) {
		var parts []string
		for _, e := range ae.Errors {
			var pe *acme.Error
			if errors.As(e, &pe) && pe.Detail != "" {
				parts = append(parts, pe.Detail)
			} else {
				parts = append(parts, e.Error())
			}
		}
		if len(parts) > 0 {
			return "the CA could not verify the domain: " + strings.Join(parts, "; ")
		}
	}
	var pe *acme.Error
	if errors.As(err, &pe) && pe.Detail != "" {
		return pe.Detail
	}
	return err.Error()
}

// obtainCertificate runs one ACME order for opts.Domain and returns
// the certificate. The caller has already set up the challenge path
// (challenge server, nginx snippet, stopped service, or DNS provider).
func obtainCertificate(ctx context.Context, opts issueOptions) (*issued, error) {
	key, err := loadOrCreateAccountKey(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	hc, err := acmeHTTPClient()
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: acmeDirectoryURL(), HTTPClient: hc, UserAgent: "loadinme/" + version}
	acct := &acme.Account{}
	if opts.Email != "" {
		acct.Contact = []string{"mailto:" + opts.Email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("could not register with the CA: %s", explainACMEError(err))
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(opts.Domain))
	if err != nil {
		return nil, fmt.Errorf("the CA refused the order: %s", explainACMEError(err))
	}
	// Keep the order URL from the creation response: later responses
	// (polling, finalize) do not always repeat it in a Location header.
	orderURL := order.URI
	for _, zurl := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, zurl)
		if err != nil {
			return nil, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		want := "http-01"
		if opts.DNS != nil {
			want = "dns-01"
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == want {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("the CA offered no %s challenge for %s", want, opts.Domain)
		}
		var cleanup func()
		if opts.DNS != nil {
			val, err := client.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				return nil, err
			}
			opts.logf("Publishing the DNS record _acme-challenge.%s …", opts.Domain)
			cleanup, err = opts.DNS.Present(ctx, opts.Domain, val)
			if err != nil {
				return nil, fmt.Errorf("could not publish the DNS record: %w", err)
			}
		} else {
			ka, err := client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return nil, err
			}
			opts.HTTP.set(chal.Token, ka)
			if opts.SelfCheck {
				opts.logf("Checking that http://%s/.well-known/acme-challenge/ reaches LoadInMe on this server …", opts.Domain)
				if err := selfCheckHTTP01(opts.Domain, chal.Token, ka); errors.Is(err, errSelfCheckUnreachable) {
					opts.logf("  (%v — going ahead)", err)
				} else if err != nil {
					return nil, fmt.Errorf("self-check failed before asking Let's Encrypt: %v", err)
				} else {
					opts.logf("  ✓ the challenge answers on port 80")
				}
			}
		}
		opts.logf("Asking the CA to check the domain …")
		if _, err := client.Accept(ctx, chal); err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, fmt.Errorf("could not start validation: %s", explainACMEError(err))
		}
		_, werr := client.WaitAuthorization(ctx, z.URI)
		if cleanup != nil {
			cleanup()
		}
		if werr != nil {
			return nil, errors.New(explainACMEError(werr))
		}
		opts.logf("  ✓ domain verified")
	}
	order, err = client.WaitOrder(ctx, orderURL)
	if err != nil {
		return nil, fmt.Errorf("order not ready: %s", explainACMEError(err))
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: opts.Domain},
		DNSNames: []string{opts.Domain},
	}, certKey)
	if err != nil {
		return nil, err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil && orderURL != "" {
		// A CA that finalizes asynchronously ("processing") without
		// a Location header on the finalize response makes
		// CreateOrderCert poll an empty URL. Poll the order we know
		// instead and fetch the certificate once it is valid.
		if o, werr := client.WaitOrder(ctx, orderURL); werr == nil && o.Status == acme.StatusValid && o.CertURL != "" {
			der, err = client.FetchCert(ctx, o.CertURL, true)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("could not finalize the certificate: %s", explainACMEError(err))
	}
	var certPEM []byte
	for _, d := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	keyPEM, err := marshalECKey(certKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, err
	}
	return &issued{CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: leaf.NotAfter, Issuer: issuerName(leaf)}, nil
}

func issuerName(c *x509.Certificate) string {
	name := c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		if name != "" {
			return c.Issuer.Organization[0] + " (" + name + ")"
		}
		return c.Issuer.Organization[0]
	}
	return name
}

// readLeaf parses the first certificate in a PEM file.
func readLeaf(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
