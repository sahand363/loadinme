package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DNS-01 through Cloudflare: for servers where port 80 cannot be used
// at all. The API token needs Zone → DNS → Edit for the domain's zone.
// It is saved in <data-dir>/acme/cloudflare.token (0600).

func cloudflareTokenPath(dataDir string) string {
	return filepath.Join(acmeDir(dataDir), "cloudflare.token")
}

func readCloudflareToken(dataDir string) string {
	if t := strings.TrimSpace(os.Getenv("LOADINME_CLOUDFLARE_TOKEN")); t != "" {
		return t
	}
	b, err := os.ReadFile(cloudflareTokenPath(dataDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveCloudflareToken(dataDir, token string) error {
	dir := acmeDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := cloudflareTokenPath(dataDir)
	if err := writeFileAtomic(p, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		return err
	}
	chownToApp(dataDir, dir, p)
	return nil
}

func cloudflareAPIBase() string {
	if b := os.Getenv("LOADINME_CLOUDFLARE_API"); b != "" {
		return strings.TrimRight(b, "/")
	}
	return "https://api.cloudflare.com/client/v4"
}

type cloudflareDNS struct {
	token  string
	base   string
	client *http.Client
	// resolver checks that the TXT record is visible before the CA
	// looks; "" = 1.1.1.1:53 (LOADINME_DNS_RESOLVER overrides).
	resolver string
	out      io.Writer
}

func newCloudflareDNS(token string, out io.Writer) *cloudflareDNS {
	r := os.Getenv("LOADINME_DNS_RESOLVER")
	if r == "" {
		r = "1.1.1.1:53"
	}
	return &cloudflareDNS{token: token, base: cloudflareAPIBase(), client: &http.Client{Timeout: 30 * time.Second}, resolver: r, out: out}
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cloudflareDNS) call(ctx context.Context, method, path string, body any, into any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r cfResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("Cloudflare API %s: %s", path, resp.Status)
	}
	if !r.Success {
		var msgs []string
		for _, e := range r.Errors {
			msgs = append(msgs, e.Message)
		}
		if len(msgs) == 0 {
			msgs = append(msgs, resp.Status)
		}
		return fmt.Errorf("Cloudflare: %s", strings.Join(msgs, "; "))
	}
	if into != nil {
		return json.Unmarshal(r.Result, into)
	}
	return nil
}

// Verify checks that the token is valid and active.
func (c *cloudflareDNS) Verify(ctx context.Context) error {
	var res struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, "GET", "/user/tokens/verify", nil, &res); err != nil {
		return err
	}
	if res.Status != "" && res.Status != "active" {
		return fmt.Errorf("Cloudflare says the token is %s", res.Status)
	}
	return nil
}

// findZone finds the Cloudflare zone that holds domain, trying
// files.example.com, then example.com, and so on.
func (c *cloudflareDNS) findZone(ctx context.Context, domain string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for i := 0; i+2 <= len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.call(ctx, "GET", "/zones?name="+name, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone found for %s (is the domain on this Cloudflare account, and may the token edit its DNS?)", domain)
}

// Present creates the TXT record, waits until a public resolver sees
// it, and returns a cleanup that deletes it again.
func (c *cloudflareDNS) Present(ctx context.Context, domain, value string) (func(), error) {
	zone, err := c.findZone(ctx, domain)
	if err != nil {
		return nil, err
	}
	name := "_acme-challenge." + domain
	var rec struct {
		ID string `json:"id"`
	}
	if err := c.call(ctx, "POST", "/zones/"+zone+"/dns_records",
		map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60}, &rec); err != nil {
		return nil, err
	}
	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = c.call(cctx, "DELETE", "/zones/"+zone+"/dns_records/"+rec.ID, nil, nil)
	}
	if c.out != nil {
		fmt.Fprintf(c.out, "Waiting until the record is visible in DNS (up to 2 minutes) …\n")
	}
	if !c.waitVisible(ctx, name, value, 2*time.Minute) && c.out != nil {
		fmt.Fprintf(c.out, "  (not visible at %s yet — asking the CA anyway)\n", c.resolver)
	}
	return cleanup, nil
}

func (c *cloudflareDNS) waitVisible(ctx context.Context, name, value string, max time.Duration) bool {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, c.resolver)
	}}
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		txts, _ := res.LookupTXT(lctx, name)
		cancel()
		for _, t := range txts {
			if t == value {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
	}
	return false
}
