package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// v0.8.1: the app icon is served without a session so the login page
// and the browser tab can show it.
func TestIconsArePublic(t *testing.T) {
	srv, _ := testAuthedServer(t, testStore(t))
	for path, ctype := range map[string]string{
		"/favicon.ico":          "image/x-icon",
		"/icon.png":             "image/png",
		"/apple-touch-icon.png": "image/png",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ctype || len(b) < 100 {
			t.Fatalf("%s: status %d type %q len %d", path, resp.StatusCode, resp.Header.Get("Content-Type"), len(b))
		}
	}
}

func TestPagesLinkIcon(t *testing.T) {
	for name, page := range map[string][]byte{"index": indexHTML, "login": loginHTML, "setup": setupHTML} {
		s := string(page)
		if !strings.Contains(s, `rel="icon"`) || !strings.Contains(s, `src="/icon.png"`) {
			t.Fatalf("%s.html does not use the app icon", name)
		}
	}
}
