package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"time"
)

//go:embed webui/index.html
var indexHTML []byte

//go:embed webui/login.html
var loginHTML []byte

//go:embed webui/setup.html
var setupHTML []byte

//go:embed webui/app.js
var appJS []byte

//go:embed webui/style.css
var styleCSS []byte

// newRouter builds the HTTP router. /health is public; /login and
// /setup are public pages; everything else needs a session.
func newRouter(store *Store, cfg Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/login", store.handleLoginPage(cfg))
	mux.HandleFunc("/setup", store.handleSetupPage(cfg))
	mux.HandleFunc("/logout", store.handleLogout)
	// The login/setup pages need the stylesheet before any session exists.
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(styleCSS)
	})

	// Static assets for the app (auth-protected: the JS only works
	// after login anyway, and this keeps the UI behind the login).
	app := http.NewServeMux()
	app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	app.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(appJS)
	})
	app.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(styleCSS)
	})
	app.HandleFunc("/api/items", store.handleListItems)
	app.HandleFunc("/api/upload", store.handleUpload)
	app.HandleFunc("/api/clips", store.handleCreateClip)
	app.HandleFunc("/api/items/", store.handleDeleteItem)
	app.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			store.handleGetSettings(w, r)
		case http.MethodPost, http.MethodPut:
			store.handleSaveSettings(w, r)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	app.HandleFunc("/api/change-password", store.handleChangePassword)
	app.HandleFunc("/f/", store.handleDownload)
	app.HandleFunc("/p/", store.handlePreview)
	mux.Handle("/", store.requireAuth(app))

	return mux
}

// serve starts the web server and the expiry sweeper. It blocks until
// the server stops.
func serve(store *Store, cfg Config) error {
	stop := make(chan struct{})
	defer close(stop)
	go store.StartSweeper(stop)

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      newRouter(store, cfg),
		ReadTimeout:  15 * time.Minute, // large uploads need a long read window
		WriteTimeout: 15 * time.Minute,
	}
	scheme := "http"
	if cfg.TLSEnabled && cfg.CertFile != "" && cfg.KeyFile != "" {
		scheme = "https"
		fmt.Printf("LoadInMe — Web UI: %s://%s\n", scheme, webAddressHost(cfg))
		fmt.Printf("Serving on :%d (HTTPS, %s)\n", cfg.Port, cfg.Domain)
		return srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	}
	fmt.Printf("LoadInMe — Web UI: http://%s\n", webAddressHost(cfg))
	fmt.Printf("Serving on :%d — open the address above in your browser (log in first)\n", cfg.Port)
	return srv.ListenAndServe()
}

func webAddressHost(cfg Config) string {
	if cfg.Domain != "" {
		if cfg.TLSEnabled {
			return cfg.Domain
		}
		if cfg.Port == 80 {
			return cfg.Domain
		}
		return fmt.Sprintf("%s:%d", cfg.Domain, cfg.Port)
	}
	if ip := outboundIP(); ip != "" {
		return fmt.Sprintf("%s:%d", ip, cfg.Port)
	}
	return fmt.Sprintf("localhost:%d", cfg.Port)
}
