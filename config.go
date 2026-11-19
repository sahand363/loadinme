package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Config is the server config, persisted in <data-dir>/config.json.
// Limits (max items, max file size, expiry) are Settings in the DB,
// not here, so they can be changed from the web UI.
type Config struct {
	Port       int    `json:"port"`
	DataDir    string `json:"dataDir"`
	Domain     string `json:"domain"`
	TLSEnabled bool   `json:"tlsEnabled"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	// BindAddress is the address the web UI listens on: "" means
	// every interface; "127.0.0.1" when a web server in front of
	// LoadInMe (nginx, Apache, Caddy) serves https://<domain>.
	BindAddress string `json:"bindAddress,omitempty"`
	// Expose is set when LoadInMe is reachable at https://<domain>
	// with no port (v0.8.0, menu 6 → 6 / loadinme ssl expose).
	Expose *ExposeInfo `json:"expose,omitempty"`
}

const defaultPort = 8080

func defaultDataDir() string {
	if d := os.Getenv("LOADINME_DATA"); d != "" {
		return d
	}
	home := appHome()
	if home == "" {
		return ".loadinme"
	}
	return filepath.Join(home, ".loadinme")
}

func defaultConfig(dataDir string) Config {
	port := defaultPort
	if p := os.Getenv("LOADINME_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			port = n
		}
	}
	return Config{Port: port, DataDir: dataDir}
}

func configPath(dataDir string) string { return filepath.Join(dataDir, "config.json") }

func loadConfig(dataDir string) (Config, error) {
	cfg := defaultConfig(dataDir)
	b, err := os.ReadFile(configPath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("bad config.json: %w", err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = dataDir
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		cfg.Port = defaultPort
	}
	return cfg, nil
}

func saveConfig(cfg Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath(cfg.DataDir), b, 0o644); err != nil {
		return err
	}
	chownToApp(cfg.DataDir, cfg.DataDir, configPath(cfg.DataDir))
	return nil
}
