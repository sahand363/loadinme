package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

var (
	itemsBucket    = []byte("items")
	settingsBucket = []byte("settings")
	userBucket     = []byte("user")
	sessionBucket  = []byte("sessions")
)

// Item is one file or one text clip. Files and clips share one list
// for the max-items limit.
type Item struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"` // "file" or "clip"
	Name        string     `json:"name"`
	RelPath     string     `json:"relPath,omitempty"` // folder upload: path inside the folder
	Size        int64      `json:"size"`
	Mime        string     `json:"mime,omitempty"`
	Text        string     `json:"text,omitempty"` // clips only
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"` // nil = keep forever
	KeepForever bool       `json:"keepForever"`
}

// Settings are changeable from the web UI gear menu and persisted in bbolt.
type Settings struct {
	MaxItems           int `json:"maxItems"`
	MaxFileMB          int `json:"maxFileMB"`
	DefaultExpiryHours int `json:"defaultExpiryHours"`
}

func defaultSettings() Settings {
	return Settings{MaxItems: 200, MaxFileMB: 100, DefaultExpiryHours: 24}
}

// ValidateSettings checks the bounds the UI enforces.
func ValidateSettings(s Settings) error {
	if s.MaxItems < 1 || s.MaxItems > 10000 {
		return fmt.Errorf("maxItems must be 1-10000")
	}
	if s.MaxFileMB < 1 || s.MaxFileMB > 1024 {
		return fmt.Errorf("maxFileMB must be 1-1024")
	}
	if s.DefaultExpiryHours < 1 || s.DefaultExpiryHours > 720 {
		return fmt.Errorf("defaultExpiryHours must be 1-720")
	}
	return nil
}

// ExpiryFor returns the expiry time for a new item, or nil for keep-forever.
func ExpiryFor(createdAt time.Time, keepForever bool, expiryHours int) *time.Time {
	if keepForever {
		return nil
	}
	t := createdAt.Add(time.Duration(expiryHours) * time.Hour)
	return &t
}

// IsExpired reports whether the item's expiry time has passed.
// Keep-forever items never expire.
func (it *Item) IsExpired(now time.Time) bool {
	if it.KeepForever || it.ExpiresAt == nil {
		return false
	}
	return now.After(*it.ExpiresAt)
}

// Store wraps the bbolt database plus the on-disk upload directory.
type Store struct {
	db         *bbolt.DB
	dataDir    string
	uploadsDir string
}

func OpenStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "uploads"), 0o755); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(filepath.Join(dataDir, "loadinme.db"), 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dataDir: dataDir, uploadsDir: filepath.Join(dataDir, "uploads")}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{itemsBucket, settingsBucket, userBucket, sessionBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error       { return s.db.Close() }
func (s *Store) DataDir() string    { return s.dataDir }
func (s *Store) UploadsDir() string { return s.uploadsDir }

// uploadPath is the on-disk path for a file item. Files are stored by
// item ID only — never by the user-supplied name — so a crafted
// filename can never escape the uploads directory.
func (s *Store) uploadPath(id string) string {
	return filepath.Join(s.uploadsDir, sanitizeID(id))
}

func (s *Store) GetSettings() (Settings, error) {
	st := defaultSettings()
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(settingsBucket).Get([]byte("settings"))
		if b == nil {
			return nil
		}
		return json.Unmarshal(b, &st)
	})
	return st, err
}

func (s *Store) SaveSettings(st Settings) error {
	if err := ValidateSettings(st); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(settingsBucket).Put([]byte("settings"), b)
	})
}

func (s *Store) ListItems() ([]Item, error) {
	var items []Item
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(itemsBucket).ForEach(func(k, v []byte) error {
			var it Item
			if err := json.Unmarshal(v, &it); err != nil {
				return err
			}
			items = append(items, it)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items, nil
}

func (s *Store) CountItems() (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		n = tx.Bucket(itemsBucket).Stats().KeyN
		return nil
	})
	return n, err
}

func (s *Store) GetItem(id string) (*Item, error) {
	var it Item
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(itemsBucket).Get([]byte(sanitizeID(id)))
		if v == nil {
			return errNotFound
		}
		return json.Unmarshal(v, &it)
	})
	if err != nil {
		return nil, err
	}
	return &it, nil
}

var errNotFound = errors.New("not found")

func (s *Store) putItem(tx *bbolt.Tx, it Item) error {
	b, err := json.Marshal(it)
	if err != nil {
		return err
	}
	return tx.Bucket(itemsBucket).Put([]byte(it.ID), b)
}

func (s *Store) SaveItem(it Item) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return s.putItem(tx, it) })
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AddClip creates a text clip, enforcing the max-items limit.
func (s *Store) AddClip(text string, keepForever bool, st Settings) (*Item, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("clip text is empty")
	}
	if len(text) > 1024*1024 {
		return nil, fmt.Errorf("clip is too large (max 1 MB of text)")
	}
	now := time.Now().UTC()
	it := Item{
		ID: itID(), Kind: "clip", Name: clipName(text), Text: text,
		Size: int64(len(text)), CreatedAt: now,
		ExpiresAt: ExpiryFor(now, keepForever, st.DefaultExpiryHours), KeepForever: keepForever,
	}
	err := s.db.Update(func(tx *bbolt.Tx) error {
		if tx.Bucket(itemsBucket).Stats().KeyN >= st.MaxItems {
			return fmt.Errorf("item limit reached (%d items max — delete something or raise the limit in Settings)", st.MaxItems)
		}
		return s.putItem(tx, it)
	})
	if err != nil {
		return nil, err
	}
	return &it, nil
}

func itID() string { return newID() }

// clipName derives a short display name from the clip text.
func clipName(text string) string {
	first := strings.SplitN(text, "\n", 2)[0]
	first = strings.TrimSpace(first)
	if len(first) > 60 {
		first = first[:57] + "…"
	}
	if first == "" {
		return "clip"
	}
	return first
}

// DeleteItem removes an item and, for files, its bytes on disk.
func (s *Store) DeleteItem(id string) error {
	id = sanitizeID(id)
	var it Item
	err := s.db.Update(func(tx *bbolt.Tx) error {
		v := tx.Bucket(itemsBucket).Get([]byte(id))
		if v == nil {
			return errNotFound
		}
		if err := json.Unmarshal(v, &it); err != nil {
			return err
		}
		return tx.Bucket(itemsBucket).Delete([]byte(id))
	})
	if err != nil {
		return err
	}
	if it.Kind == "file" {
		_ = os.Remove(s.uploadPath(id))
	}
	return nil
}

// SweepExpired deletes expired items (files from disk + DB, clips from DB).
// It runs in the background every 60s while the server is up.
func (s *Store) SweepExpired(now time.Time) (int, error) {
	items, err := s.ListItems()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if it.IsExpired(now) {
			if err := s.DeleteItem(it.ID); err == nil {
				n++
			}
		}
	}
	return n, nil
}

func (s *Store) StartSweeper(stop <-chan struct{}) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			if n, err := s.SweepExpired(now); err == nil && n > 0 {
				fmt.Printf("loadinme: expired %d item(s)\n", n)
			}
		}
	}
}

// --- users & sessions (auth.go uses these) ---

func (s *Store) HasUser() (bool, error) {
	has := false
	err := s.db.View(func(tx *bbolt.Tx) error {
		has = tx.Bucket(userBucket).Get([]byte("username")) != nil
		return nil
	})
	return has, err
}

func (s *Store) SetUser(username string, hash []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(userBucket)
		if err := b.Put([]byte("username"), []byte(username)); err != nil {
			return err
		}
		return b.Put([]byte("passwordHash"), hash)
	})
}

func (s *Store) GetUser() (string, []byte, error) {
	var name string
	var hash []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(userBucket)
		name = string(b.Get([]byte("username")))
		hash = append([]byte(nil), b.Get([]byte("passwordHash"))...)
		return nil
	})
	return name, hash, err
}

func (s *Store) CreateSession(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	err := s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(sessionBucket).Put([]byte(token), []byte(username))
	})
	return token, err
}

func (s *Store) SessionUser(token string) (string, bool) {
	var name string
	_ = s.db.View(func(tx *bbolt.Tx) error {
		name = string(tx.Bucket(sessionBucket).Get([]byte(token)))
		return nil
	})
	return name, name != ""
}

func (s *Store) DeleteSession(token string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(sessionBucket).Delete([]byte(token))
	})
}

// ClearSessions deletes ALL login sessions, logging out every browser
// and device. Called whenever the password is reset or changed, so
// the new password is required everywhere (a reset must not leave
// an already-logged-in browser logged in).
func (s *Store) ClearSessions() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(sessionBucket)
		return b.ForEach(func(k, _ []byte) error { return b.Delete(k) })
	})
}

// --- filename safety ---

// sanitizeID keeps only [a-z0-9_-] (lowercase hex ids); anything else
// becomes empty, so a crafted id can never be a path.
func sanitizeID(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeFilename strips directories and dangerous characters from an
// uploaded filename, for display and for Content-Disposition only.
// Files are stored by ID on disk, so this is defence in depth.
func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\x00", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "file"
	}
	return name
}
