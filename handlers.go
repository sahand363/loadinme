package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const maxClipBytes = 1024 * 1024 // 1 MB of text per clip

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// --- pages ---

func (s *Store) handleLoginPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		has, _ := s.HasUser()
		if !has {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if _, ok := s.currentUser(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			username := strings.TrimSpace(r.FormValue("username"))
			password := r.FormValue("password")
			name, hash, _ := s.GetUser()
			if username != name || !verifyPassword(hash, password) {
				http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
				return
			}
			token, err := s.CreateSession(username)
			if err != nil {
				http.Error(w, "could not create session", http.StatusInternalServerError)
				return
			}
			s.setSessionCookie(w, token)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(loginHTML)
	}
}

func (s *Store) handleSetupPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		has, _ := s.HasUser()
		if has {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			username := strings.TrimSpace(r.FormValue("username"))
			password := r.FormValue("password")
			confirm := r.FormValue("confirm")
			if username == "" || len(password) < 4 || password != confirm {
				http.Redirect(w, r, "/setup?error=1", http.StatusSeeOther)
				return
			}
			hash, err := hashPassword(password)
			if err != nil {
				http.Error(w, "could not hash password", http.StatusInternalServerError)
				return
			}
			if err := s.SetUser(username, hash); err != nil {
				http.Error(w, "could not save user", http.StatusInternalServerError)
				return
			}
			token, err := s.CreateSession(username)
			if err != nil {
				http.Error(w, "could not create session", http.StatusInternalServerError)
				return
			}
			s.setSessionCookie(w, token)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(setupHTML)
	}
}

func (s *Store) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.DeleteSession(c.Value)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- API ---

func (s *Store) handleListItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Drop expired items on list, so the UI never shows stale ones.
	_, _ = s.SweepExpired(time.Now().UTC())
	items, err := s.ListItems()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleUpload accepts one file per request (the JS uploads each file
// separately so each gets its own progress bar). Fields: file,
// keepForever ("true"/"1"), relPath (folder uploads).
func (s *Store) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	st, err := s.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	keepForever := r.FormValue("keepForever") == "true" || r.FormValue("keepForever") == "1"
	relPath := sanitizeRelPath(r.FormValue("relPath"))

	// Cap the in-memory multipart parsing; the file body itself is
	// streamed below with a hard limit of maxFileMB+1.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload: "+err.Error())
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "no file in upload (field name must be 'file')")
		return
	}
	defer f.Close()

	maxBytes := int64(st.MaxFileMB) << 20
	// Reject obviously-too-big files early when the client told us.
	if hdr.Size > maxBytes {
		writeErr(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file is too large: %s exceeds the %d MB limit (change it in Settings)", hdr.Filename, st.MaxFileMB))
		return
	}
	name := sanitizeFilename(hdr.Filename)
	if relPath != "" {
		name = sanitizeFilename(filepath.Base(relPath))
	}

	now := time.Now().UTC()
	id := newID()
	tmpPath := s.uploadPath(id)
	out, err := os.Create(tmpPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Stream with a hard cap so a lying Content-Length can't fill the disk.
	written, copyErr := io.Copy(out, io.LimitReader(f, maxBytes+1))
	_ = out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		writeErr(w, http.StatusInternalServerError, "upload failed: "+copyErr.Error())
		return
	}
	if written > maxBytes {
		_ = os.Remove(tmpPath)
		writeErr(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file is too large: exceeds the %d MB limit (change it in Settings)", st.MaxFileMB))
		return
	}
	it := Item{
		ID: id, Kind: "file", Name: name, RelPath: relPath,
		Size: written, Mime: hdr.Header.Get("Content-Type"), CreatedAt: now,
		ExpiresAt: ExpiryFor(now, keepForever, st.DefaultExpiryHours), KeepForever: keepForever,
	}
	if err := s.dbUpdateWithLimitCheck(st, it); err != nil {
		_ = os.Remove(tmpPath)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"item": it})
}

func (s *Store) dbUpdateWithLimitCheck(st Settings, it Item) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if tx.Bucket(itemsBucket).Stats().KeyN >= st.MaxItems {
			return fmt.Errorf("item limit reached (%d items max — delete something or raise the limit in Settings)", st.MaxItems)
		}
		return s.putItem(tx, it)
	})
}

func (s *Store) handleCreateClip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Text        string `json:"text"`
		KeepForever bool   `json:"keepForever"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return
	}
	st, err := s.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	it, err := s.AddClip(req.Text, req.KeepForever, st)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"item": it})
}

func (s *Store) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/items/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || sanitizeID(id) == "" {
		writeErr(w, http.StatusBadRequest, "missing item id")
		return
	}
	if err := s.DeleteItem(id); err != nil {
		if err == errNotFound {
			writeErr(w, http.StatusNotFound, "item not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Store) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/f/")
	id = strings.SplitN(id, "/", 2)[0]
	it, err := s.GetItem(id)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if it.Kind != "file" {
		http.Error(w, "not a file", http.StatusNotFound)
		return
	}
	if it.IsExpired(time.Now().UTC()) {
		_ = s.DeleteItem(it.ID)
		http.Error(w, "file has expired", http.StatusGone)
		return
	}
	path := s.uploadPath(it.ID)
	fi, err := os.Stat(path)
	if err != nil {
		http.Error(w, "file not found on disk", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(it.Name, `"`, "_")+`"`)
	if it.Mime != "" {
		w.Header().Set("Content-Type", it.Mime)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	http.ServeFile(w, r, path)
}

func (s *Store) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	st, err := s.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	username, _, _ := s.GetUser()
	writeJSON(w, http.StatusOK, map[string]any{"settings": st, "username": username})
}

func (s *Store) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var st Settings
	if err := decodeJSON(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return
	}
	if err := s.SaveSettings(st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": st})
}

func (s *Store) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return
	}
	name, hash, _ := s.GetUser()
	if !verifyPassword(hash, req.CurrentPassword) {
		writeErr(w, http.StatusBadRequest, "current password is wrong")
		return
	}
	if len(req.NewPassword) < 4 {
		writeErr(w, http.StatusBadRequest, "new password must be at least 4 characters")
		return
	}
	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.SetUser(name, newHash); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sanitizeRelPath keeps a folder-upload relative path safe for display:
// no leading /, no ".." segments, forward slashes only.
func sanitizeRelPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.Trim(p, "/")
	parts := strings.Split(p, "/")
	var kept []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "/")
}
