package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "loadinme_session"

// hashPassword hashes a password with bcrypt (cost 10: fast enough on
// a 1 GB server, still strong).
func hashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

func verifyPassword(hash []byte, pw string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}

// requireAuth is middleware: everything except /login, /setup,
// /health and the static login assets needs a valid session cookie.
func (s *Store) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.currentUser(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "unauthorized — please log in", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (s *Store) currentUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	return s.SessionUser(c.Value)
}

// setSessionCookie sets the login cookie. With HTTPS on, the cookie
// is marked Secure, so a browser never sends it over plain http.
func (s *Store) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: requestIsHTTPS(r),
		MaxAge: 30 * 24 * 60 * 60, // 30 days
	})
}

func (s *Store) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
		Secure: requestIsHTTPS(r),
	})
}

// errCancelled is returned when the user types exactly "0" at a
// prompt. In the menu it means "cancel this step" (or exit), never a
// value — "0" must never become a username, password, port or domain.
var errCancelled = errors.New("cancelled")

// setPasswordCLI implements `loadinme set-password [username]` and its
// alias `loadinme reset-password [username]`. It reads the password
// from stdin (twice, must match) and stores the bcrypt hash. It never
// asks for the current/old password: a reset must work when the old
// password is forgotten. On success it clears every login session, so
// all browsers/devices are logged out and the new password is required.
// Pass scanner=nil to read from os.Stdin (CLI use); the menu passes its
// own scanner so input is not lost between two buffered readers.
func setPasswordCLI(store *Store, username string, scanner *bufio.Scanner) error {
	existing, _, _ := store.GetUser()
	if username == "" {
		username = existing
	}
	if scanner == nil {
		scanner = bufio.NewScanner(os.Stdin)
	}
	if username == "" {
		fmt.Print("Username (0 to cancel): ")
		if !scanner.Scan() {
			return fmt.Errorf("no username given")
		}
		username = strings.TrimSpace(scanner.Text())
		if username == "0" {
			return errCancelled
		}
		if username == "" {
			return fmt.Errorf("username cannot be empty")
		}
	} else {
		fmt.Println("Username:", username)
	}
	fmt.Print("New password (0 to cancel): ")
	if !scanner.Scan() {
		return fmt.Errorf("no password given")
	}
	pw := scanner.Text()
	if strings.TrimSpace(pw) == "0" {
		return errCancelled
	}
	if len(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	fmt.Print("Repeat password (0 to cancel): ")
	if !scanner.Scan() {
		return fmt.Errorf("no password given")
	}
	if strings.TrimSpace(scanner.Text()) == "0" {
		return errCancelled
	}
	if scanner.Text() != pw {
		return fmt.Errorf("passwords do not match")
	}
	hash, err := hashPassword(pw)
	if err != nil {
		return err
	}
	if err := store.SetUser(username, hash); err != nil {
		return err
	}
	// A login exists now, so the one-time setup code is no longer needed.
	removeSetupCode(store.DataDir())
	if err := store.ClearSessions(); err != nil {
		return fmt.Errorf("password set but could not log out old sessions: %w", err)
	}
	fmt.Printf("Password reset for user %q. All sessions were logged out — log in again with the new password.\n", username)
	return nil
}
