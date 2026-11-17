package main

import (
	"bufio"
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

func (s *Store) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: 30 * 24 * 60 * 60, // 30 days
	})
}

func (s *Store) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// setPasswordCLI implements `loadinme set-password [username]`.
// It reads the password from stdin (twice, must match) and stores
// the bcrypt hash. Used on first install and from the SSH menu.
func setPasswordCLI(store *Store, username string) error {
	existing, _, _ := store.GetUser()
	if username == "" {
		username = existing
	}
	scanner := bufio.NewScanner(os.Stdin)
	if username == "" {
		fmt.Print("Username: ")
		if !scanner.Scan() {
			return fmt.Errorf("no username given")
		}
		username = strings.TrimSpace(scanner.Text())
		if username == "" {
			return fmt.Errorf("username cannot be empty")
		}
	} else {
		fmt.Println("Username:", username)
	}
	fmt.Print("New password: ")
	if !scanner.Scan() {
		return fmt.Errorf("no password given")
	}
	pw := scanner.Text()
	if len(pw) < 4 {
		return fmt.Errorf("password must be at least 4 characters")
	}
	fmt.Print("Repeat password: ")
	if !scanner.Scan() {
		return fmt.Errorf("no password given")
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
	fmt.Printf("Password set for user %q.\n", username)
	return nil
}
