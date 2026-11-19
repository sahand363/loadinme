package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
)

// LoadInMe runs as the user who installed it (a systemd *user*
// service from ~/.loadinme). Some SSL steps need root (binding port
// 80, writing an nginx snippet, installing the renewal timer), so
// they run through sudo. These helpers make sure that, even then,
// everything LoadInMe keeps (config, certificates, database) stays
// owned by the real user, and that the web UI keeps running as them.

// appUser is the real user behind a root process started with sudo.
type appUser struct {
	name     string
	uid, gid int
	home     string
}

// sudoInvoker returns the user who ran `sudo loadinme …`, when this
// process is root through sudo (and that user is not root itself).
func sudoInvoker() (appUser, bool) {
	if !isRoot() {
		return appUser{}, false
	}
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return appUser{}, false
	}
	u, err := user.Lookup(name)
	if err != nil {
		return appUser{}, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid == 0 {
		return appUser{}, false
	}
	return appUser{name: name, uid: uid, gid: gid, home: u.HomeDir}, true
}

// appHome is the home directory of the user LoadInMe runs as: the
// sudo invoker's when running as root through sudo (Ubuntu's sudo
// sets HOME=/root, which would point at the wrong ~/.loadinme).
func appHome() string {
	if u, ok := sudoInvoker(); ok && u.home != "" {
		return u.home
	}
	home, _ := os.UserHomeDir()
	return home
}

// appOwnerFor returns the uid/gid that should own files in dataDir:
// the sudo invoker when there is one, otherwise whoever owns the data
// directory (the renewal timer runs as root with no SUDO_USER).
func appOwnerFor(dataDir string) (uid, gid int, ok bool) {
	if u, ok := sudoInvoker(); ok {
		return u.uid, u.gid, true
	}
	if uid, gid, ok := fileOwner(dataDir); ok {
		return uid, gid, true
	}
	return fileOwner(filepath.Dir(dataDir))
}

// chownToApp gives paths back to the user LoadInMe runs as. It only
// does something when this process is root; otherwise the files are
// already ours.
func chownToApp(dataDir string, paths ...string) {
	if !isRoot() {
		return
	}
	uid, gid, ok := appOwnerFor(dataDir)
	if !ok || uid == 0 {
		return
	}
	for _, p := range paths {
		_ = os.Lchown(p, uid, gid)
	}
}

// userSystemctl builds `systemctl --user …` for the app user. As root
// through sudo it runs as the invoking user against their own user
// manager (otherwise it would talk to root's, which has no
// loadinme.service).
func userSystemctl(args ...string) *exec.Cmd {
	full := append([]string{"--user"}, args...)
	if u, ok := sudoInvoker(); ok {
		runtimeDir := "/run/user/" + strconv.Itoa(u.uid)
		cmd := exec.Command("systemctl", full...)
		cmd.Env = append(os.Environ(),
			"XDG_RUNTIME_DIR="+runtimeDir,
			"DBUS_SESSION_BUS_ADDRESS=unix:path="+runtimeDir+"/bus",
			"HOME="+u.home, "USER="+u.name, "LOGNAME="+u.name)
		setRunAs(cmd, u.uid, u.gid)
		return cmd
	}
	return exec.Command("systemctl", full...)
}
