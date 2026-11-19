//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// isRoot reports whether this process runs as root.
func isRoot() bool { return os.Geteuid() == 0 }

// fileOwner returns the uid/gid that own path.
func fileOwner(path string) (uid, gid int, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// setRunAs makes cmd run as uid/gid (used when the menu runs as root
// through sudo but the web UI must keep running as the real user).
func setRunAs(cmd *exec.Cmd, uid, gid int) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
}
