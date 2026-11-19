//go:build windows

package main

import "os/exec"

func isRoot() bool { return false }

func fileOwner(path string) (uid, gid int, ok bool) { return 0, 0, false }

func setRunAs(cmd *exec.Cmd, uid, gid int) {}
