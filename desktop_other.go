//go:build !windows

package main

import (
	"errors"
	"os/exec"
)

func hideWindow(*exec.Cmd) {}

func detachConsole() {}

// desktop falls back to the browser outside Windows.
type desktop struct{ url string }

func newDesktop(url string, quit func()) *desktop { return &desktop{url: url} }
func (d *desktop) show()                          { openApp(d.url) }
func (d *desktop) startTray()                     {}
func (d *desktop) close()                         {}

func runInstall() error {
	return errors.New("install is only implemented for Windows; elsewhere, put the binary on your PATH")
}
