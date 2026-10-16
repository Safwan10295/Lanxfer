//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"fyne.io/systray"
	webview2 "github.com/jchv/go-webview2"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	user32                    = syscall.NewLazyDLL("user32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procShowWindow            = user32.NewProc("ShowWindow")
	procSetForegroundWindow   = user32.NewProc("SetForegroundWindow")
)

// hideWindow stops helper programs (tailscale, powershell) from flashing a
// console window.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// detachConsole drops the console window when lanxfer was started from a
// shortcut rather than from a terminal, and logs to a file instead.
func detachConsole() {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return // a terminal shares this console: keep printing there
	}
	st, err := os.Stdout.Stat()
	redirected := err == nil && st.Mode()&os.ModeCharDevice == 0
	procFreeConsole.Call()
	if redirected {
		return
	}
	if f, err := os.Create(filepath.Join(configDir(), "lanxfer.log")); err == nil {
		// The old console handles are gone and Windows will hand their
		// numbers to new files and sockets. Keep the old *os.File values
		// reachable so the garbage collector never "closes" those numbers.
		detachedStd = append(detachedStd, os.Stdout, os.Stderr)
		os.Stdout, os.Stderr = f, f
	}
}

var detachedStd []*os.File

// desktop is the app's native side: a tray icon that keeps lanxfer
// receiving in the background, and a window that shows the UI.
type desktop struct {
	url  string
	quit func()

	mu      sync.Mutex
	win     webview2.WebView
	opening bool
}

func newDesktop(url string, quit func()) *desktop { return &desktop{url: url, quit: quit} }

// show opens the window, or brings it to the front if it's already open.
func (d *desktop) show() {
	d.mu.Lock()
	if w := d.win; w != nil {
		d.mu.Unlock()
		w.Dispatch(func() {
			procShowWindow.Call(uintptr(w.Window()), 9) // SW_RESTORE
			procSetForegroundWindow.Call(uintptr(w.Window()))
			// If the window is stuck on an error page, load the app again.
			w.Eval(fmt.Sprintf("if (typeof render !== 'function') location.replace(%q)", d.url))
		})
		return
	}
	if d.opening {
		d.mu.Unlock()
		return
	}
	d.opening = true
	d.mu.Unlock()

	go func() {
		// A window belongs to the thread that made it; its message loop
		// has to run there too.
		runtime.LockOSThread()
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			DataPath:  filepath.Join(configDir(), "webview"),
			WindowOptions: webview2.WindowOptions{
				Title: "lanxfer", Width: 1000, Height: 900, IconId: 1, Center: true,
			},
		})
		d.mu.Lock()
		d.win, d.opening = w, false
		d.mu.Unlock()
		if w == nil {
			openApp(d.url) // no WebView2 runtime: fall back to a browser window
			return
		}
		w.Navigate(d.url)
		w.Run()
		d.mu.Lock()
		d.win = nil
		d.mu.Unlock()
		w.Destroy()
	}()
}

// startTray puts lanxfer in the notification area. Closing the window
// leaves it running there, so it keeps receiving.
func (d *desktop) startTray() {
	go func() {
		runtime.LockOSThread()
		systray.Run(func() {
			systray.SetIcon(iconICO())
			systray.SetTooltip("lanxfer")
			open := systray.AddMenuItem("Open lanxfer", "")
			auto := systray.AddMenuItemCheckbox("Start with Windows", "Run in the tray from sign-in so files can arrive any time", autostartEnabled())
			systray.AddSeparator()
			quit := systray.AddMenuItem("Quit lanxfer", "")
			systray.SetOnTapped(d.show)
			go func() {
				for {
					select {
					case <-open.ClickedCh:
						d.show()
					case <-auto.ClickedCh:
						if err := setAutostart(!auto.Checked()); err != nil {
							logf("start with Windows: %v", err)
						} else if auto.Checked() {
							auto.Uncheck()
						} else {
							auto.Check()
						}
					case <-quit.ClickedCh:
						d.quit()
						return
					}
				}
			}()
		}, nil)
	}()
}

func (d *desktop) close() {
	systray.Quit()
	d.mu.Lock()
	if d.win != nil {
		d.win.Terminate()
	}
	d.mu.Unlock()
}

func startupShortcut() string {
	return filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup\lanxfer.lnk`)
}

func autostartEnabled() bool {
	_, err := os.Stat(startupShortcut())
	return err == nil
}

// setAutostart adds or removes a sign-in shortcut that starts lanxfer in
// the tray without opening its window.
func setAutostart(on bool) error {
	if !on {
		return os.Remove(startupShortcut())
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return createShortcut(startupShortcut(), exe, "-no-window", filepath.Join(filepath.Dir(exe), "lanxfer.ico"))
}

// createShortcut writes a .lnk file through the Windows Script Host.
func createShortcut(lnk, target, args, icon string) error {
	const script = `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LX_LNK)
$s.TargetPath = $env:LX_TARGET
$s.Arguments = $env:LX_ARGS
$s.IconLocation = $env:LX_ICON
$s.WindowStyle = 7
$s.Description = 'Send files between this computer, phones and other computers'
$s.Save()`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "LX_LNK="+lnk, "LX_TARGET="+target, "LX_ARGS="+args, "LX_ICON="+icon)
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating %s: %v: %s", filepath.Base(lnk), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runInstall copies the program to a permanent place and adds Start menu
// and desktop shortcuts.
func runInstall() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "lanxfer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	exe, ico := filepath.Join(dir, "lanxfer.exe"), filepath.Join(dir, "lanxfer.ico")
	if !strings.EqualFold(self, exe) {
		b, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		if err := os.WriteFile(exe, b, 0o755); err != nil {
			return fmt.Errorf("%w (if lanxfer is running, quit it from its tray icon first)", err)
		}
	}
	if err := os.WriteFile(ico, iconICO(), 0o644); err != nil {
		return err
	}
	desktopDir, _ := os.UserHomeDir()
	if out, err := exec.Command("powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')").Output(); err == nil {
		desktopDir = strings.TrimSpace(string(out))
	} else {
		desktopDir = filepath.Join(desktopDir, "Desktop")
	}
	programs := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs`)
	var errs []error
	for _, d := range []string{desktopDir, programs} {
		errs = append(errs, createShortcut(filepath.Join(d, "lanxfer.lnk"), exe, "", ico))
	}
	if autostartEnabled() { // point an existing sign-in shortcut at the new copy
		errs = append(errs, createShortcut(startupShortcut(), exe, "-no-window", ico))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Printf("Installed to %s\nShortcuts named \"lanxfer\" are on the desktop and in the Start menu.\n", exe)
	return nil
}
