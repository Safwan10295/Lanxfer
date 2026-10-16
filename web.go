package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

//go:embed web/index.html
var indexHTML []byte

// serveUI starts the app's own page on loopback only and returns its URL.
func serveUI(ctx context.Context, port int, hub *Hub, s *Sender, quit, show func(), tsLogin func() string) (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("GET /icon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(iconPNG(64, true))
	})
	mux.HandleFunc("GET /qr.png", func(w http.ResponseWriter, r *http.Request) {
		hub.mu.Lock()
		url := hub.url
		if hub.remoteURL != "" {
			url = hub.remoteURL
		}
		hub.mu.Unlock()
		png, err := qrcode.Encode(url, qrcode.Medium, 480)
		if url == "" || err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		t := time.NewTicker(300 * time.Millisecond)
		defer t.Stop()
		for {
			fmt.Fprintf(w, "data: %s\n\n", hub.snapshot())
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
	mux.HandleFunc("POST /api/upload", s.handleUpload)
	mux.HandleFunc("POST /api/send", func(w http.ResponseWriter, r *http.Request) { s.handleSend(ctx, w, r) })
	mux.HandleFunc("POST /api/clear", s.handleClear)
	mux.HandleFunc("POST /api/tophone", func(w http.ResponseWriter, r *http.Request) {
		if s.offer() == 0 {
			http.Error(w, "everything here is already on the phone's list", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("POST /api/reveal", func(w http.ResponseWriter, r *http.Request) {
		// Only paths the app itself recorded can be shown, never one from the request.
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		hub.mu.Lock()
		dir := hub.dir
		hub.mu.Unlock()
		reveal(hub.pathOf(id), dir)
	})
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) { quit() })
	mux.HandleFunc("POST /api/show", func(w http.ResponseWriter, r *http.Request) { show() })
	mux.HandleFunc("POST /api/tslogin", func(w http.ResponseWriter, r *http.Request) {
		if u := tsLogin(); strings.HasPrefix(u, "https://") {
			openBrowser(u)
			return
		}
		http.Error(w, "the sign-in link isn't ready yet; try again in a few seconds", http.StatusServiceUnavailable)
	})

	// Only this machine's browser, on this page, may talk to the UI: reject
	// other Host headers (DNS rebinding) and cross-site requests.
	hosts := map[string]bool{ln.Addr().String(): true, fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port): true}
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); !hosts[r.Host] || (o != "" && o != "http://"+r.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
	// Keep the window's server up for as long as the app runs: if it ever
	// stops, say why and listen again rather than leaving a dead window.
	go func() {
		for {
			err := http.Serve(ln, guarded)
			if ctx.Err() != nil {
				return
			}
			logf("app window server stopped (%v); restarting", err)
			for {
				time.Sleep(time.Second)
				if ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
					break
				}
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	context.AfterFunc(ctx, func() { ln.Close() })
	return "http://" + ln.Addr().String(), nil
}

// handleUpload spools a file dropped in the browser to a temp file (browsers
// don't reveal the original path) and queues it, hashing as it arrives.
func (s *Sender) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !s.begin("") {
		http.Error(w, "a transfer is in progress", http.StatusConflict)
		return
	}
	defer s.hub.setBusy(false, "")
	name := safeName(r.URL.Query().Get("name"))
	f, err := os.CreateTemp(s.tmp, "spool-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fp := s.hub.add(name, max(r.ContentLength, 0), "loading")
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h, progWriter{fp}), r.Body)
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		s.hub.set(fp, "failed", "could not read file")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.enqueue(&sendFile{path: f.Name(), temp: true, prog: fp,
		info: fileInfo{Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}})
}

// begin claims the sender for one operation at a time.
func (s *Sender) begin(msg string) bool {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	if s.hub.busy {
		return false
	}
	s.hub.busy, s.hub.message = true, msg
	return true
}

func (s *Sender) handleSend(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct{ Peer, Code string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := digits(req.Code)
	addrs := s.lookup(strings.TrimSpace(req.Peer))
	switch {
	case len(code) != 6:
		http.Error(w, "enter the 6-digit code shown on the other computer", http.StatusBadRequest)
		return
	case addrs == nil:
		http.Error(w, "that computer was not found", http.StatusBadRequest)
		return
	case !s.begin("Sending to " + req.Peer + "…"):
		http.Error(w, "a transfer is in progress", http.StatusConflict)
		return
	}
	go func() {
		err := s.send(ctx, addrs, code)
		if err != nil {
			logf("send failed: %v", err)
			s.hub.setBusy(false, "Failed: "+err.Error())
			return
		}
		s.hub.setBusy(false, "Sent to "+req.Peer+" and verified.")
	}()
}

// handleClear empties the send list (what=out) or the received list (what=in).
func (s *Sender) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("what") == "in" {
		s.hub.clear(true)
		return
	}
	if !s.begin("") {
		http.Error(w, "a transfer is in progress", http.StatusConflict)
		return
	}
	s.clear()
	s.hub.setBusy(false, "")
}

func digits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// reveal shows a received file in the file manager, or just the folder.
func reveal(path, dir string) {
	switch {
	case runtime.GOOS == "windows" && path != "":
		exec.Command("explorer.exe", "/select,"+path).Start()
	case runtime.GOOS == "windows":
		exec.Command("explorer.exe", dir).Start()
	case runtime.GOOS == "darwin" && path != "":
		exec.Command("open", "-R", path).Start()
	case runtime.GOOS == "darwin":
		exec.Command("open", dir).Start()
	default:
		exec.Command("xdg-open", dir).Start()
	}
}

// openApp shows the UI in its own window (no tabs or address bar) when Edge
// or Chrome is installed, and in the default browser otherwise.
func openApp(url string) {
	if runtime.GOOS == "windows" {
		for _, root := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LocalAppData")} {
			for _, exe := range []string{`Microsoft\Edge\Application\msedge.exe`, `Google\Chrome\Application\chrome.exe`} {
				p := filepath.Join(root, exe)
				if _, err := os.Stat(p); root != "" && err == nil {
					if exec.Command(p, "--app="+url, "--window-size=980,860").Start() == nil {
						return
					}
				}
			}
		}
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		return
	}
	if runtime.GOOS == "darwin" {
		exec.Command("open", url).Start()
		return
	}
	exec.Command("xdg-open", url).Start()
}

// openBrowser opens a link in the default browser.
func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}
