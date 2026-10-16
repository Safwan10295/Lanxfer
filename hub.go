package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Hub holds the live state shown in the web UI and on the terminal.

type fileProg struct {
	done atomic.Int64

	// guarded by Hub.mu
	id       int
	name     string
	size     int64
	incoming bool
	status   string
	err      string
	path     string // where an incoming file was saved
}

type Peer struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

type Hub struct {
	total atomic.Int64 // bytes moved over the network by this process

	mu   sync.Mutex
	name string
	code string
	dir  string
	url  string // the address a phone opens on this network

	remoteURL string // the address that works from anywhere (Tailscale)
	ts        string // Tailscale state: missing, off, on, https
	tsHint    string
	phoneSeen time.Time
	peers     []Peer
	files     []*fileProg
	nextID    int
	busy      bool
	message   string
	speed     float64
}

func (h *Hub) add(name string, size int64, status string) *fileProg {
	fp := &fileProg{name: name, size: size, status: status}
	h.mu.Lock()
	h.nextID++
	fp.id = h.nextID
	h.files = append(h.files, fp)
	h.mu.Unlock()
	return fp
}

// addIn registers a file arriving on this computer.
func (h *Hub) addIn(name string, size int64) *fileProg {
	fp := h.add(name, size, "receiving")
	h.mu.Lock()
	fp.incoming = true
	h.mu.Unlock()
	return fp
}

func (h *Hub) set(fp *fileProg, status, err string) {
	h.mu.Lock()
	fp.status, fp.err = status, err
	h.mu.Unlock()
}

func (h *Hub) setBusy(busy bool, msg string) {
	h.mu.Lock()
	h.busy, h.message = busy, msg
	h.mu.Unlock()
}

// saved marks an incoming file as complete at path.
func (h *Hub) saved(fp *fileProg, path string) {
	h.mu.Lock()
	fp.status, fp.err, fp.path = "done", "", path
	h.mu.Unlock()
}

// clear drops the incoming or the outgoing files from the list, keeping
// incoming ones that are still arriving.
func (h *Hub) clear(incoming bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	kept := h.files[:0]
	for _, fp := range h.files {
		if fp.incoming != incoming || (incoming && (fp.status == "receiving" || fp.status == "verifying")) {
			kept = append(kept, fp)
		}
	}
	h.files = kept
}

// pathOf returns where the incoming file with this id was saved.
func (h *Hub) pathOf(id int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, fp := range h.files {
		if fp.id == id {
			return fp.path
		}
	}
	return ""
}

func (h *Hub) snapshot() []byte {
	type file struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		Done   int64  `json:"done"`
		In     bool   `json:"in"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	files := make([]file, len(h.files))
	for i, fp := range h.files {
		files[i] = file{fp.id, fp.name, fp.size, fp.done.Load(), fp.incoming, fp.status, fp.err}
	}
	b, _ := json.Marshal(map[string]any{
		"name": h.name, "code": h.code, "dir": h.dir, "url": h.url,
		"remote": h.remoteURL, "ts": h.ts, "tsHint": h.tsHint,
		"phoneOnline": time.Since(h.phoneSeen) < 10*time.Second,
		"peers":       h.peers, "files": files, "busy": h.busy, "message": h.message, "speed": h.speed,
	})
	return b
}

// run keeps a smoothed throughput figure up to date and prints a progress
// line on the terminal while bytes are moving.
func (h *Hub) run() {
	const tick = 500 * time.Millisecond
	last, lastT := h.total.Load(), time.Now()
	for now := range time.Tick(tick) {
		cur := h.total.Load()
		inst := float64(cur-last) / now.Sub(lastT).Seconds()
		last, lastT = cur, now

		h.mu.Lock()
		if h.speed == 0 || inst == 0 {
			h.speed = inst
		} else {
			h.speed = 0.6*h.speed + 0.4*inst
		}
		speed := h.speed
		h.mu.Unlock()

		if inst > 0 {
			fmt.Printf("\r  %s/s   ", human(speed))
		}
	}
}

// logf prints a full line, clearing any progress line first.
func logf(format string, args ...any) {
	fmt.Printf("\r%-40s\n", fmt.Sprintf(format, args...))
}

func human(n float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}
