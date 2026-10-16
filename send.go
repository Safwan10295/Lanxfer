package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type sendFile struct {
	path string
	info fileInfo
	temp bool // spooled from the web UI; deleted when the list is cleared
	prog *fileProg

	offered bool // guarded by Sender.mu: listed on the phone since "Send to phone"
}

// id names the file in download links for a phone.
func (f *sendFile) id() string { return f.info.SHA256[:16] }

// chunkHook, when set by tests, runs after every chunk is sent.
var chunkHook func() error

type job struct {
	file int
	idx  int64
}

// sendFiles pairs with the receiver and transfers the files, skipping any
// chunks the receiver already has from an earlier attempt.
func sendFiles(ctx context.Context, addrs []string, code string, files []*sendFile, par int, hub *Hub) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sc, l, err := dialControl(ctx, addrs, code)
	if err != nil {
		return err
	}
	defer sc.Close()
	defer context.AfterFunc(ctx, func() { sc.Close() })()

	offer := message{Type: "offer", Chunk: defaultChunk}
	for _, f := range files {
		offer.Files = append(offer.Files, f.info)
	}
	if err := sc.sendJSON(offer); err != nil {
		return err
	}
	accept, err := sc.readJSON()
	if err != nil {
		return fmt.Errorf("waiting for receiver: %w", err)
	}
	if accept.Type != "accept" || len(accept.Have) != len(files) {
		return fmt.Errorf("receiver refused the transfer: %s", accept.Error)
	}

	handles := make([]*os.File, len(files))
	var jobs []job
	for i, f := range files {
		n := chunkCount(f.info.Size, defaultChunk)
		have := accept.Have[i]
		if int64(len(have)) != (n+7)/8 {
			have = make([]byte, (n+7)/8)
		}
		var done int64
		for c := int64(0); c < n; c++ {
			if hasBit(have, c) {
				done += chunkLen(f.info.Size, defaultChunk, c)
			} else {
				jobs = append(jobs, job{i, c})
			}
		}
		f.prog.done.Store(done)
		hub.set(f.prog, "sending", "")
		if done > 0 {
			logf("resuming %s at %s of %s", f.info.Name, human(float64(done)), human(float64(f.info.Size)))
		}
		if handles[i], err = os.Open(f.path); err != nil {
			return err
		}
		defer handles[i].Close()
	}

	queue := make(chan job, len(jobs))
	for _, j := range jobs {
		queue <- j
	}
	close(queue)

	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	for range min(par, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sendWorker(ctx, l, files, handles, queue, hub); err != nil {
				once.Do(func() { firstErr = err; cancel() })
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}

	for _, f := range files {
		hub.set(f.prog, "verifying", "")
	}
	if err := sc.sendJSON(message{Type: "done"}); err != nil {
		return err
	}
	res, err := sc.readJSON()
	if err != nil {
		return fmt.Errorf("waiting for verification: %w", err)
	}
	if res.Type != "result" || len(res.Results) != len(files) {
		return errors.New("unexpected reply from receiver")
	}
	var failed []string
	for i, f := range files {
		if res.Results[i].OK {
			hub.set(f.prog, "sent", "")
			continue
		}
		hub.set(f.prog, "failed", res.Results[i].Error)
		failed = append(failed, fmt.Sprintf("%s: %s", f.info.Name, res.Results[i].Error))
	}
	if failed != nil {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// sendWorker owns one data connection and sends chunks from the shared queue.
func sendWorker(ctx context.Context, l *link, files []*sendFile, handles []*os.File, queue <-chan job, hub *Hub) error {
	sc, err := dialData(ctx, l)
	if err != nil {
		return err
	}
	defer sc.Close()
	defer context.AfterFunc(ctx, func() { sc.Close() })()

	frame := make([]byte, 4+chunkHdr+defaultChunk+sc.wr.Overhead())
	for j := range queue {
		if err := ctx.Err(); err != nil {
			return err
		}
		f := files[j.file]
		n := int(chunkLen(f.info.Size, defaultChunk, j.idx))
		frame[4] = recChunk
		binary.BigEndian.PutUint32(frame[5:], uint32(j.file))
		binary.BigEndian.PutUint32(frame[9:], uint32(j.idx))
		data := frame[4+chunkHdr:][:n]
		if _, err := handles[j.file].ReadAt(data, j.idx*defaultChunk); err != nil {
			return fmt.Errorf("read %s: %w", f.info.Name, err)
		}
		if err := sc.writeFrame(frame, chunkHdr+n); err != nil {
			return err
		}
		f.prog.done.Add(int64(n))
		hub.total.Add(int64(n))
		if chunkHook != nil {
			if err := chunkHook(); err != nil {
				return err
			}
		}
	}
	// Wait for the receiver to confirm everything on this connection is written.
	if err := sc.WriteMsg([]byte{recEnd}); err != nil {
		return err
	}
	if _, err := sc.ReadMsg(nil); err != nil {
		return fmt.Errorf("waiting for receiver: %w", err)
	}
	return nil
}

// Sender is the state behind send mode: discovered receivers and the queue
// of files waiting to go.
type Sender struct {
	hub  *Hub
	par  int
	tmp  string
	self string // our own advertised name, left out of the receiver list

	mu    sync.Mutex
	peers map[string]map[string]time.Time // name -> address -> last seen
	queue []*sendFile
}

func newSender(hub *Hub, par int) *Sender {
	return &Sender{hub: hub, par: max(par, 1), peers: map[string]map[string]time.Time{}}
}

// addPath queues a file from disk, hashing it first.
func (s *Sender) addPath(p string) error {
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", p)
	}
	fp := s.hub.add(filepath.Base(p), st.Size(), "hashing")
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(h, progWriter{fp}), f)
	if err != nil {
		return err
	}
	s.enqueue(&sendFile{path: p, prog: fp, info: fileInfo{Name: filepath.Base(p), Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}})
	return nil
}

func (s *Sender) enqueue(f *sendFile) {
	f.prog.done.Store(0)
	s.hub.mu.Lock()
	f.prog.size, f.prog.status = f.info.Size, "ready"
	s.hub.mu.Unlock()
	s.mu.Lock()
	s.queue = append(s.queue, f)
	s.mu.Unlock()
}

type progWriter struct{ fp *fileProg }

func (w progWriter) Write(p []byte) (int, error) {
	w.fp.done.Add(int64(len(p)))
	return len(p), nil
}

// files returns the current queue.
func (s *Sender) files() []*sendFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*sendFile(nil), s.queue...)
}

// send transfers the queued files that haven't been delivered yet, or all
// of them again if every one already has (say, to a second computer).
func (s *Sender) send(ctx context.Context, addrs []string, code string) error {
	files := s.files()
	if len(files) == 0 {
		return errors.New("nothing to send")
	}
	s.hub.mu.Lock()
	var pending []*sendFile
	for _, f := range files {
		if f.prog.status != "sent" {
			pending = append(pending, f)
		}
	}
	s.hub.mu.Unlock()
	if len(pending) == 0 {
		pending = files
	}

	start, before := time.Now(), s.hub.total.Load()
	err := sendFiles(ctx, addrs, code, pending, s.par, s.hub)
	if err != nil {
		s.hub.mu.Lock()
		for _, f := range pending {
			if f.prog.status != "sent" && f.prog.status != "failed" {
				f.prog.status, f.prog.err = "failed", "interrupted; send again to resume"
			}
		}
		s.hub.mu.Unlock()
	}
	if err != nil {
		return err
	}
	sent, secs := float64(s.hub.total.Load()-before), time.Since(start).Seconds()
	logf("sent %d file(s), %s in %.1fs (%s/s), SHA-256 verified by receiver",
		len(pending), human(sent), secs, human(sent/secs))
	return nil
}

// clear empties the queue and removes spooled uploads.
func (s *Sender) clear() {
	s.mu.Lock()
	for _, f := range s.queue {
		if f.temp {
			os.Remove(f.path)
		}
	}
	s.queue = nil
	s.mu.Unlock()
	s.hub.clear(false)
}

// discover keeps the list of receivers seen on the LAN fresh.
func (s *Sender) discover(ctx context.Context) {
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := browse(round, s.addPeer)
		cancel()
		if err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
		s.mu.Lock()
		for name, addrs := range s.peers {
			for a, seen := range addrs {
				if time.Since(seen) > 30*time.Second {
					delete(addrs, a)
				}
			}
			if len(addrs) == 0 {
				delete(s.peers, name)
			}
		}
		s.mu.Unlock()
		s.publishPeers()
	}
}

func (s *Sender) peerList() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]Peer, 0, len(s.peers))
	for name, addrs := range s.peers {
		p := Peer{Name: name}
		for a := range addrs {
			p.Addrs = append(p.Addrs, a)
		}
		// Same-network addresses first: they're direct and fastest.
		sort.SliceStable(p.Addrs, func(i, j int) bool { return !isTailscale(p.Addrs[i]) && isTailscale(p.Addrs[j]) })
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// addPeer records that a receiver answered at these addresses just now.
func (s *Sender) addPeer(p Peer) {
	if p.Name == s.self {
		return
	}
	s.mu.Lock()
	addrs := s.peers[p.Name]
	if addrs == nil {
		addrs = map[string]time.Time{}
		s.peers[p.Name] = addrs
	}
	for _, a := range p.Addrs {
		addrs[a] = time.Now()
	}
	s.mu.Unlock()
	s.publishPeers()
}

var tailnet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isTailscale(addr string) bool {
	h, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(h)
	return ip != nil && (tailnet.Contains(ip) || strings.HasPrefix(h, "fd7a:115c:a1e0"))
}

func (s *Sender) publishPeers() {
	list := s.peerList()
	s.hub.mu.Lock()
	s.hub.peers = list
	s.hub.mu.Unlock()
}

// lookup turns a receiver name or a literal host:port into dial addresses.
func (s *Sender) lookup(to string) []string {
	if _, _, err := net.SplitHostPort(to); err == nil {
		return []string{to}
	}
	for _, p := range s.peerList() {
		if strings.EqualFold(p.Name, to) {
			return p.Addrs
		}
	}
	return nil
}

// offer lists every file not yet offered on the phone, and returns how
// many that was.
func (s *Sender) offer() int {
	s.mu.Lock()
	var fresh []*sendFile
	for _, f := range s.queue {
		if !f.offered {
			f.offered = true
			fresh = append(fresh, f)
		}
	}
	s.mu.Unlock()
	for _, f := range fresh {
		s.hub.set(f.prog, "offered", "")
	}
	return len(fresh)
}

// offeredFiles is what the phone sees, newest first.
func (s *Sender) offeredFiles() []*sendFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []*sendFile
	for i := len(s.queue) - 1; i >= 0; i-- {
		if s.queue[i].offered {
			list = append(list, s.queue[i])
		}
	}
	return list
}
