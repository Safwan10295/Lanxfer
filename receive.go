package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/cpace"
)

type Receiver struct {
	name string // answered to pings from other computers
	dir  string
	code string
	hub  *Hub
	ln   net.Listener

	lock lockout

	mu       sync.Mutex
	sessions map[[16]byte]*session
}

// session is one paired sender: a control connection plus its data connections.
type session struct {
	key []byte

	mu     sync.Mutex
	chunk  int64
	files  []*rfile
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// rfile is a file being received into <name>.<sha8>.part, with a JSON
// sidecar recording which chunks are on disk so a later run can resume.
type rfile struct {
	info       fileInfo
	name       string
	part, meta string
	chunk      int64
	nchunks    int64
	f          *os.File
	prog       *fileProg
	final      bool

	mu     sync.Mutex
	have   []byte
	saved  time.Time
	metaMu sync.Mutex
}

type partMeta struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Chunk  int64  `json:"chunk"`
	Have   []byte `json:"have"`
}

func newCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n)
}

func newReceiver(dir, listen string, hub *Hub) (*Receiver, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	return &Receiver{dir: dir, code: newCode(), hub: hub, ln: ln, sessions: map[[16]byte]*session{}}, nil
}

func (r *Receiver) port() int { return r.ln.Addr().(*net.TCPAddr).Port }

func (r *Receiver) serve() error { return r.serveOn(r.ln) }

func (r *Receiver) serveOn(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *Receiver) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	hdr := make([]byte, len(magic)+1)
	if _, err := io.ReadFull(c, hdr); err != nil || string(hdr[:len(magic)]) != magic {
		return
	}
	switch hdr[len(magic)] {
	case connControl:
		r.control(c)
	case connData:
		r.data(c)
	case connPing:
		writeBlob(c, []byte(r.name))
	}
}

// lockout admits one pairing attempt at a time and none for a while after a
// failure, so a 6-digit code can't be brute-forced by guessing quickly or in
// parallel.
type lockout struct {
	mu    sync.Mutex
	busy  bool
	fails int
	until time.Time
}

func (l *lockout) begin() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.busy || time.Now().Before(l.until) {
		return false
	}
	l.busy = true
	return true
}

func (l *lockout) end(ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.busy = false
	if ok {
		l.fails = 0
		return
	}
	l.fails++
	l.until = time.Now().Add(time.Second << min(l.fails-1, 5))
}

func (r *Receiver) handshake(c net.Conn) (*secureConn, [16]byte, []byte, error) {
	var sid [16]byte
	msgA, err := readBlob(c)
	if err != nil {
		return nil, sid, nil, err
	}
	msgB, key, err := cpace.Exchange(r.code, paceCtx, msgA)
	if err != nil {
		return nil, sid, nil, err
	}
	rand.Read(sid[:])
	if _, err := c.Write(sid[:]); err != nil {
		return nil, sid, nil, err
	}
	if err := writeBlob(c, msgB); err != nil {
		return nil, sid, nil, err
	}
	sc := newSecure(c, key, sid[:], false)
	if m, err := sc.readJSON(); err != nil || m.Type != "hello" {
		return nil, sid, nil, errors.New("wrong code")
	}
	return sc, sid, key, nil
}

func (r *Receiver) control(c net.Conn) {
	if !r.lock.begin() {
		c.Write([]byte{1})
		return
	}
	c.Write([]byte{0})
	sc, sid, key, err := r.handshake(c)
	r.lock.end(err == nil)
	if err != nil {
		logf("pairing attempt from %s failed", c.RemoteAddr())
		return
	}
	c.SetDeadline(time.Time{})

	s := &session{key: key, conns: map[net.Conn]struct{}{}}
	r.mu.Lock()
	r.sessions[sid] = s
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.sessions, sid)
		r.mu.Unlock()
		r.closeSession(s)
	}()

	if err := sc.sendJSON(message{Type: "hello"}); err != nil {
		return
	}
	logf("paired with %s", c.RemoteAddr())
	for {
		m, err := sc.readJSON()
		if err != nil {
			return
		}
		var reply message
		switch m.Type {
		case "offer":
			have, err := r.prepare(s, m)
			if err != nil {
				reply = message{Type: "error", Error: err.Error()}
			} else {
				reply = message{Type: "accept", Have: have}
			}
		case "done":
			reply = message{Type: "result", Results: r.finish(s)}
		default:
			return
		}
		if err := sc.sendJSON(reply); err != nil {
			return
		}
	}
}

// prepare opens (or resumes) a .part file for every offered file and
// returns the chunk bitmaps the sender should skip.
func (r *Receiver) prepare(s *session, m message) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.files != nil {
		return nil, errors.New("only one offer per session")
	}
	if m.Chunk < minChunk || m.Chunk > maxChunk {
		return nil, errors.New("unsupported chunk size")
	}
	if len(m.Files) == 0 || len(m.Files) > 10000 {
		return nil, errors.New("bad file count")
	}
	s.chunk = m.Chunk
	used := map[string]bool{}
	var files []*rfile
	var have [][]byte
	fail := func(err error) ([][]byte, error) {
		for _, rf := range files {
			rf.f.Close()
			r.hub.set(rf.prog, "failed", err.Error())
		}
		return nil, err
	}
	for i, fi := range m.Files {
		sum, err := hex.DecodeString(fi.SHA256)
		if err != nil || len(sum) != sha256.Size || fi.Size < 0 {
			return fail(fmt.Errorf("bad offer for %q", fi.Name))
		}
		base := filepath.Join(r.dir, safeName(fi.Name)+"."+strings.ToLower(fi.SHA256[:8]))
		if used[base] {
			base += fmt.Sprintf(".%d", i)
		}
		used[base] = true
		rf, done, err := openPart(base, fi, m.Chunk)
		if err != nil {
			return fail(err)
		}
		rf.prog = r.hub.addIn(rf.name, fi.Size)
		files = append(files, rf)
		rf.prog.done.Store(done)
		if done > 0 {
			logf("resuming %s at %s of %s", rf.name, human(float64(done)), human(float64(fi.Size)))
		} else {
			logf("receiving %s (%s)", rf.name, human(float64(fi.Size)))
		}
		have = append(have, append([]byte(nil), rf.have...))
	}
	s.files = files
	return have, nil
}

// openPart opens base.part for fi, picking up the chunk bitmap from its
// sidecar when an earlier attempt at the same file left one. It returns how
// many bytes are already on disk.
func openPart(base string, fi fileInfo, chunk int64) (*rfile, int64, error) {
	rf := &rfile{info: fi, name: safeName(fi.Name), chunk: chunk, nchunks: chunkCount(fi.Size, chunk),
		part: base + ".part", meta: base + ".part.json"}
	rf.have = make([]byte, (rf.nchunks+7)/8)

	var done int64
	if st, err := os.Stat(rf.part); err == nil && st.Size() == fi.Size {
		var pm partMeta
		if b, err := os.ReadFile(rf.meta); err == nil && json.Unmarshal(b, &pm) == nil &&
			pm.Size == fi.Size && pm.Chunk == chunk && strings.EqualFold(pm.SHA256, fi.SHA256) && len(pm.Have) == len(rf.have) {
			rf.have = pm.Have
			for c := int64(0); c < rf.nchunks; c++ {
				if hasBit(rf.have, c) {
					done += chunkLen(fi.Size, chunk, c)
				}
			}
		}
	}
	f, err := os.OpenFile(rf.part, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, 0, err
	}
	if err := f.Truncate(fi.Size); err != nil {
		f.Close()
		return nil, 0, err
	}
	rf.f = f
	return rf, done, nil
}

func (r *Receiver) data(c net.Conn) {
	var sid [16]byte
	nonces := make([]byte, 32)
	if _, err := io.ReadFull(c, sid[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, nonces[:16]); err != nil {
		return
	}
	r.mu.Lock()
	s := r.sessions[sid]
	r.mu.Unlock()
	if s == nil {
		return
	}
	rand.Read(nonces[16:])
	if _, err := c.Write(nonces[16:]); err != nil {
		return
	}
	sc := newSecure(c, s.key, nonces, false)
	c.SetDeadline(time.Time{})

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	chunk := s.chunk
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		s.wg.Done()
	}()

	buf := make([]byte, chunk+chunkHdr+64)
	for {
		p, err := sc.ReadMsg(buf)
		if err != nil || len(p) == 0 {
			return
		}
		switch p[0] {
		case recChunk:
			if len(p) < chunkHdr || r.writeChunk(s, p) != nil {
				return
			}
		case recEnd:
			sc.WriteMsg([]byte{recEnd})
			return
		default:
			return
		}
	}
}

func (r *Receiver) writeChunk(s *session, p []byte) error {
	fid, idx := int(binary.BigEndian.Uint32(p[1:])), int64(binary.BigEndian.Uint32(p[5:]))
	data := p[chunkHdr:]
	s.mu.Lock()
	var rf *rfile
	if fid < len(s.files) {
		rf = s.files[fid]
	}
	s.mu.Unlock()
	if rf == nil {
		return errors.New("bad chunk")
	}
	return rf.put(idx, data, r.hub)
}

// put writes one chunk to the .part file and records it.
func (rf *rfile) put(idx int64, data []byte, hub *Hub) error {
	if rf.final || idx < 0 || idx >= rf.nchunks || int64(len(data)) != chunkLen(rf.info.Size, rf.chunk, idx) {
		return errors.New("bad chunk")
	}
	if _, err := rf.f.WriteAt(data, idx*rf.chunk); err != nil {
		logf("write %s: %v", rf.name, err)
		return err
	}
	rf.mu.Lock()
	if !hasBit(rf.have, idx) {
		setBit(rf.have, idx)
		rf.prog.done.Add(int64(len(data)))
		hub.total.Add(int64(len(data)))
	}
	save := time.Since(rf.saved) > time.Second
	if save {
		rf.saved = time.Now()
	}
	rf.mu.Unlock()
	if save {
		rf.saveMeta()
	}
	return nil
}

// saveMeta records the chunks on disk. A chunk is only marked after its
// write returned, so the sidecar never claims more than the .part file has.
func (rf *rfile) saveMeta() {
	rf.mu.Lock()
	pm := partMeta{Size: rf.info.Size, SHA256: rf.info.SHA256, Chunk: rf.chunk, Have: append([]byte(nil), rf.have...)}
	rf.mu.Unlock()
	b, _ := json.Marshal(pm)
	rf.metaMu.Lock()
	defer rf.metaMu.Unlock()
	if os.WriteFile(rf.meta+".tmp", b, 0o644) == nil {
		os.Rename(rf.meta+".tmp", rf.meta)
	}
}

func (rf *rfile) complete() bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	for c := int64(0); c < rf.nchunks; c++ {
		if !hasBit(rf.have, c) {
			return false
		}
	}
	return true
}

// finish verifies each fully received file against the sender's SHA-256 and
// moves it to its final name.
func (r *Receiver) finish(s *session) []fileResult {
	s.mu.Lock()
	files := s.files
	s.mu.Unlock()
	results := make([]fileResult, len(files))
	for i, rf := range files {
		path, err := r.finalize(rf)
		if err != nil {
			results[i] = fileResult{Error: err.Error()}
			r.hub.set(rf.prog, "failed", err.Error())
			logf("%s: %v", rf.name, err)
			continue
		}
		results[i] = fileResult{OK: true, Path: path}
		r.hub.saved(rf.prog, path)
		logf("saved %s (SHA-256 verified)", path)
	}
	return results
}

func (r *Receiver) finalize(rf *rfile) (string, error) {
	if rf.final {
		return "", errors.New("already finished")
	}
	if !rf.complete() {
		return "", errors.New("incomplete: some chunks never arrived")
	}
	r.hub.set(rf.prog, "verifying", "")
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(rf.f, 0, rf.info.Size)); err != nil {
		return "", err
	}
	rf.final = true
	rf.f.Close()
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), rf.info.SHA256) {
		// The data on disk is wrong, so there is nothing worth resuming.
		os.Remove(rf.part)
		os.Remove(rf.meta)
		return "", errors.New("SHA-256 mismatch")
	}
	path := uniquePath(filepath.Join(r.dir, rf.name))
	if err := os.Rename(rf.part, path); err != nil {
		return "", err
	}
	os.Remove(rf.meta)
	return path, nil
}

// closeSession stops the data connections and leaves unfinished files in a
// resumable state.
func (r *Receiver) closeSession(s *session) {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	files := s.files
	s.mu.Unlock()
	s.wg.Wait()
	for _, rf := range files {
		if rf.final {
			continue
		}
		rf.saveMeta()
		rf.f.Close()
		r.hub.set(rf.prog, "interrupted", "partial data kept; send again to resume")
		logf("%s interrupted at %s; send again to resume", rf.name, human(float64(rf.prog.done.Load())))
	}
}

// uniquePath returns p, or "name (1).ext" etc. if p already exists.
func uniquePath(p string) string {
	ext := filepath.Ext(p)
	stem := strings.TrimSuffix(p, ext)
	for i := 1; ; i++ {
		if _, err := os.Lstat(p); err != nil {
			return p
		}
		p = fmt.Sprintf("%s (%d)%s", stem, i, ext)
	}
}
