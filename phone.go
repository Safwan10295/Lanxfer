package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A phone can't run this binary, so the computer serves an HTTPS page on
// the LAN instead. The phone pairs with the 6-digit code, uploads files in
// SHA-256-checked chunks (resumable, like .part files elsewhere) and
// downloads whatever is in the computer's send list.

//go:embed web/phone.html
var phoneHTML []byte

// quietLog drops TLS handshake noise: phones abort the first handshake
// while showing a certificate warning.
var quietLog = log.New(io.Discard, "", 0)

const (
	phoneChunk  = maxChunk
	phoneCookie = "lanxfer"

	pwaTags = `<link rel="manifest" href="/manifest.webmanifest">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">`

	manifest = `{"name":"lanxfer","short_name":"lanxfer","start_url":"/","scope":"/","display":"standalone",
"background_color":"#111318","theme_color":"#111318",
"icons":[{"src":"/icon.png","sizes":"180x180","type":"image/png"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png","purpose":"any maskable"}]}`
)

type Phone struct {
	hub     *Hub
	dir     string
	code    string
	queue   func() []*sendFile // files offered to the phone
	fetched func(*sendFile)    // called when the phone has downloaded a whole file
	lock    lockout

	mu        sync.Mutex
	tokens    map[string]bool
	tokenFile string // where paired phones are remembered; "" keeps them in memory only
	uploads   map[string]*rfile
}

func newPhone(dir, code string, hub *Hub, queue func() []*sendFile) (*Phone, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Phone{hub: hub, dir: dir, code: code, queue: queue, tokens: map[string]bool{}, uploads: map[string]*rfile{}}, nil
}

// remember keeps paired phones across restarts, so a phone only has to
// enter a code the first time.
func (p *Phone) remember(file string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenFile = file
	var saved []string
	if b, err := os.ReadFile(file); err == nil && json.Unmarshal(b, &saved) == nil {
		for _, t := range saved {
			p.tokens[t] = true
		}
	}
}

// close records the state of unfinished uploads so they can resume later.
func (p *Phone) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rf := range p.uploads {
		rf.saveMeta()
		rf.f.Close()
	}
}

// handler serves the phone page. trusted means it is reached through a real
// certificate (Tailscale), where an iPhone can install it as an app.
func (p *Phone) handler(trusted bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := phoneHTML
		// Only on a trusted certificate does an iPhone run a home-screen web
		// app properly; on the self-signed one it stays a Safari bookmark.
		if trusted {
			page = bytes.Replace(page, []byte("<!--PWA-->"), []byte(pwaTags), 1)
		}
		w.Write(page)
	})
	mux.HandleFunc("GET /icon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(iconPNG(180, false))
	})
	mux.HandleFunc("GET /icon-512.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(iconPNG(512, false))
	})
	mux.HandleFunc("GET /manifest.webmanifest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/manifest+json")
		w.Write([]byte(manifest))
	})
	mux.HandleFunc("POST /api/pair", p.handlePair)
	mux.HandleFunc("GET /api/state", p.authed(p.handleState))
	mux.HandleFunc("POST /api/up/start", p.authed(p.handleStart))
	mux.HandleFunc("PUT /api/up/chunk", p.authed(p.handleChunk))
	mux.HandleFunc("POST /api/up/finish", p.authed(p.handleFinish))
	mux.HandleFunc("GET /dl/{id}", p.authed(p.handleDownload))
	return mux
}

func (p *Phone) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(phoneCookie)
		p.mu.Lock()
		ok := err == nil && p.tokens[c.Value]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "pair first", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (p *Phone) handlePair(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !p.lock.begin() {
		http.Error(w, "too many attempts; wait a few seconds", http.StatusTooManyRequests)
		return
	}
	ok := subtle.ConstantTimeCompare([]byte(digits(req.Code)), []byte(p.code)) == 1
	p.lock.end(ok)
	if !ok {
		logf("pairing attempt from %s failed", r.RemoteAddr)
		http.Error(w, "wrong code", http.StatusForbidden)
		return
	}
	tok := make([]byte, 16)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	p.mu.Lock()
	p.tokens[token] = true
	if p.tokenFile != "" {
		all := make([]string, 0, len(p.tokens))
		for t := range p.tokens {
			all = append(all, t)
		}
		b, _ := json.Marshal(all)
		os.WriteFile(p.tokenFile, b, 0o600)
	}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: phoneCookie, Value: token, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	logf("paired with phone at %s", r.RemoteAddr)
}

func (p *Phone) handleState(w http.ResponseWriter, r *http.Request) {
	type file struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	files := []file{}
	seen := map[string]bool{}
	for _, f := range p.queue() {
		if !seen[f.id()] {
			seen[f.id()] = true
			files = append(files, file{f.id(), f.info.Name, f.info.Size})
		}
	}
	p.hub.mu.Lock()
	name := p.hub.name
	p.hub.phoneSeen = time.Now() // the phone page polls this every few seconds
	p.hub.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"name": name, "files": files})
}

// handleStart opens (or resumes) an upload. Browsers can't cheaply hash a
// whole file up front, so an upload is identified by name, size and
// modification time; integrity is checked per chunk instead.
func (p *Phone) handleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string
		Size, Mtime int64
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Size < 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d\x00%d", req.Name, req.Size, req.Mtime))
	id := hex.EncodeToString(sum[:])

	p.mu.Lock()
	defer p.mu.Unlock()
	rf := p.uploads[id]
	if rf == nil {
		var done int64
		var err error
		base := filepath.Join(p.dir, safeName(req.Name)+"."+id[:8])
		rf, done, err = openPart(base, fileInfo{Name: req.Name, Size: req.Size, SHA256: id}, phoneChunk)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rf.prog = p.hub.addIn(rf.name, req.Size)
		rf.prog.done.Store(done)
		p.uploads[id] = rf
		if done > 0 {
			logf("resuming %s at %s of %s", rf.name, human(float64(done)), human(float64(req.Size)))
		} else {
			logf("receiving %s (%s)", rf.name, human(float64(req.Size)))
		}
	}
	rf.mu.Lock()
	have := append([]byte{}, rf.have...)
	rf.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"id": id, "chunk": phoneChunk, "have": have})
}

func (p *Phone) upload(r *http.Request) *rfile {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.uploads[r.URL.Query().Get("id")]
}

func (p *Phone) handleChunk(w http.ResponseWriter, r *http.Request) {
	rf := p.upload(r)
	idx, err := strconv.ParseInt(r.URL.Query().Get("idx"), 10, 64)
	if rf == nil || err != nil {
		http.Error(w, "unknown upload", http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, phoneChunk))
	if err != nil {
		http.Error(w, "bad chunk", http.StatusBadRequest)
		return
	}
	if want := r.Header.Get("X-SHA256"); want != "" {
		if sum := sha256.Sum256(data); !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
			http.Error(w, "SHA-256 mismatch", http.StatusUnprocessableEntity)
			return
		}
	}
	if err := rf.put(idx, data, p.hub); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Phone) handleFinish(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	p.mu.Lock()
	rf := p.uploads[id]
	if rf == nil || !rf.complete() {
		p.mu.Unlock()
		http.Error(w, "upload is incomplete", http.StatusConflict)
		return
	}
	delete(p.uploads, id)
	p.mu.Unlock()

	rf.final = true
	rf.f.Close()
	path := uniquePath(filepath.Join(p.dir, rf.name))
	if err := os.Rename(rf.part, path); err != nil {
		p.hub.set(rf.prog, "failed", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	os.Remove(rf.meta)
	p.hub.saved(rf.prog, path)
	logf("saved %s", path)
	w.WriteHeader(http.StatusNoContent)
}

type countWriter struct {
	http.ResponseWriter
	hub *Hub
	n   int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	c.hub.total.Add(int64(n))
	return n, err
}

func (p *Phone) handleDownload(w http.ResponseWriter, r *http.Request) {
	var sf *sendFile
	for _, f := range p.queue() {
		if f.id() == r.PathValue("id") {
			sf = f
		}
	}
	if sf == nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(sf.path)
	if err != nil {
		http.Error(w, "file is no longer available", http.StatusGone)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": sf.info.Name}))
	// ServeContent handles Range requests, which is what lets the phone's
	// download manager resume.
	cw := &countWriter{ResponseWriter: w, hub: p.hub}
	http.ServeContent(cw, r, sf.info.Name, st.ModTime(), f)
	if r.Header.Get("Range") == "" && cw.n == st.Size() && p.fetched != nil {
		p.fetched(sf)
	}
}

// serve starts the HTTPS server the phone talks to and returns its URL.
func (p *Phone) serve(ctx context.Context, listen, host string) (string, error) {
	ips, primary := lanIPs()
	if host == "" {
		host = primary.String()
	} else if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	}
	cert, err := loadCert(ips)
	if err != nil {
		return "", err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", listen, cfg)
	if err != nil {
		return "", err
	}
	// Phones abort the first handshake while showing the certificate
	// warning; that isn't worth logging.
	srv := &http.Server{Handler: p.handler(false), ErrorLog: quietLog}
	go srv.Serve(ln)
	context.AfterFunc(ctx, func() { srv.Close() })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	return "https://" + net.JoinHostPort(host, port), nil
}

// lanIPs returns this machine's IPv4 addresses and the one used for outbound
// traffic, which is almost always the one a phone on the same Wi-Fi can reach.
func lanIPs() (all []net.IP, primary net.IP) {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			all = append(all, n.IP.To4())
		}
	}
	// Connecting a UDP socket sends nothing; it just asks the OS for a route.
	if c, err := net.Dial("udp4", "192.0.2.1:9"); err == nil {
		primary = c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
	}
	if primary == nil || primary.IsUnspecified() {
		primary = net.IPv4(127, 0, 0, 1)
		if len(all) > 0 {
			primary = all[0]
		}
	}
	return all, primary
}

// configDir is where the phone certificate and paired phones are kept.
func configDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "lanxfer")
	os.MkdirAll(dir, 0o700)
	return dir
}

// loadCert returns a self-signed certificate covering ips. It is kept in the
// user's config directory so the phone sees the same certificate (and so
// the same one-time warning) across runs, until this machine's IP changes.
func loadCert(ips []net.IP) (tls.Certificate, error) {
	ips = append(ips, net.IPv4(127, 0, 0, 1))
	dir := configDir()
	certPath, keyPath := filepath.Join(dir, "phone-cert.pem"), filepath.Join(dir, "phone-key.pem")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && time.Until(leaf.NotAfter) > 24*time.Hour {
			covered := true
			for _, ip := range ips {
				covered = covered && leaf.VerifyHostname(ip.String()) == nil
			}
			if covered {
				return cert, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "lanxfer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(397 * 24 * time.Hour), // under the 398-day cap iOS puts on server certificates
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(certPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)
	return tls.X509KeyPair(certPEM, keyPEM)
}
