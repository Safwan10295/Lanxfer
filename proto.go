package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"filippo.io/cpace"
)

// Wire protocol
//
// Every TCP connection starts with magic + one type byte.
//
// Control connection (one per transfer):
//   sender   -> magic, connControl
//   receiver -> status byte (0 = go ahead, 1 = busy / locked out)
//   sender   -> CPace message A
//   receiver -> session id (16 bytes), CPace message B
//   Both sides now hold a strong shared key if (and only if) they used the
//   same pairing code. Everything after this is AES-256-GCM records carrying
//   JSON messages: hello, offer/accept, done/result.
//
// Data connections (several per transfer):
//   sender   -> magic, connData, session id, 16-byte nonce
//   receiver -> 16-byte nonce
//   Keys are derived from the session key and both nonces, then the sender
//   streams encrypted chunk records and finishes with an end record, which
//   the receiver acknowledges once everything is on disk.

const (
	magic       = "LANXFER1"
	connControl = byte(0)
	connData    = byte(1)
	connPing    = byte(2) // "are you lanxfer?"; the receiver answers with its name

	// defaultPCPort is where the app listens for other computers, fixed so
	// they can find it over Tailscale, where mDNS doesn't reach.
	defaultPCPort = 7442

	recChunk = byte(1)
	recEnd   = byte(2)
	chunkHdr = 9 // type, file index (u32), chunk index (u32)

	defaultChunk = 1 << 20
	minChunk     = 64 << 10
	maxChunk     = 4 << 20
	maxRecord    = maxChunk + 1024

	handshakeTimeout = 10 * time.Second
)

var paceCtx = cpace.NewContextInfo("lanxfer-sender", "lanxfer-receiver", nil)

var errBusy = errors.New("receiver is busy or briefly locked after a wrong code; try again in a few seconds")

type fileInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type fileResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Path  string `json:"path,omitempty"`
}

type message struct {
	Type    string       `json:"type"`
	Files   []fileInfo   `json:"files,omitempty"`
	Chunk   int64        `json:"chunk,omitempty"`
	Have    [][]byte     `json:"have,omitempty"` // per file: bitmap of chunks already on disk
	Results []fileResult `json:"results,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// secureConn frames a TCP stream into AES-GCM records: a 4-byte big-endian
// ciphertext length followed by the ciphertext. Each direction has its own
// key and a counter nonce.
type secureConn struct {
	net.Conn
	rd, wr cipher.AEAD
	rn, wn uint64
}

func newSecure(c net.Conn, key, salt []byte, sender bool) *secureConn {
	aead := func(label string) cipher.AEAD {
		k, err := hkdf.Key(sha256.New, key, salt, label, 32)
		if err != nil {
			panic(err)
		}
		b, err := aes.NewCipher(k)
		if err != nil {
			panic(err)
		}
		g, err := cipher.NewGCM(b)
		if err != nil {
			panic(err)
		}
		return g
	}
	up, down := aead("lanxfer sender->receiver"), aead("lanxfer receiver->sender")
	if sender {
		return &secureConn{Conn: c, wr: up, rd: down}
	}
	return &secureConn{Conn: c, wr: down, rd: up}
}

func counterNonce(n uint64) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[4:], n)
	return b
}

// writeFrame encrypts frame[4:4+n] in place and sends it. frame must have
// room for the 4-byte length prefix and the 16-byte tag.
func (s *secureConn) writeFrame(frame []byte, n int) error {
	out := s.wr.Seal(frame[4:4], counterNonce(s.wn), frame[4:4+n], nil)
	s.wn++
	binary.BigEndian.PutUint32(frame, uint32(len(out)))
	_, err := s.Conn.Write(frame[:4+len(out)])
	return err
}

func (s *secureConn) WriteMsg(p []byte) error {
	frame := make([]byte, 4+len(p)+s.wr.Overhead())
	copy(frame[4:], p)
	return s.writeFrame(frame, len(p))
}

// ReadMsg reads and decrypts one record, reusing buf when it is big enough.
func (s *secureConn) ReadMsg(buf []byte) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < s.rd.Overhead() || n > maxRecord {
		return nil, fmt.Errorf("bad record length %d", n)
	}
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return nil, err
	}
	p, err := s.rd.Open(buf[:0], counterNonce(s.rn), buf, nil)
	s.rn++
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return p, nil
}

func (s *secureConn) sendJSON(m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.WriteMsg(b)
}

func (s *secureConn) readJSON() (message, error) {
	var m message
	b, err := s.ReadMsg(nil)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func writeBlob(w io.Writer, b []byte) error {
	_, err := w.Write(append([]byte{byte(len(b))}, b...))
	return err
}

func readBlob(r io.Reader) ([]byte, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, n[0])
	_, err := io.ReadFull(r, b)
	return b, err
}

// link is what a sender needs to open data connections for a paired session.
type link struct {
	addr string
	sid  [16]byte
	key  []byte
}

// dialControl connects to the first reachable address, runs the CPace
// exchange with the pairing code and confirms both sides got the same key.
func dialControl(ctx context.Context, addrs []string, code string) (*secureConn, *link, error) {
	var c net.Conn
	var err error
	var addr string
	for _, addr = range addrs {
		if c, err = dial(ctx, addr, 3*time.Second); err == nil {
			break
		}
	}
	if c == nil {
		if err == nil {
			err = errors.New("no receiver address")
		}
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	sc, l, err := pair(c, addr, code)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return sc, l, nil
}

func pair(c net.Conn, addr, code string) (*secureConn, *link, error) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if _, err := c.Write(append([]byte(magic), connControl)); err != nil {
		return nil, nil, err
	}
	var status [1]byte
	if _, err := io.ReadFull(c, status[:]); err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	if status[0] != 0 {
		return nil, nil, errBusy
	}
	msgA, state, err := cpace.Start(code, paceCtx)
	if err != nil {
		return nil, nil, err
	}
	if err := writeBlob(c, msgA); err != nil {
		return nil, nil, err
	}
	l := &link{addr: addr}
	if _, err := io.ReadFull(c, l.sid[:]); err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	msgB, err := readBlob(c)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	if l.key, err = state.Finish(msgB); err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	sc := newSecure(c, l.key, l.sid[:], true)
	// Key confirmation: the receiver can only read this (and we can only
	// read its reply) if both sides used the same code.
	if err := sc.sendJSON(message{Type: "hello"}); err != nil {
		return nil, nil, err
	}
	if m, err := sc.readJSON(); err != nil || m.Type != "hello" {
		return nil, nil, errors.New("pairing failed: wrong code?")
	}
	c.SetDeadline(time.Time{})
	return sc, l, nil
}

func dialData(ctx context.Context, l *link) (*secureConn, error) {
	c, err := dial(ctx, l.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	nonces := make([]byte, 32)
	rand.Read(nonces[:16])
	hello := append(append([]byte(magic), connData), l.sid[:]...)
	if _, err := c.Write(append(hello, nonces[:16]...)); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.ReadFull(c, nonces[16:]); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return newSecure(c, l.key, nonces, true), nil
}

func chunkCount(size, chunk int64) int64 { return (size + chunk - 1) / chunk }

func chunkLen(size, chunk, idx int64) int64 {
	if rest := size - idx*chunk; rest < chunk {
		return rest
	}
	return chunk
}

func hasBit(b []byte, i int64) bool { return b[i/8]&(1<<(i%8)) != 0 }
func setBit(b []byte, i int64)      { b[i/8] |= 1 << (i % 8) }

// safeName reduces a peer- or browser-supplied file name to a plain base
// name that is safe to create inside the download directory.
func safeName(n string) string {
	n = path.Base(strings.ReplaceAll(n, "\\", "/"))
	n = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/|?*`, r) {
			return '_'
		}
		return r
	}, n)
	n = strings.TrimRight(n, ". ")
	if len(n) > 200 {
		n = n[len(n)-200:]
	}
	if n == "" || n == "." || n == ".." {
		return "file"
	}
	return n
}
