package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startReceiver(t *testing.T) (*Receiver, []string) {
	t.Helper()
	r, err := newReceiver(t.TempDir(), "127.0.0.1:0", &Hub{})
	if err != nil {
		t.Fatal(err)
	}
	go r.serve()
	t.Cleanup(func() { r.ln.Close() })
	return r, []string{r.ln.Addr().String()}
}

func queueFile(t *testing.T, s *Sender, name string, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	rand.Read(data)
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.addPath(p); err != nil {
		t.Fatal(err)
	}
	return data
}

func checkFile(t *testing.T, r *Receiver, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: content differs", name)
	}
}

func TestTransfer(t *testing.T) {
	r, addrs := startReceiver(t)
	s := newSender(&Hub{}, 4)
	big := queueFile(t, s, "big.bin", 9<<20+12345)
	small := queueFile(t, s, "small.txt", 100)
	empty := queueFile(t, s, "empty", 0)

	if err := s.send(context.Background(), addrs, r.code); err != nil {
		t.Fatal(err)
	}
	checkFile(t, r, "big.bin", big)
	checkFile(t, r, "small.txt", small)
	checkFile(t, r, "empty", empty)

	left, _ := filepath.Glob(filepath.Join(r.dir, "*.part*"))
	if len(left) != 0 {
		t.Fatalf("leftover partial files: %v", left)
	}
}

func TestWrongCode(t *testing.T) {
	r, addrs := startReceiver(t)
	wrong := "000000"
	if r.code == wrong {
		wrong = "000001"
	}
	s := newSender(&Hub{}, 2)
	data := queueFile(t, s, "f.bin", 300_000)

	err := s.send(context.Background(), addrs, wrong)
	if err == nil || !strings.Contains(err.Error(), "wrong code") {
		t.Fatalf("want pairing failure, got %v", err)
	}
	// A failed attempt locks the receiver briefly, even for the right code.
	if err := s.send(context.Background(), addrs, r.code); !errors.Is(err, errBusy) {
		t.Fatalf("want lockout, got %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := s.send(context.Background(), addrs, r.code); err != nil {
		t.Fatal(err)
	}
	checkFile(t, r, "f.bin", data)
}

func TestResume(t *testing.T) {
	r, addrs := startReceiver(t)
	s := newSender(&Hub{}, 3)
	const size = 20<<20 + 7
	data := queueFile(t, s, "movie.bin", size)

	// Cut the first attempt off after 8 chunks.
	var sent atomic.Int64
	chunkHook = func() error {
		if sent.Add(1) >= 8 {
			time.Sleep(200 * time.Millisecond) // let the receiver write what was sent
			return errors.New("cable pulled")
		}
		return nil
	}
	err := s.send(context.Background(), addrs, r.code)
	chunkHook = nil
	if err == nil {
		t.Fatal("first attempt should have failed")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "movie.bin")); err == nil {
		t.Fatal("file was finalized despite the interruption")
	}

	// The receiver notices the dropped session asynchronously; wait for it
	// to record what it has.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m, _ := filepath.Glob(filepath.Join(r.dir, "movie.bin.*.part.json")); len(m) == 1 {
			r.mu.Lock()
			n := len(r.sessions)
			r.mu.Unlock()
			if n == 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("receiver never saved resume state")
		}
		time.Sleep(20 * time.Millisecond)
	}

	before := s.hub.total.Load()
	if err := s.send(context.Background(), addrs, r.code); err != nil {
		t.Fatal(err)
	}
	resent := s.hub.total.Load() - before
	if resent >= size || resent == 0 {
		t.Fatalf("second attempt sent %d of %d bytes; expected a partial resend", resent, size)
	}
	t.Logf("resumed: second attempt sent %d of %d bytes", resent, size)
	checkFile(t, r, "movie.bin", data)
}

func TestPhone(t *testing.T) {
	hub := &Hub{name: "pc"}
	s := newSender(hub, 1)
	p, err := newPhone(t.TempDir(), newCode(), hub, s.files)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.close)
	srv := httptest.NewTLSServer(p.handler(false))
	t.Cleanup(srv.Close)
	c := srv.Client()
	c.Jar, _ = cookiejar.New(nil)

	do := func(method, path string, body []byte, hdr ...string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}

	// Nothing works before pairing, and a wrong code locks pairing briefly.
	if code, _ := do("GET", "/api/state", nil); code != 401 {
		t.Fatalf("unpaired state: got %d", code)
	}
	wrong := "000000"
	if p.code == wrong {
		wrong = "000001"
	}
	if code, _ := do("POST", "/api/pair", []byte(`{"code":"`+wrong+`"}`)); code != 403 {
		t.Fatalf("wrong code: got %d", code)
	}
	if code, _ := do("POST", "/api/pair", []byte(`{"code":"`+p.code+`"}`)); code != 429 {
		t.Fatalf("lockout: got %d", code)
	}
	time.Sleep(1100 * time.Millisecond)
	if code, _ := do("POST", "/api/pair", []byte(`{"code":"`+p.code+`"}`)); code != 200 {
		t.Fatalf("pair: got %d", code)
	}

	// Upload a file but "lose the connection" before the last chunk.
	data := make([]byte, 2*phoneChunk+999)
	rand.Read(data)
	startBody := []byte(fmt.Sprintf(`{"name":"IMG_0001.mov","size":%d,"mtime":1700000000000}`, len(data)))
	var st struct {
		ID    string
		Chunk int
		Have  []byte
	}
	start := func() {
		t.Helper()
		code, b := do("POST", "/api/up/start", startBody)
		if code != 200 || json.Unmarshal(b, &st) != nil {
			t.Fatalf("start: %d %s", code, b)
		}
	}
	put := func(idx int, corrupt bool) int {
		t.Helper()
		part := data[idx*st.Chunk : min(len(data), (idx+1)*st.Chunk)]
		sum := sha256.Sum256(part)
		if corrupt {
			part = append([]byte{part[0] ^ 1}, part[1:]...)
		}
		code, _ := do("PUT", fmt.Sprintf("/api/up/chunk?id=%s&idx=%d", st.ID, idx), part, "X-SHA256", hex.EncodeToString(sum[:]))
		return code
	}
	start()
	if put(0, false) != 204 || put(1, false) != 204 {
		t.Fatal("chunk upload failed")
	}
	if put(2, true) != 422 {
		t.Fatal("corrupted chunk was accepted")
	}
	if code, _ := do("POST", "/api/up/finish?id="+st.ID, nil); code != 409 {
		t.Fatalf("finish of incomplete upload: got %d", code)
	}

	// Restart lanxfer: a new Phone on the same directory must pick up the
	// two chunks already on disk.
	p.close()
	p.uploads = map[string]*rfile{}
	start()
	if len(st.Have) != 1 || st.Have[0] != 0b011 {
		t.Fatalf("resume bitmap = %v, want chunks 0 and 1", st.Have)
	}
	if put(2, false) != 204 {
		t.Fatal("last chunk failed")
	}
	if code, _ := do("POST", "/api/up/finish?id="+st.ID, nil); code != 204 {
		t.Fatalf("finish: got %d", code)
	}
	got, err := os.ReadFile(filepath.Join(p.dir, "IMG_0001.mov"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("uploaded file differs (%v)", err)
	}

	// Computer -> phone, including a ranged (resumed) download.
	src := filepath.Join(t.TempDir(), "report.pdf")
	os.WriteFile(src, data[:5000], 0o644)
	if err := s.addPath(src); err != nil {
		t.Fatal(err)
	}
	var state struct{ Files []struct{ ID string } }
	_, b := do("GET", "/api/state", nil)
	if json.Unmarshal(b, &state) != nil || len(state.Files) != 1 {
		t.Fatalf("state: %s", b)
	}
	if code, b := do("GET", "/dl/"+state.Files[0].ID, nil); code != 200 || !bytes.Equal(b, data[:5000]) {
		t.Fatalf("download: %d", code)
	}
	if code, b := do("GET", "/dl/"+state.Files[0].ID, nil, "Range", "bytes=4000-"); code != 206 || !bytes.Equal(b, data[4000:5000]) {
		t.Fatalf("ranged download: %d", code)
	}
}
