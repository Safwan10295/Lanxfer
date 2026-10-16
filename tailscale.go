package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// lanxfer joins the user's Tailscale network by itself (tsnet), so the
// laptop doesn't need the Tailscale app running. Phones and other computers
// on the tailnet reach it from anywhere: the phone page on port 443 with a
// real certificate, and computer-to-computer transfers on defaultPCPort.

// tsDial reaches Tailscale addresses through lanxfer's own Tailscale
// connection; nil when that isn't running.
var tsDial func(ctx context.Context, network, addr string) (net.Conn, error)

func dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if tsDial != nil && isTailscale(addr) {
		return tsDial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

type remote struct {
	hub    *Hub
	sender *Sender
	srv    *tsnet.Server
	lc     *local.Client

	mu      sync.Mutex
	authURL string
}

// start brings up lanxfer's Tailscale node and its listeners.
func (rm *remote) start(ctx context.Context, name string, phone http.Handler, recv *Receiver) {
	rm.set("starting", "Connecting to Tailscale…", "")
	rm.srv = &tsnet.Server{
		Dir:      filepath.Join(configDir(), "tailscale"),
		Hostname: name,
		Logf:     func(string, ...any) {},
	}
	if err := rm.srv.Start(); err != nil {
		rm.set("off", "Tailscale couldn't start: "+err.Error(), "")
		return
	}
	context.AfterFunc(ctx, func() { rm.srv.Close() })
	lc, err := rm.srv.LocalClient()
	if err != nil {
		rm.set("off", "Tailscale couldn't start: "+err.Error(), "")
		return
	}
	rm.lc = lc
	tsDial = rm.srv.Dial

	go func() {
		ln, err := rm.srv.ListenTLS("tcp", ":443")
		if err != nil {
			logf("tailscale: phone page: %v", err)
			return
		}
		srv := &http.Server{Handler: phone, ErrorLog: quietLog}
		context.AfterFunc(ctx, func() { srv.Close() })
		srv.Serve(ln)
	}()
	go func() {
		ln, err := rm.srv.Listen("tcp", fmt.Sprintf(":%d", defaultPCPort))
		if err != nil {
			logf("tailscale: computer port: %v", err)
			return
		}
		recv.serveOn(ln)
	}()
	go rm.watch(ctx)
}

func (rm *remote) set(state, hint, url string) {
	rm.hub.mu.Lock()
	rm.hub.ts, rm.hub.tsHint, rm.hub.remoteURL = state, hint, url
	rm.hub.mu.Unlock()
}

// login returns the sign-in link while the node needs one.
func (rm *remote) login() string {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.authURL
}

func (rm *remote) watch(ctx context.Context) {
	for {
		rm.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (rm *remote) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := rm.lc.Status(ctx)
	if err != nil {
		return
	}
	rm.mu.Lock()
	rm.authURL = st.AuthURL
	rm.mu.Unlock()
	switch st.BackendState {
	case "Running":
	case "NeedsLogin":
		if st.AuthURL == "" {
			// Ask for a sign-in link; it shows up in the next status.
			rm.lc.StartLoginInteractive(ctx)
		}
		rm.set("login", "Connect lanxfer to your Tailscale account once to use it from anywhere.", "")
		return
	case "NeedsMachineAuth":
		rm.set("off", "Approve this device in the Tailscale admin console.", "")
		return
	default:
		rm.set("starting", "Connecting to Tailscale…", "")
		return
	}

	domain := strings.TrimSuffix(st.Self.DNSName, ".")
	if len(st.CertDomains) > 0 && domain != "" {
		rm.set("https", "Works anywhere your phone has Tailscale on. Open the link on the phone, then Share → Add to Home Screen.", "https://"+domain)
	} else {
		rm.set("on", "Works anywhere your phone has Tailscale on. Turn on HTTPS Certificates in the Tailscale admin console (DNS page) to install it as an app.", "")
	}
	rm.findComputers(ctx, st)
}

// findComputers asks every online computer on the tailnet whether lanxfer
// is running on the usual port, since mDNS doesn't cross Tailscale.
func (rm *remote) findComputers(ctx context.Context, st *ipnstate.Status) {
	var wg sync.WaitGroup
	for _, n := range st.Peer {
		if !n.Online || n.OS == "iOS" || n.OS == "android" || len(n.TailscaleIPs) == 0 {
			continue
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, fmt.Sprint(defaultPCPort))
			if name, err := probe(ctx, addr); err == nil {
				rm.sender.addPeer(Peer{Name: name, Addrs: []string{addr}})
			}
		}(n.TailscaleIPs[0].String())
	}
	wg.Wait()
}

// probe asks a lanxfer receiver for its name.
func probe(ctx context.Context, addr string) (string, error) {
	c, err := dial(ctx, addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(append([]byte(magic), connPing)); err != nil {
		return "", err
	}
	name, err := readBlob(c)
	if err != nil {
		return "", err
	}
	if len(name) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	return string(name), nil
}
