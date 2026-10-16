// lanxfer sends files between computers and phones on the same network.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const usage = `lanxfer - encrypted file transfer over the local network

  lanxfer                       open the app: send and receive with phones and computers
  lanxfer install               add lanxfer to the Start menu and desktop (Windows)

Terminal only, between two computers:
  lanxfer receive [flags]       wait for files, show a pairing code
  lanxfer send [flags] FILE...  send files

Run "lanxfer app -h", "lanxfer receive -h" or "lanxfer send -h" for flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cmd, args := "app", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "app":
		err = runApp(ctx, args)
	case "receive", "recv":
		err = runReceive(ctx, args)
	case "send":
		err = runSend(ctx, args)
	case "install":
		err = runInstall()
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		logf("error: %v", err)
		os.Exit(1)
	}
}

// defaultDir is where received files go unless -dir says otherwise.
func defaultDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		if d := filepath.Join(home, "Downloads"); isDir(d) {
			return d
		}
	}
	return "."
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// runApp runs everything at once behind one window: it receives from
// computers and phones, and sends to both, on Wi-Fi and over Tailscale.
func runApp(ctx context.Context, args []string) error {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("app", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "directory to save received files in")
	name := fs.String("name", host, "name other computers see")
	port := fs.Int("port", defaultPCPort, "TCP port for computer-to-computer transfers")
	phonePort := fs.Int("phone-port", 7443, "HTTPS port phones connect to")
	uiPort := fs.Int("ui-port", 7410, "port for this computer's own window")
	par := fs.Int("p", 4, "parallel TCP connections when sending to a computer")
	noWindow := fs.Bool("no-window", false, "start in the tray without opening the window")
	fs.Parse(args)
	detachConsole()

	ctx, quit := context.WithCancel(ctx)
	defer quit()
	hub := &Hub{name: *name}
	s := newSender(hub, *par)
	s.self = *name
	d := newDesktop(fmt.Sprintf("http://127.0.0.1:%d", *uiPort), quit)
	rm := &remote{hub: hub, sender: s}

	ui, err := serveUI(ctx, *uiPort, hub, s, quit, d.show, rm.login)
	if err != nil {
		// The port is taken, most likely by lanxfer itself: ask it to show
		// its window.
		c := http.Client{Timeout: 2 * time.Second}
		if res, perr := c.Post(d.url+"/api/show", "", nil); perr == nil {
			res.Body.Close()
			fmt.Println("lanxfer is already running; showing its window.")
			return nil
		}
		return err
	}

	r, err := newReceiver(*dir, fmt.Sprintf(":%d", *port), hub)
	if err != nil {
		// Another program has the usual port; any port still works on
		// Wi-Fi, but computers on Tailscale won't find this one.
		fmt.Printf("port %d is busy (%v); other computers on Tailscale won't find this one\n", *port, err)
		if r, err = newReceiver(*dir, ":0", hub); err != nil {
			return err
		}
	}
	r.name = *name
	if s.tmp, err = os.MkdirTemp("", "lanxfer-"); err != nil {
		return err
	}
	defer os.RemoveAll(s.tmp)
	p, err := newPhone(r.dir, r.code, hub, s.offeredFiles)
	if err != nil {
		return err
	}
	p.fetched = func(f *sendFile) { hub.set(f.prog, "fetched", "") }
	p.remember(filepath.Join(configDir(), "phones.json"))
	defer p.close()
	phoneURL, err := p.serve(ctx, fmt.Sprintf(":%d", *phonePort), "")
	if err != nil {
		fmt.Printf("Phones can't connect: %v\n", err)
	}

	hub.mu.Lock()
	hub.code, hub.dir, hub.url = r.code, r.dir, phoneURL
	hub.mu.Unlock()
	go hub.run()
	go s.discover(ctx)
	go r.serve()
	go rm.start(ctx, *name, p.handler(true), r)
	if stopAd, err := advertise(*name, r.port()); err != nil {
		fmt.Printf("Other computers won't find this one automatically (%v); they can use %s:%d\n", err, host, r.port())
	} else {
		defer stopAd()
	}

	fmt.Printf("lanxfer is running as %q.\n\n", *name)
	fmt.Printf("  App window:   %s\n", ui)
	if phoneURL != "" {
		fmt.Printf("  Phone link:   %s\n", phoneURL)
	}
	fmt.Printf("  Pairing code: %s %s\n", r.code[:3], r.code[3:])
	fmt.Printf("  Saving to:    %s\n", r.dir)
	fmt.Printf("  Direct address, if another computer can't find this one: %s:%d\n\n", host, r.port())
	d.startTray()
	if !*noWindow {
		d.show()
	}
	<-ctx.Done()
	d.close()
	r.ln.Close()
	return nil
}

func runReceive(ctx context.Context, args []string) error {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to save received files in")
	name := fs.String("name", host, "name to advertise on the network")
	port := fs.Int("port", 0, "TCP port for transfers (0 picks a free one)")
	fs.Parse(args)

	hub := &Hub{name: *name}
	r, err := newReceiver(*dir, fmt.Sprintf(":%d", *port), hub)
	if err != nil {
		return err
	}
	go hub.run()

	fmt.Printf("Receiving as %q on port %d, saving to %s\n", *name, r.port(), r.dir)
	if stopAd, err := advertise(*name, r.port()); err != nil {
		fmt.Printf("mDNS advertising failed (%v); senders can still use -to HOST:%d\n", err, r.port())
	} else {
		defer stopAd()
	}
	fmt.Printf("\n  Pairing code: %s %s\n\n", r.code[:3], r.code[3:])

	go func() {
		<-ctx.Done()
		r.ln.Close()
	}()
	if err := r.serve(); ctx.Err() == nil {
		return err
	}
	return nil
}

func runSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "receiver name, or HOST:PORT to skip discovery")
	code := fs.String("code", "", "pairing code shown on the receiver (prompted if empty)")
	par := fs.Int("p", 4, "parallel TCP connections")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("name the files to send, or run lanxfer with no arguments for the app")
	}

	hub := &Hub{}
	s := newSender(hub, *par)
	go hub.run()
	go s.discover(ctx)
	for _, p := range fs.Args() {
		if err := s.addPath(p); err != nil {
			return err
		}
	}
	in := bufio.NewReader(os.Stdin)
	addrs, err := s.choose(ctx, *to, in)
	if err != nil {
		return err
	}
	if *code == "" {
		fmt.Print("Pairing code: ")
		*code, _ = in.ReadString('\n')
	}
	if *code = digits(*code); len(*code) != 6 {
		return errors.New("the pairing code is 6 digits")
	}
	return s.send(ctx, addrs, *code)
}

// choose resolves the -to flag, or waits for discovery and asks when more
// than one receiver is around.
func (s *Sender) choose(ctx context.Context, to string, in *bufio.Reader) ([]string, error) {
	if addrs := s.lookup(to); addrs != nil {
		return addrs, nil
	}
	fmt.Println("Looking for receivers...")
	var peers []Peer
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline) && ctx.Err() == nil; {
		time.Sleep(250 * time.Millisecond)
		if to != "" {
			if addrs := s.lookup(to); addrs != nil {
				return addrs, nil
			}
			continue
		}
		// Give other receivers a moment to answer before settling on one.
		if peers = s.peerList(); len(peers) > 0 && time.Until(deadline) < 4*time.Second {
			break
		}
	}
	switch {
	case to != "":
		return nil, fmt.Errorf("receiver %q not found", to)
	case len(peers) == 0:
		return nil, errors.New("no receivers found; if mDNS is blocked on this network, use -to HOST:PORT")
	case len(peers) == 1:
		fmt.Printf("Found %s\n", peers[0].Name)
		return peers[0].Addrs, nil
	}
	for i, p := range peers {
		fmt.Printf("  %d) %s\n", i+1, p.Name)
	}
	fmt.Print("Send to which receiver? ")
	line, _ := in.ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(peers) {
		return nil, errors.New("no receiver chosen")
	}
	return peers[n-1].Addrs, nil
}
