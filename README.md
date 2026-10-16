# lanxfer

[![test](https://github.com/Safwan10295/Lanxfer/actions/workflows/test.yml/badge.svg)](https://github.com/Safwan10295/Lanxfer/actions/workflows/test.yml)

Fast, encrypted file transfer between your computers and your phone, at
home on Wi-Fi or from anywhere through Tailscale. One small Go program, no
cloud storage, no accounts on someone else's server.

- **Computer ↔ computer**: discovered automatically on the network (mDNS),
  paired with a 6-digit code, files sent in chunks over parallel TCP
  connections, checked with SHA-256, resumable after a dropped connection.
- **Phone ↔ computer**: the phone opens a page served by the computer and can
  be added to the home screen as an app. Upload photos and files, download
  whatever the computer sends.
- **From anywhere**: lanxfer joins your [Tailscale](https://tailscale.com)
  network by itself (no Tailscale app needed on the computer), with a real
  HTTPS certificate for the phone.
- **Windows app**: its own window, a tray icon that keeps it receiving in
  the background, and an optional start-with-Windows switch.

## How it works

**Pairing.** The receiver shows a random 6-digit code. The code is never
used as a key directly (a 6-digit code could be brute-forced offline from
recorded traffic). Instead both sides run [CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/),
a password-authenticated key exchange, which turns the short code into a
strong shared key and gives an attacker one guess per attempt. The receiver
allows one pairing at a time and locks out for longer after each wrong code.

**Transfer.** Each direction of each connection gets its own AES-256-GCM key
derived from the session key with HKDF. Files are split into 1 MiB chunks
handed out to several TCP connections. The receiver writes chunks into a
`.part` file and records which ones it has in a small sidecar file, so an
interrupted transfer resumes where it stopped. When everything has arrived,
the receiver checks the whole file against the sender's SHA-256 before
moving it into place.

**Phone.** Browsers can't open raw TCP connections, so the computer serves
an HTTPS page. Uploads go in 4 MiB chunks, each checked with SHA-256, and
resume the same way. On the local network the page uses a self-signed
certificate; through Tailscale it gets a real one, which is what lets an
iPhone install it as a home-screen app.

## Using it

**Windows:** download `lanxfer.exe` from the [latest release](https://github.com/Safwan10295/Lanxfer/releases/latest), and double-click it. To get Start menu and desktop shortcuts, run `lanxfer.exe install` once from a terminal.

**Build it yourself** (Go 1.27 or newer):

```
go build -o lanxfer.exe .
```

or install straight from GitHub:

```
go install github.com/Safwan10295/Lanxfer@latest
```

Then:

| Command | What it does |
|---|---|
| `lanxfer` | Opens the app: receive from and send to phones and computers |
| `lanxfer install` | Windows: copies itself to `%LOCALAPPDATA%\lanxfer` and adds Start menu and desktop shortcuts |
| `lanxfer receive` | Terminal-only receiver; prints a pairing code |
| `lanxfer send FILE...` | Terminal-only sender; finds receivers on the network and asks for the code |

Received files go to your Downloads folder (change it with `-dir`). Run any
command with `-h` for its flags.

### Phone setup

1. Start lanxfer on the computer and scan the QR code in its window with
   the phone's camera.
2. Enter the pairing code once. The phone stays paired.
3. Share → Add to Home Screen.

On the same Wi-Fi this works straight away (accept the certificate warning
the first time). To use it from anywhere, click **Connect to Tailscale** in
the lanxfer window once, and install the Tailscale app on the phone with the
same account. Turn on MagicDNS and HTTPS Certificates in the Tailscale admin
console so the phone gets a trusted certificate.

## Project layout

| File | |
|---|---|
| `proto.go` | Wire protocol, CPace pairing, encrypted record framing |
| `receive.go` | Receiver: lockout, `.part` files, resume, verification |
| `send.go` | Sender: chunk queue over parallel connections, send list |
| `discovery.go` | mDNS advertising and browsing |
| `phone.go` | HTTPS server and API for the phone page |
| `tailscale.go` | Built-in Tailscale node (tsnet), finding computers on the tailnet |
| `web.go`, `hub.go` | The app window's local server and live state |
| `desktop_windows.go` | Native window (WebView2), tray icon, shortcuts |
| `web/` | The app page and the phone page |
| `transfer_test.go` | End-to-end tests on localhost: transfer, wrong code, resume, phone API |

Run the tests with `go test ./...`.

## Limits

- The computer has to be on and awake to send or receive.
- No folders, only files.
- The phone page works in any modern mobile browser; it has mostly been
  used with iPhone Safari.
- On the local network the phone page uses a self-signed certificate, so
  someone actively intercepting traffic on that Wi-Fi at the moment you
  accept the warning could get in the middle. Through Tailscale this
  doesn't apply.

## License

Public domain ([The Unlicense](LICENSE)): do whatever you like with it.
