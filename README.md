# fido-watch

Shows **which program is asking your security key for a touch**, because a blinking LED tells you nothing about who blinked it.

```
14:02:51  sudo           pid 4812    /usr/bin/sudo          (/dev/hidraw0)
14:07:10  chrome         pid 9021    /usr/bin/chrome        (/dev/hidraw0)
```

## Why

Without this, any process on your machine can ask the key for a signature: you see a blink, touch it, and never learn who asked. FIDO2 still needs your touch, so a blink alone is not a compromise but a touch given to the wrong requester is.

This is especially handy if you use your FIDO token for sudo permissions.

## Requirements

- Linux with `bpftrace` and bash 4.1+. It hooks `hidraw_send_report` (or `hidraw_write`) inside the HID driver, and falls back to the `sys_enter_write` tracepoint where that isn't available
- `sudo` or `doas` for the tracing part. It reads `/proc` for other processes, which needs root
- optional: `notify-send` for desktop popups. Every event is also written to the systemd journal — `journalctl -t fido-watch` — or to syslog via `logger` on non-systemd hosts

```sh
sudo pacman -S bpftrace     # Arch
sudo apt install bpftrace   # Debian/Ubuntu
sudo dnf install bpftrace   # Fedora
```

## Use

```sh
./fido-watch.sh            # watch; Ctrl+C to stop
./fido-watch.sh --list     # show detected FIDO keys and exit
```

Then use the key normally: run `sudo`, log in somewhere, use a passkey. Leave it running in a terminal.

## Reading the output

| Program | What it is |
|---|---|
| `sudo`, `login`, `gdm-password` | PAM authentication, which you requested |
| `chrome`, `firefox`, … | a website's WebAuthn/passkey prompt |
| `ssh`, `ssh-agent` | an `sk-ssh-*` key operation |
| anything else | **investigate** what and why |

Known requesters (`sudo`, login managers, polkit, browsers, `ssh`) get a brief popup that clears itself after six seconds. Anything not on that list uses critical urgency, so the notification stays on screen until you dismiss it. The list lives in `urgency_for()`; add to it as you meet programs that should not be sticky.

## Options

| Flag | Effect |
|---|---|
| `--list` | list FIDO tokens currently plugged in |
| `--install` | install and start the systemd service, then exit |
| `--no-notify` | no popups; terminal and journal only |
| `--user NAME` | desktop user to notify (default: the user who ran `sudo`) |
| `--tracepoint` | force the syscall tracer instead of the hidraw kprobe |

## Notes and limits

- **Observes only.** It does not block, prompt or change behaviour.
- **Text is sanitised.** Process names and executable paths come from the process itself, so control characters are stripped before anything is printed, notified or journaled.
- **Any token works.** There are no vendor IDs: the FIDO interface is recognised from the HID report descriptor, so multiple keys and hot-plugging are fine.
- **Some requests are invisible.** Tokens used over NFC or the smart-card/CCID interface go through `pcscd`, not `hidraw`. Those possibly show up as `pcscd`, not as the application.
- **Very short-lived opens may be missed**, though a request that waits for a touch holds the device open and is always caught.
- **Best-effort, not a control.** It observes; it does not enforce. Root or kernel-resident code can evade it, and so can anything that reaches the token by a path that isn't hooked. Treat an empty log as "nothing was noticed", never as "nothing happened".

## Keep it running (optional)

```sh
./fido-watch.sh --install               # notify the user who runs it
./fido-watch.sh --install --user NAME   # notify someone else
```

It copies the script to `/usr/local/bin/fido-watch.sh` (root-owned, mode 755), writes `/etc/systemd/system/fido-watch.service`, enables it for `graphical.target` and starts it. The unit runs as root — that is what tracing needs — and passes `--user`, so popups reach your session; before you log in, events go to the journal only.

```sh
systemctl status fido-watch
journalctl -t fido-watch -f
```

To remove it:

```sh
sudo systemctl disable --now fido-watch
sudo rm /etc/systemd/system/fido-watch.service
sudo systemctl daemon-reload
```

## Troubleshooting

- **`no FIDO token detected`** — is the key plugged in? `./fido-watch.sh --list` and `lsusb` should agree.
- **`cannot read device descriptors as this user`** — sysfs is restricted here; `sudo ./fido-watch.sh --list` sees them.
- **No popup, but terminal lines appear** — no notification daemon, or `notify-send` can't reach your session bus; check `sudo journalctl -t fido-watch`.
- **`tracing needs root and cannot prompt here`** — run it from a real terminal, or use `--install` so it runs as a root service and never needs to elevate.
- **`Watcher stopped: bpftrace exited N`** — the tracer could not attach and nothing was watched. Try `--tracepoint`; if that also fails, check that BPF is permitted (`sudo bpftrace -l 'tracepoint:syscalls:sys_enter_write'`) and that lockdown or a hardened kernel isn't blocking it.
- **`--install` says `cannot tell whose session to notify`** — run it as your normal user (it elevates itself), or pass `--user NAME`.
- **The service is not running after install** — `systemctl status fido-watch` and `journalctl -t fido-watch`; the usual cause is the tracer failing to attach, which the unit reports as a failed start.
- **Nothing at all, but no error either** — confirm the banner names a tracer and a token; if the token list is empty, detection is the problem, not tracing.
