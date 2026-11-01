#!/usr/bin/env bash
# fido-watch — report which process asks a FIDO2/U2F security key for a touch.

set -uo pipefail

usage() {
  cat <<'EOF'
fido-watch — report which process asks a FIDO2/U2F security key for a touch.

Usage: fido-watch.sh [options]

  --list         list FIDO tokens currently plugged in, then exit
  --install      install and start the systemd service, then exit
  --no-notify    no desktop popups (terminal and journal only)
  --user NAME    desktop user to notify (default: the user who ran sudo)
  --tracepoint   force the syscall tracer instead of the hidraw kprobe
  -h, --help     this text

Needs bpftrace; elevates itself through sudo or doas. See README.md.
EOF
}

# device model

# 0 = FIDO token, 1 = not a token, 2 = cannot tell (descriptor unreadable)
is_fido() { # $1 = /dev/hidrawN
  local rd=/sys/class/hidraw/${1##*/}/device/report_descriptor
  # udev's fido_id helper parses the descriptor properly; trust it first
  if udevadm info -q property -n "$1" 2>/dev/null | grep -qxF 'ID_FIDO_TOKEN=1'; then
    return 0
  fi
  [ -r "$rd" ] || return 2
  # usage page 0xF1D0 followed by FIDO usage 0x01 (06 D0 F1 09 01); -F because a byte pattern must not be parsed as a regex
  LC_ALL=C grep -qaF $'\x06\xd0\xf1\x09\x01' "$rd" && return 0
  return 1
}

fido_devs() {
  local h
  for h in /sys/class/hidraw/hidraw*; do
    [ -e "$h" ] || continue
    is_fido "/dev/${h##*/}" && printf '/dev/%s\n' "${h##*/}"
  done
}

dev_name() { sed -n 's/^HID_NAME=//p' "/sys/class/hidraw/${1##*/}/device/uevent" 2>/dev/null; }

# text safety

# comm and exe paths are process controlled: strip control characters so a crafted name cannot
# inject lines or terminal escapes into the output.
sanitize() { LC_ALL=C tr -d '\000-\037\177' <<<"$1"; }

# options

NOTIFY=1
LIST=0
TARGET_USER=
FORCE_TP=0
INSTALL=0
DEDUP=${DEDUP:-2} # seconds; collapses one auth's packet burst

while [ $# -gt 0 ]; do
  case "$1" in
    --list)       LIST=1 ;;
    --no-notify)  NOTIFY=0 ;;
    --user)       TARGET_USER=${2:?--user needs a name}; shift ;;
    --tracepoint) FORCE_TP=1 ;;
    --install)    INSTALL=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            printf 'unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$LIST" = 1 ]; then
  found=0 unknown=0 d=
  for h in /sys/class/hidraw/hidraw*; do
    [ -e "$h" ] || continue
    d=/dev/${h##*/}
    is_fido "$d"; rc=$?
    case "$rc" in
      0) printf '%-14s %s\n' "$d" "$(dev_name "$d")"; found=1 ;;
      2) unknown=1 ;;
    esac
  done
  if [ "$found" = 0 ] && [ "$unknown" = 1 ]; then
    echo 'cannot read device descriptors as this user; try: sudo ./fido-watch.sh --list'
  elif [ "$found" = 0 ]; then
    echo 'no FIDO token detected'
  elif [ "$unknown" = 1 ]; then
    echo '(some devices could not be inspected; sudo gives a complete list)'
  fi
  exit 0
fi

# install

# Writes the copy under /usr/local/bin and a root system unit, so the service
# needs no sudo rule of its own. --user tells it whose session to notify.
if [ "$INSTALL" = 1 ]; then
  if [ "$EUID" -ne 0 ]; then
    self=$(readlink -f -- "$0")
    args=(--install)
    [ -n "$TARGET_USER" ] && args+=(--user "$TARGET_USER")
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -- "$self" "${args[@]}"
    elif command -v doas >/dev/null 2>&1; then
      exec doas "$self" "${args[@]}"
    else
      echo 'installing needs root: install sudo or doas, or run as root' >&2
      exit 1
    fi
  fi

  as_user=${TARGET_USER:-${SUDO_USER:-${DOAS_USER:-}}}
  [ -d /run/systemd/system ] || { echo 'systemd is not running here' >&2; exit 1; }
  command -v systemctl >/dev/null 2>&1 || { echo 'systemctl not found' >&2; exit 1; }
  if [ -z "$as_user" ]; then
    echo 'cannot tell whose session to notify; rerun with --user NAME' >&2
    exit 1
  fi
  case "$as_user" in
    *[!A-Za-z0-9._-]*|'') echo "unusable user name: $as_user" >&2; exit 1 ;;
  esac
  id -u "$as_user" >/dev/null 2>&1 || { echo "no such user: $as_user" >&2; exit 1; }
  if [ "$(id -u "$as_user")" -eq 0 ]; then
    echo "refusing to notify root; pass --user NAME" >&2
    exit 1
  fi

  src=$(readlink -f -- "$0")
  dest=/usr/local/bin/fido-watch.sh
  if [ "$src" != "$dest" ]; then
    install -o root -g root -m 755 -- "$src" "$dest" || exit 1
  fi

  unit=/etc/systemd/system/fido-watch.service
  cat >"$unit" <<EOF || { echo "cannot write $unit" >&2; exit 1; }
[Unit]
Description=Notify which process uses the FIDO2 key

[Service]
ExecStart=$dest --user $as_user
Restart=on-failure
StartLimitBurst=5

[Install]
WantedBy=graphical.target
EOF
  chmod 644 "$unit"

  systemctl daemon-reload
  systemctl enable fido-watch.service >/dev/null 2>&1
  if systemctl restart fido-watch.service; then
    printf 'installed %s\n' "$dest"
    printf 'unit      %s (notifying %s)\n' "$unit" "$as_user"
    printf 'follow    journalctl -t fido-watch -f\n'
  else
    printf 'unit written, but it failed to start:\n' >&2
    systemctl --no-pager --lines=0 status fido-watch.service >&2
    exit 1
  fi
  exit 0
fi

command -v bpftrace >/dev/null || {
  echo 'bpftrace is not installed. See README.md for install commands' >&2
  exit 1
}

# elevation

# /proc/<pid>/fd is unreadable for other users, so without root the watcher
# would miss every sudo/PAM request. Re-exec once and keep the options.
if [ "$EUID" -ne 0 ]; then
  if [ ! -t 0 ] && ! { command -v sudo >/dev/null && sudo -n true >/dev/null 2>&1; }; then
    echo 'tracing needs root and cannot prompt here. Run this from a terminal' >&2
    exit 1
  fi
  self=$(readlink -f -- "$0")

  args=()
  [ "$NOTIFY" = 0 ] && args+=(--no-notify)
  [ -n "$TARGET_USER" ] && args+=(--user "$TARGET_USER")
  [ "$FORCE_TP" = 1 ] && args+=(--tracepoint)

  if command -v sudo >/dev/null 2>&1; then
    exec sudo -- "$self" ${args+"${args[@]}"}
  elif command -v doas >/dev/null 2>&1; then
    exec doas "$self" ${args+"${args[@]}"}
  else
    echo 'tracing needs root: install sudo or doas, or run as root' >&2
    exit 1
  fi
fi

# output

TARGET_USER=${TARGET_USER:-${SUDO_USER:-${DOAS_USER:-}}}

as_user_cmd() { # $1 user, rest: command
  local u=$1; shift
  if command -v runuser >/dev/null 2>&1; then runuser -u "$u" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo -u "$u" -- "$@"
  else return 1
  fi
}

log_entry() {
  if command -v systemd-cat >/dev/null 2>&1; then
    systemd-cat -t fido-watch printf '%s\n' "$*"
  elif command -v logger >/dev/null 2>&1; then
    logger -t fido-watch "$*"   # /dev/log is journald's socket on systemd hosts
  fi
}

# Routine requesters get a short popup; anything unrecognised stays on screen,
# because that is the case worth interrupting for.
urgency_for() {                   # $1 = program name
  case "$1" in
    sudo|doas|su|login|sshd|ssh|ssh-agent|ssh-add) echo normal ;;
    gdm*|sddm|lightdm|polkit*|systemd-ask*)        echo normal ;;
    chrome|chromium|brave|vivaldi|opera|msedge)    echo normal ;;
    firefox|firefox-bin)                           echo normal ;;
    *)                                             echo critical ;;
  esac
}

notify() { # $1 title, $2 body, $3 urgency (normal|critical)
  if [ "$NOTIFY" = 1 ] && command -v notify-send >/dev/null 2>&1; then
    local uid= bus= urg=${3:-normal} opts
    if [ "$urg" = critical ]; then
      opts=(-u critical)          # no -t: stays until dismissed
    else
      opts=(-u normal -t 6000)    # milliseconds
    fi
    if [ -n "$TARGET_USER" ]; then
      uid=$(id -u "$TARGET_USER" 2>/dev/null) || uid=
      bus=/run/user/${uid:-0}/bus
    fi
    # inherited library paths (snap/AppImage/steam-runtime) break libnotify
    if [ -n "$uid" ] && [ -S "$bus" ]; then
      as_user_cmd "$TARGET_USER" env -u LD_LIBRARY_PATH -u LD_PRELOAD \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" XDG_RUNTIME_DIR="/run/user/$uid" \
        notify-send "${opts[@]}" -a FIDO2 "$1" "$2" >/dev/null 2>&1 || true
    elif [ -z "$TARGET_USER" ]; then
      env -u LD_LIBRARY_PATH -u LD_PRELOAD \
        notify-send "${opts[@]}" -a FIDO2 "$1" "$2" >/dev/null 2>&1 || true
    fi
  fi
  log_entry "$1: $2"
}

# tracing

# Best choke point is inside hidraw itself: every write path (write, pwrite64, writev, io_uring) ends in one of these,
# and the struct file* identifies the device without any /proc lookup afterwards. Falls back to the write syscall
# tracepoint, which is portable but only sees plain write(2) and is noisy.
probe=
if [ "$FORCE_TP" = 0 ]; then
  for fn in hidraw_send_report hidraw_write hidraw_write_iter; do
    if grep -qw "$fn" /proc/kallsyms 2>/dev/null; then probe=$fn; break; fi
  done
fi

if [ -n "$probe" ]; then
  tracer="kprobe:$probe"
  if [ "$probe" = hidraw_write_iter ]; then
    prog=$(printf '%s\n' "kprobe:$probe" '{' \
      '  $f = ((struct kiocb *)arg0)->ki_filp;' \
      '  printf("FW\t%d\t%s\t%d\t%s\n", pid, str($f->f_path.dentry->d_name.name), $f->f_inode->i_ino, comm);' \
      '}')
  else
    prog=$(printf '%s\n' "kprobe:$probe" '{' \
      '  $f = (struct file *)arg0;' \
      '  printf("FW\t%d\t%s\t%d\t%s\n", pid, str($f->f_path.dentry->d_name.name), $f->f_inode->i_ino, comm);' \
      '}')
  fi
else
  tracer='tracepoint:sys_enter_write (fallback)'
  prog='tracepoint:syscalls:sys_enter_write
/ args->count >= 63 && args->count <= 65 /
{
  printf("FW\t%d\t@%d\t0\t%s\n", pid, args->fd, comm);
}'
fi

printf 'Watching FIDO token requests via %s.\n' "$tracer"
while IFS= read -r d; do printf '  token: %s (%s)\n' "$d" "$(dev_name "$d")"; done < <(fido_devs)
printf 'Ctrl+C to stop.\n\n'

stdbuf -oL bpftrace -q -e "$prog" | {
  declare -A kind=()
  last=''; last_ts=0

  while IFS=$'\t' read -r tag pid dev ino comm; do
    # comm is untrusted bytes: it is emitted last so embedded tabs cannot shift
    # the fields, and a newline-split fragment lacks the record tag
    [ "$tag" = FW ] || continue
    case "$pid" in ''|*[!0-9]*) continue ;; esac

    case "$dev" in
      hidraw[0-9]*) target=/dev/$dev ;;
      @*)       # tracepoint path: the fd still has to be resolved through /proc
        target=$(readlink "/proc/$pid/fd/${dev#@}" 2>/dev/null) || continue
        case "$target" in /dev/hidraw*) ;; *) continue ;; esac
        ino=$(stat -c %i "$target" 2>/dev/null || echo -)
        ;;
      *) continue ;;
    esac

    # cached per node+inode so a node reused after a replug is re-checked
    key="$target:$ino"
    if [ -z "${kind[$key]+x}" ]; then
      if is_fido "$target"; then kind[$key]=1; else kind[$key]=0; fi
    fi
    [ "${kind[$key]}" = 1 ] || continue

    now=$(date +%s)
    # one authentication sends several packets; collapse the burst per process
    # and device, so two different requests still both get reported
    if [ "$pid:$target" = "$last" ] && [ $((now - last_ts)) -lt "$DEDUP" ]; then
      last_ts=$now; continue
    fi
    last="$pid:$target"; last_ts=$now

    comm=$(sanitize "$comm")
    exe=$(sanitize "$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo '?')")
    line=$(printf '%s  %-14s pid %-7s %-45s %s' \
              "$(date '+%F %T')" "$comm" "$pid" "$exe" "$target")

    printf '%s\n' "$line"
    prog=${exe##*/}
    [ "$prog" = '?' ] && prog=$comm
    notify "Security key request" "$comm (pid $pid)"$'\n'"$exe"$'\n'"$target" \
           "$(urgency_for "$prog")"
  done
}

# the loop ends here whenever the tracer does; say so instead of exiting quietly
rc=${PIPESTATUS[0]}
case "$rc" in
  0|130|143) printf 'Watcher stopped.\n' ;;
  *) printf 'Watcher stopped: bpftrace exited %s — nothing was watched after that point.\n' "$rc" >&2
     [ -n "$probe" ] && printf 'If it failed on startup, retry with --tracepoint.\n' >&2
     log_entry "watcher stopped abnormally: bpftrace exit $rc"
     exit 1 ;;
esac
