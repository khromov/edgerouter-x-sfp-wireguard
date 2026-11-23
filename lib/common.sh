# Shared by install.sh and device.sh (macOS bash 3.2): logging, prompts, local
# settings, and one SSH connection to the router that every step reuses.
# The caller sets REPO_DIR and runs start_log before anything else.

DEFAULT_HOST="192.168.10.1"
DEFAULT_USER="ubnt"
REMOTE_DIR="/tmp/erx-wg"
LOCAL_CONF="$REPO_DIR/local.conf"     # gitignored: holds the endpoint hostname
CLIENTS="$REPO_DIR/clients"           # gitignored: device configs with private keys
LOG="(none)"

ts()   { date +%H:%M:%S; }
step() { printf '\n[%s] ==> %s\n' "$(ts)" "$*"; }
info() { printf '[%s]     %s\n' "$(ts)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(ts)" "$*"; }
die()  { printf '[%s] ERROR: %s\n' "$(ts)" "$*" >&2; exit 1; }

# Everything printed from here on is also written to logs/. Secrets (device
# private keys, QR codes) are printed straight to /dev/tty and never logged.
start_log() {
    mkdir -p "$REPO_DIR/logs"
    LOG="$REPO_DIR/logs/$(date +%Y%m%d-%H%M%S)-$1.log"
    exec > >(tee -a "$LOG") 2>&1
}

# ask <question> <default> [hidden]
ask() {
    local question=$1 default=$2 hidden=${3:-} answer=""
    if ! ( : < /dev/tty ) 2>/dev/null; then
        die "no terminal to prompt on: run this from a terminal"
    fi
    if [ -n "$hidden" ]; then
        read -r -s -p "$question: " answer < /dev/tty
        echo >&2
    elif [ -n "$default" ]; then
        read -r -p "$question [$default]: " answer < /dev/tty
    else
        read -r -p "$question: " answer < /dev/tty
    fi
    printf '%s' "${answer:-$default}"
}

local_setting() { # local_setting <NAME>
    [ -f "$LOCAL_CONF" ] || return 0
    sed -n "s/^$1='\(.*\)'\$/\1/p" "$LOCAL_CONF" | tail -1
}

save_local_setting() { # save_local_setting <NAME> <value>
    local tmp="$LOCAL_CONF.tmp"
    { echo "# Local settings for this repo (gitignored)."
      if [ -f "$LOCAL_CONF" ]; then grep -v -e '^#' -e "^$1=" "$LOCAL_CONF" || true; fi
      echo "$1='$2'"; } > "$tmp"
    mv -f "$tmp" "$LOCAL_CONF"
}

WORK=$(mktemp -d /tmp/erx-wg.XXXXXX)   # short path: the SSH control socket must fit in 104 bytes
SSH_OPTS=(-o "ControlPath=$WORK/ssh.sock" -o StrictHostKeyChecking=accept-new
          -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
CONNECTED=no
TARGET=""
ROOT_MODE=""
PASSWORD=""

rssh()    { ssh "${SSH_OPTS[@]}" -o ControlMaster=no -o BatchMode=yes -n "$TARGET" "$@"; }
rssh_in() { ssh "${SSH_OPTS[@]}" -o ControlMaster=no -o BatchMode=yes "$TARGET" "$@"; }

cleanup() {
    local rc=$?
    if [ "$CONNECTED" = yes ]; then
        rssh "rm -rf $REMOTE_DIR" >/dev/null 2>&1 || true
        ssh "${SSH_OPTS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
    if [ "$LOG" = "(none)" ]; then
        exit "$rc"
    elif [ "$rc" -eq 0 ]; then
        step "Finished. Log: $LOG"
    else
        printf '\n[%s] FAILED (exit %s). Log: %s\n' "$(ts)" "$rc" "$LOG"
    fi
    exit "$rc"
}
trap cleanup EXIT

ask_login() {
    step "Router login"
    local answer
    answer=$(ask "EdgeRouter address (use user@address if your admin user is not '$DEFAULT_USER')" "$DEFAULT_HOST")
    case "$answer" in
        *@*) SSH_USER=${answer%@*}; HOST=${answer##*@} ;;
        *)   SSH_USER=$DEFAULT_USER; HOST=$answer ;;
    esac
    [[ $HOST =~ ^[A-Za-z0-9.:-]+$ ]] || die "not a valid address: $HOST"
    [[ $SSH_USER =~ ^[A-Za-z0-9._-]+$ ]] || die "not a valid user name: $SSH_USER"
    TARGET="$SSH_USER@$HOST"
    info "target: $TARGET"
    PASSWORD=$(ask "SSH password for $TARGET" "" hidden)
    [ -n "$PASSWORD" ] || die "no password entered"
    info "password received (not logged)"
}

connect() {
    step "Connecting to $TARGET"
    cat > "$WORK/askpass" <<'EOF'
#!/bin/sh
printf '%s\n' "$ERX_WG_PASSWORD"
EOF
    chmod 700 "$WORK/askpass"
    # One master connection, authenticated once; every later ssh call reuses it.
    if ! ERX_WG_PASSWORD="$PASSWORD" SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force \
        ssh "${SSH_OPTS[@]}" -o ControlMaster=yes -o PubkeyAuthentication=no \
            -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=1 \
            -fN "$TARGET" </dev/null >/dev/null 2>"$WORK/ssh-master.log"; then
        grep -v '^ *$' "$WORK/ssh-master.log" | sed 's/^/      ssh: /' || true
        die "SSH login to $TARGET failed (wrong password? SSH disabled on the router?)"
    fi
    CONNECTED=yes
    info "logged in; all further steps reuse this connection"
    info "router: $(rssh 'uname -n; head -1 /opt/vyatta/etc/version 2>/dev/null' | tr '\n' ' ')"
    if [ "$(rssh id -u)" = 0 ]; then
        ROOT_MODE=root; info "logged in as root"
    elif rssh sudo -n true >/dev/null 2>&1; then
        ROOT_MODE=sudo; info "root access: sudo, no password needed"
    else
        ROOT_MODE=sudo-password; info "root access: sudo with the SSH password"
    fi
}

upload() {
    step "Uploading the router script to $HOST:$REMOTE_DIR"
    COPYFILE_DISABLE=1 tar --format ustar -C "$REPO_DIR/router" -cf - . \
        | rssh_in "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR && tar -C $REMOTE_DIR -xf - && ls -l $REMOTE_DIR" \
        | sed 's/^/      /'
}

# remote root|admin <subcommand> [args]: run the router-side script.
# Arguments must already be validated (no spaces or shell characters).
remote() {
    local as=$1 script="$REMOTE_DIR/erx-wg.sh"
    shift
    step "Router: $* (as $as)"
    case "$as:$ROOT_MODE" in
        admin:*|root:root)  rssh bash "$script" "$@" ;;
        root:sudo)          rssh sudo -n bash "$script" "$@" ;;
        root:sudo-password) printf '%s\n' "$PASSWORD" | rssh_in sudo -S -p "''" bash "$script" "$@" ;;
    esac
}

# result <name> <output>: the value of a "[router] result name=value" line.
result() { printf '%s\n' "$2" | sed -n "s/^\\[router\\] result $1=//p" | tail -1; }

need_tools() {
    local t missing=""
    for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
    [ -z "$missing" ] || die "missing:$missing (install with: brew install wireguard-tools qrencode)"
}
