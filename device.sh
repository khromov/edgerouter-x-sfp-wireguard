#!/usr/bin/env bash
#
# Manage WireGuard devices on the EdgeRouter (run ./install.sh first).
#
#   ./device.sh add NAME      add a device; shows its QR code and config
#   ./device.sh show NAME     show a saved device's QR code and config again
#                             (no router login needed)
#   ./device.sh list          devices on the router, with their last handshake
#   ./device.sh remove NAME   remove a device from the router and delete its
#                             saved config
#   ./device.sh debug         watch the router's WAN while a device connects,
#                             to see why it doesn't
#
# Device configs contain the device's private key. They are saved in clients/
# (gitignored, mode 600). QR codes and configs are printed to the terminal
# only, never to the log.

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$REPO_DIR/lib/common.sh"

usage() { sed -n '5,12p' "$0" | sed 's/^# \{0,1\}//'; }

CMD=${1:-}
NAME=${2:-}
case "$CMD" in
    add|show|remove)
        [[ $NAME =~ ^[A-Za-z0-9._-]{1,32}$ ]] || { usage >&2; die "NAME must be 1-32 of A-Z a-z 0-9 . _ -"; } ;;
    list|debug) ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
start_log "device-$CMD${NAME:+-$NAME}"
CONF="$CLIENTS/$NAME.conf"

show_config() {
    [ -f "$CONF" ] || die "no saved config for '$NAME' ($CONF)"
    need_tools qrencode
    info "QR code and config for '$NAME' go to the terminal only (not the log)"
    {
        printf '\nWireGuard app: + > Create from QR code, then scan:\n\n'
        qrencode -t ansiutf8 < "$CONF"
        printf '\n----- %s -----\n' "$CONF"
        cat "$CONF"
        printf -- '-----\n\n'
    } > /dev/tty
}

cmd_add() {
    local endpoint priv pub out address dns port server
    need_tools wg qrencode
    [ ! -e "$CONF" ] || die "$CONF already exists; pick another name or remove the device first"
    endpoint=$(local_setting ENDPOINT)
    [ -n "$endpoint" ] || die "no endpoint saved in $LOCAL_CONF; run ./install.sh first"

    ask_login
    connect
    upload

    step "Generating keys for '$NAME' on this Mac"
    priv=$(wg genkey)
    pub=$(printf '%s\n' "$priv" | wg pubkey)
    info "device public key: $pub (the private key never leaves this Mac and the device)"

    out=$(remote admin add-peer "$NAME" "$pub" | tee /dev/stderr)
    address=$(result address "$out"); dns=$(result dns "$out")
    port=$(result port "$out"); server=$(result server_pubkey "$out")
    if [ -z "$address" ] || [ -z "$dns" ] || [ -z "$port" ] || [ -z "$server" ]; then
        die "the router did not return the device settings"
    fi

    step "Saving $CONF"
    mkdir -p "$CLIENTS"
    chmod 700 "$CLIENTS"
    # Full tunnel. ::/0 sends IPv6 into the tunnel too, where it is dropped, so
    # it cannot leak around the VPN on networks that have IPv6.
    ( umask 077
      cat > "$CONF" <<EOF
[Interface]
PrivateKey = $priv
Address = $address
DNS = $dns

[Peer]
PublicKey = $server
Endpoint = $endpoint:$port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    )
    info "address $address, DNS $dns, endpoint $endpoint:$port, all traffic through the tunnel"
    show_config
    step "Next"
    info "Test on mobile data, not your home Wi-Fi. Then ./device.sh list should show a recent handshake."
}

cmd_remove() {
    local out
    ask_login
    connect
    upload
    out=$(remote admin remove-peer "$NAME" | tee /dev/stderr)
    [ -n "$(result removed "$out")" ] || die "the router did not confirm the removal"
    if [ -f "$CONF" ]; then
        rm -f "$CONF"
        info "deleted $CONF"
    fi
}

cmd_list() {
    local f
    ask_login
    connect
    upload
    remote root status
    step "Saved device configs in $CLIENTS"
    if ls "$CLIENTS"/*.conf >/dev/null 2>&1; then
        for f in "$CLIENTS"/*.conf; do info "$(basename "$f" .conf)"; done
    else
        info "(none)"
    fi
}

cmd_debug() {
    local secs=45
    ask_login
    connect
    upload
    step "Connection test"
    info "On the phone: tunnel OFF. Then, during the ${secs}s capture:"
    info "  1. turn the tunnel ON and wait ~10s"
    info "  2. optional: open http://<endpoint>:51831 in the phone's browser (it won't load;"
    info "     it shows whether any traffic from the phone reaches the router)"
    info "On home Wi-Fi this tests the keys and config; on mobile data it tests the internet path."
    ask "Press Enter to start the capture" "" >/dev/null
    remote root diagnose "$secs"
    step "How to read this"
    info "Source 192.168.10.x = the phone on home Wi-Fi; any other source = from the internet."
    info "No packets at all:     they never reach the router (mobile network, ISP or the endpoint address)."
    info "UDP length 148 in, nothing back: the router ignores them (keys don't match: remove and re-add"
    info "                       the device; or the firewall drops them: see the counter on the 51831 rule)."
    info "148 in and 92 back, but the phone receives nothing: replies don't make it back to the phone."
    info "Only TCP arrives, never UDP: something on the way blocks UDP to this port."
}

case "$CMD" in
    add)    cmd_add ;;
    show)   show_config ;;
    list)   cmd_list ;;
    remove) cmd_remove ;;
    debug)  cmd_debug ;;
esac
