#!/bin/bash
# Router-side half of edgerouter-x-sfp-wireguard (EdgeRouter X SFP, EdgeOS 3,
# which has WireGuard built in). install.sh and device.sh upload this to
# /tmp/erx-wg and run one subcommand at a time:
#
#   check                 WireGuard support, WAN, firewall, NAT, DNS      (root)
#   prepare               state dir + the router's private key            (root)
#   setup                 wg0, firewall rule, NAT, DNS for the tunnel      (admin)
#   status                interface, port, devices with last handshake    (root)
#   add-peer NAME PUBKEY  add a device; prints its tunnel address         (admin)
#   remove-peer NAME      remove a device                                 (admin)
#   diagnose [SECONDS]    watch the WAN for WireGuard packets             (root)
#   uninstall             remove what setup added                         (admin)

set -euo pipefail

WG_IF=wg0
WG_PORT=51831
WG_NET=10.51.83                  # tunnel subnet 10.51.83.0/24; the router is .1
WG_ADDR=$WG_NET.1/24
KEY=/config/auth/$WG_IF.key      # /config survives firmware upgrades
STATE_DIR=/config/erx-wg         # config.boot backups + what setup added
STATE=$STATE_DIR/state
TAG="erx-wg: WireGuard UDP $WG_PORT"   # description on the firewall/NAT rules we add

CFG=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper
API=$(command -v cli-shell-api || echo /bin/cli-shell-api)
TEMPLATES=/opt/vyatta/share/vyatta-cfg/templates/interfaces/wireguard

say()     { printf '[router] %s\n' "$*"; }
warn()    { printf '[router] WARNING: %s\n' "$*"; }
die()     { printf '[router] ERROR: %s\n' "$*"; exit 1; }
section() { printf '[router]\n[router] --- %s\n' "$*"; }
indent()  { sed 's/^/[router]     /'; }
run()     { printf '[router] + %s\n' "$*"; "$@" 2>&1 | indent; return "${PIPESTATUS[0]}"; }
emit()    { printf '[router] result %s=%s\n' "$1" "$2"; }   # read by install.sh/device.sh
need_root() { [ "$(id -u)" = 0 ] || die "$1 must run as root"; }
in_list() { local needle=$1 x; shift; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1; }

# --- Reading the active EdgeOS config ---------------------------------------
# cli-shell-api prints multi-values as 'a' 'b'; callers eval that into arrays.
list_values() { "$API" returnActiveValues "$@" 2>/dev/null || true; }
list_nodes()  { "$API" listActiveNodes "$@" 2>/dev/null || true; }
get_value()   { "$API" returnActiveValue "$@" 2>/dev/null || true; }
cfg_exists()  { "$API" existsActive "$@" 2>/dev/null; }

# The WAN: the one ethernet/vif interface with "address dhcp", or a PPPoE
# session. Sets WAN_PATH (config path), WAN_IF (kernel name), WAN_FW (local
# firewall ruleset name, may be empty).
load_wan() {
    local i v s
    local -a ifs=() vifs=() addrs=() sess=() found=()
    eval "ifs=($(list_nodes interfaces ethernet))"
    for i in "${ifs[@]}"; do
        eval "addrs=($(list_values interfaces ethernet "$i" address))"
        if in_list dhcp "${addrs[@]}"; then found+=("interfaces ethernet $i|$i"); fi
        eval "sess=($(list_nodes interfaces ethernet "$i" pppoe))"
        for s in "${sess[@]}"; do found+=("interfaces ethernet $i pppoe $s|pppoe$s"); done
        eval "vifs=($(list_nodes interfaces ethernet "$i" vif))"
        for v in "${vifs[@]}"; do
            eval "addrs=($(list_values interfaces ethernet "$i" vif "$v" address))"
            if in_list dhcp "${addrs[@]}"; then found+=("interfaces ethernet $i vif $v|$i.$v"); fi
            eval "sess=($(list_nodes interfaces ethernet "$i" vif "$v" pppoe))"
            for s in "${sess[@]}"; do found+=("interfaces ethernet $i vif $v pppoe $s|pppoe$s"); done
        done
    done
    if [ ${#found[@]} -ne 1 ]; then
        die "expected exactly one DHCP or PPPoE WAN interface, found ${#found[@]}: ${found[*]:-none}"
    fi
    WAN_PATH=${found[0]%|*}
    WAN_IF=${found[0]#*|}
    WAN_FW=$(get_value $WAN_PATH firewall local name)
}

# find_tagged_rule <rule list path>: number of the rule whose description is $TAG.
find_tagged_rule() {
    local r
    local -a rules=()
    eval "rules=($(list_nodes $1))"
    for r in "${rules[@]}"; do
        if [ "$(get_value $1 "$r" description)" = "$TAG" ]; then echo "$r"; return 0; fi
    done
    return 1
}

free_rule() { # free_rule <rule list path> <first> <step>
    local n=$2
    while cfg_exists $1 "$n"; do n=$((n + $3)); done
    echo "$n"
}

# A masquerade rule on the WAN with no source filter (or for exactly the
# tunnel subnet) already covers tunnel traffic going to the internet.
nat_covering_tunnel() {
    local r src
    local -a rules=()
    eval "rules=($(list_nodes service nat rule))"
    for r in "${rules[@]}"; do
        if [ "$(get_value service nat rule "$r" type)" != masquerade ]; then continue; fi
        if [ "$(get_value service nat rule "$r" outbound-interface)" != "$WAN_IF" ]; then continue; fi
        src=$(get_value service nat rule "$r" source address)
        if [ -z "$src" ] || [ "$src" = "$WG_NET.0/24" ]; then echo "$r"; return 0; fi
    done
    return 1
}

port_in_spec() { # port_in_spec <port> <spec like 80,443,51000-52000>
    local item lo hi
    for item in ${2//,/ }; do
        case "$item" in
            *-*) lo=${item%-*}; hi=${item#*-}
                 if [[ $lo =~ ^[0-9]+$ && $hi =~ ^[0-9]+$ ]] && [ "$1" -ge "$lo" ] && [ "$1" -le "$hi" ]; then return 0; fi ;;
            *)   if [ "$item" = "$1" ]; then return 0; fi ;;
        esac
    done
    return 1
}

# Port-forwards and destination NAT rewrite packets before the router's own
# firewall sees them, so one covering our port silently steals every WireGuard
# packet. Prints a warning per conflict; sets PORT_CONFLICTS to the count.
check_port_conflicts() {
    local r spec
    local -a rules=()
    PORT_CONFLICTS=0
    eval "rules=($(list_nodes port-forward rule))"
    for r in "${rules[@]}"; do
        spec=$(get_value port-forward rule "$r" original-port)
        if [ -n "$spec" ] && port_in_spec "$WG_PORT" "$spec"; then
            warn "port-forward rule $r sends port $spec to $(get_value port-forward rule "$r" forward-to address) ('$(get_value port-forward rule "$r" description)'), so WireGuard on the router never sees it"
            PORT_CONFLICTS=$((PORT_CONFLICTS + 1))
        fi
    done
    eval "rules=($(list_nodes service nat rule))"
    for r in "${rules[@]}"; do
        if [ "$(get_value service nat rule "$r" type)" != destination ]; then continue; fi
        spec=$(get_value service nat rule "$r" destination port)
        if [ -n "$spec" ] && port_in_spec "$WG_PORT" "$spec"; then
            warn "destination NAT rule $r sends port $spec to $(get_value service nat rule "$r" inside-address address), so WireGuard on the router never sees it"
            PORT_CONFLICTS=$((PORT_CONFLICTS + 1))
        fi
    done
    if [ "$PORT_CONFLICTS" -eq 0 ]; then say "no port-forward or destination NAT rule uses port $WG_PORT"; fi
    return 0
}

# Peers on wg0: sets PEERS (public keys) and USED (their allowed-ips).
load_peers() {
    local p
    local -a ips=()
    PEERS=(); USED=()
    eval "PEERS=($(list_nodes interfaces wireguard $WG_IF peer))"
    for p in "${PEERS[@]}"; do
        eval "ips=($(list_values interfaces wireguard $WG_IF peer "$p" allowed-ips))"
        USED+=("${ips[@]}")
    done
    return 0
}

peer_by_name() { # peer_by_name <name>: prints the public key
    local p
    for p in "${PEERS[@]}"; do
        if [ "$(get_value interfaces wireguard $WG_IF peer "$p" description)" = "$1" ]; then echo "$p"; return 0; fi
    done
    return 1
}

# --- Changing the EdgeOS config -------------------------------------------------
# Config changes need the vyattacfg group, like an interactive "configure"
# session, so re-run this script under it. Arguments are validated beforehand.
as_config_group() {
    if [ "$(id -gn)" = vyattacfg ]; then return 0; fi
    if [ "$(id -u)" != 0 ] && ! id -Gn | tr ' ' '\n' | grep -qx vyattacfg; then
        die "$(id -un) is not an EdgeOS admin user (not in group vyattacfg)"
    fi
    say "re-running as group vyattacfg"
    exec sg vyattacfg -c "/bin/bash $0 $*"
}

# The wrapper keys its session on the parent PID, so it must always be called
# directly from this shell: no pipes, no $(...).
abort_session() { "$CFG" discard || true; "$CFG" end || true; }
apply_cmds() {
    local c
    local -a args
    say "+ configure"
    "$CFG" begin || return 1
    for c in "$@"; do
        eval "args=($c)"
        say "+ $c"
        if ! "$CFG" "${args[@]}"; then abort_session; return 1; fi
    done
    say "+ commit"
    if ! "$CFG" commit; then abort_session; return 1; fi
    say "+ save"
    "$CFG" save || warn "save failed: the change is live but will not survive a reboot"
    "$CFG" end || true
}

save_backup() {
    local b
    b="$STATE_DIR/config.boot.$(date +%Y%m%d-%H%M%S)"
    cp /config/config.boot "$b"
    say "backed up /config/config.boot to $b"
    ls -1t "$STATE_DIR"/config.boot.* | tail -n +6 | xargs -r rm -f   # keep the newest 5
}

validate_name() { [[ ${1:-} =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "device name must be 1-32 of A-Z a-z 0-9 . _ -"; }
validate_key()  { [[ ${1:-} =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || die "not a WireGuard public key: ${1:-}"; }

# --- Subcommands ----------------------------------------------------------------
cmd_check() {
    need_root check
    local problems=0 f rel help r n
    section "System"
    indent < /opt/vyatta/etc/version || true
    say "kernel: $(uname -srm), userland $(dpkg --print-architecture 2>/dev/null || echo unknown)"
    if ! grep -Eq 'v3\.[0-9]' /opt/vyatta/etc/version 2>/dev/null; then
        warn "only EdgeOS 3 is supported"; problems=$((problems + 1))
    fi

    section "WireGuard support"
    if [ -f "$TEMPLATES/node.def" ]; then
        # Only the nodes this script sets; the template also has routing,
        # firewall and QoS options that don't matter here.
        for n in address listen-port private-key description peer/node.tag/allowed-ips peer/node.tag/description; do
            f="$TEMPLATES/node.tag/$n/node.def"
            if [ -f "$f" ]; then
                help=$(sed -n 's/^help:[[:space:]]*//p' "$f" | head -1)
                say "config node ok: ${n//node.tag/<key>}  ($help)"
            else
                warn "missing config node: ${n//node.tag/<key>}"; problems=$((problems + 1))
            fi
        done
    else
        warn "no 'interfaces wireguard' config template in this EdgeOS"; problems=$((problems + 1))
    fi
    if command -v wg >/dev/null 2>&1; then say "wg tool: $(wg --version 2>&1 | head -1)"
    else warn "missing the wg tool"; problems=$((problems + 1)); fi
    if ip link add dev erxwgtest0 type wireguard 2>/dev/null; then
        ip link del dev erxwgtest0
        say "kernel: WireGuard interfaces can be created"
    else
        warn "kernel: cannot create a WireGuard interface"; problems=$((problems + 1))
    fi

    section "WireGuard versions"
    local mver mfile owner
    mver=$(modinfo -F version wireguard 2>/dev/null || true)
    mfile=$(modinfo -n wireguard 2>/dev/null || true)
    say "kernel:         $(uname -r) (built $(uname -v))"
    say "module version: ${mver:-unknown}$([ -r /sys/module/wireguard/version ] && echo " (loaded: $(cat /sys/module/wireguard/version))")"
    say "module file:    ${mfile:-<built into the kernel or missing>}"
    modinfo wireguard 2>/dev/null | grep -E '^(srcversion|vermagic|author):' | indent || true
    if [ -n "$mfile" ] && owner=$(dpkg -S "$mfile" 2>/dev/null); then
        owner=${owner%%:*}
        say "module package: $owner $(dpkg-query -W -f '${Version}' "$owner" 2>/dev/null)"
    fi
    say "packages with 'wireguard' in the name:"
    dpkg-query -W -f '${Package} ${Version}\n' 2>/dev/null | grep -i wireguard | indent || say "    (none)"
    dmesg 2>/dev/null | grep -i wireguard | tail -n 3 | indent || true
    emit kernel "$(uname -r)"
    emit module_version "$mver"
    emit tools_version "$(wg --version 2>/dev/null | sed -n 's/^wireguard-tools v\([^ ]*\).*/\1/p')"

    section "Existing WireGuard interfaces"
    local -a wgs=()
    eval "wgs=($(list_nodes interfaces wireguard))"
    if [ ${#wgs[@]} -eq 0 ]; then say "(none)"; fi
    for n in "${wgs[@]}"; do
        say "$n: address $(list_values interfaces wireguard "$n" address), port $(get_value interfaces wireguard "$n" listen-port), $(list_nodes interfaces wireguard "$n" peer | wc -w) peer(s)"
    done
    if [ -f "$STATE" ]; then say "set up by this script; state:"; indent < "$STATE"; fi

    section "WAN"
    load_wan
    say "config path: $WAN_PATH (kernel interface $WAN_IF)"
    ip -4 -o addr show dev "$WAN_IF" | awk '{print $4}' | indent || true
    emit wan_ip "$(ip -4 -o addr show dev "$WAN_IF" | awk '{split($4, a, "/"); print a[1]; exit}')"
    case "$(ip -4 -o addr show dev "$WAN_IF")" in
        *" 100.6"[4-9]"."*|*" 100."[7-9][0-9]"."*|*" 100.1"[01][0-9]"."*|*" 100.12"[0-7]"."*)
            warn "the WAN address is carrier-grade NAT (100.64.0.0/10): devices cannot reach the router from outside" ;;
    esac

    section "Firewall on traffic to the router from the WAN"
    if [ -z "$WAN_FW" ]; then
        warn "$WAN_PATH has no 'firewall local' ruleset, so the router itself is not firewalled from the internet"
    else
        say "ruleset $WAN_FW, default-action $(get_value firewall name "$WAN_FW" default-action)"
        local -a rules=()
        eval "rules=($(list_nodes firewall name "$WAN_FW" rule))"
        for r in "${rules[@]}"; do
            say "  rule $r: $(get_value firewall name "$WAN_FW" rule "$r" action) $(get_value firewall name "$WAN_FW" rule "$r" protocol) port $(get_value firewall name "$WAN_FW" rule "$r" destination port) - $(get_value firewall name "$WAN_FW" rule "$r" description)"
        done
    fi

    section "Port forwards and destination NAT on port $WG_PORT"
    check_port_conflicts
    problems=$((problems + PORT_CONFLICTS))

    section "NAT (devices reaching the internet through the tunnel)"
    if r=$(nat_covering_tunnel); then say "masquerade rule $r on $WAN_IF already covers $WG_NET.0/24"
    else say "no masquerade rule covers $WG_NET.0/24; setup adds one"; fi

    section "DNS for devices"
    say "dnsmasq listen-on: $(list_values service dns forwarding listen-on)"
    local -a dyn=() svc=()
    local d s h
    eval "dyn=($(list_nodes service dns dynamic interface))"
    for d in "${dyn[@]}"; do
        eval "svc=($(list_nodes service dns dynamic interface "$d" service))"
        for s in "${svc[@]}"; do
            for h in $(list_values service dns dynamic interface "$d" service "$s" host-name | tr -d "'"); do
                say "dynamic DNS: $h ($s on $d)"
                emit ddns_host "$h"
            done
        done
    done
    if [ ${#dyn[@]} -eq 0 ]; then say "no dynamic DNS configured on the router"; fi

    section "UDP port $WG_PORT"
    if ss -lun | grep -E ":$WG_PORT\b" | indent; then :; else say "not in use"; fi

    section "Preflight result"
    if [ "$problems" -gt 0 ]; then die "$problems problem(s) found; nothing was changed"; fi
    say "OK"
}

cmd_prepare() {
    need_root prepare
    section "State directory and router key"
    run install -d -m 2775 -g vyattacfg "$STATE_DIR"
    if [ ! -d /config/auth ]; then run install -d -m 0775 -g vyattacfg /config/auth; fi
    if [ -s "$KEY" ]; then
        say "router private key exists: $KEY"
    else
        say "generating the router's private key in $KEY (readable by root and admins only)"
        ( umask 077; wg genkey > "$KEY.new" )
        run chgrp vyattacfg "$KEY.new"
        run chmod 0640 "$KEY.new"
        run mv -f "$KEY.new" "$KEY"
    fi
    say "router public key: $(wg pubkey < "$KEY")"
}

cmd_setup() {
    as_config_group setup
    [ -s "$KEY" ] || die "no router key at $KEY; run prepare first"
    load_wan
    section "Backup"
    save_backup

    local base r
    local -a cmds=() records=() addrs=() listen=()
    base="interfaces wireguard $WG_IF"
    eval "addrs=($(list_values $base address))"
    if ! in_list "$WG_ADDR" "${addrs[@]}"; then cmds+=("set $base address $WG_ADDR"); fi
    if [ "$(get_value $base listen-port)" != "$WG_PORT" ]; then cmds+=("set $base listen-port $WG_PORT"); fi
    if [ "$(get_value $base private-key)" != "$KEY" ]; then cmds+=("set $base private-key $KEY"); fi
    if [ -z "$(get_value $base description)" ]; then cmds+=("set $base description 'WireGuard remote access'"); fi

    if [ -z "$WAN_FW" ]; then
        warn "no local firewall on the WAN, so no rule is needed to reach UDP $WG_PORT"
    else
        base="firewall name $WAN_FW rule"
        if r=$(find_tagged_rule "$base"); then
            say "firewall: $WAN_FW rule $r already accepts UDP $WG_PORT"
        else
            r=$(free_rule "$base" 30 10)
            cmds+=("set $base $r action accept" "set $base $r protocol udp"
                   "set $base $r destination port $WG_PORT" "set $base $r description '$TAG'")
            records+=("firewall=$base $r")
        fi
    fi

    if r=$(nat_covering_tunnel); then
        say "NAT: rule $r already masquerades $WG_NET.0/24 out of $WAN_IF"
    else
        base="service nat rule"
        r=$(free_rule "$base" 5100 1)
        cmds+=("set $base $r type masquerade" "set $base $r outbound-interface $WAN_IF"
               "set $base $r source address $WG_NET.0/24" "set $base $r description '$TAG'")
        records+=("nat=$base $r")
    fi

    eval "listen=($(list_values service dns forwarding listen-on))"
    if cfg_exists service dns forwarding && ! in_list "$WG_IF" "${listen[@]}"; then
        cmds+=("set service dns forwarding listen-on $WG_IF")
        records+=("dns-listen-on=$WG_IF")
    fi

    section "EdgeOS configuration changes"
    if [ ${#cmds[@]} -eq 0 ]; then
        say "everything is already in place; nothing to change"
    else
        apply_cmds "${cmds[@]}" || die "configuration change failed and was discarded; nothing changed"
        if [ ${#records[@]} -gt 0 ]; then printf '%s\n' "${records[@]}" >> "$STATE"; fi
    fi
    if [ -f "$STATE" ]; then say "added by this script (removed by uninstall):"; indent < "$STATE"; fi
}

cmd_status() {
    need_root status
    section "Interface $WG_IF"
    if ! ip link show dev "$WG_IF" >/dev/null 2>&1; then say "$WG_IF does not exist"; return 0; fi
    ip -4 -o addr show dev "$WG_IF" | awk '{print $4}' | indent
    wg show "$WG_IF" | indent      # prints "private key: (hidden)"

    section "Devices"
    local pub psk endpoint allowed hs rx tx ka name ago now
    now=$(date +%s)
    printf '[router]     %-16s %-16s %-22s %-20s %s\n' NAME ADDRESS ENDPOINT "LAST HANDSHAKE" "RX/TX"
    # dump: first line is the interface (holds the private key) and is skipped.
    wg show "$WG_IF" dump | tail -n +2 | while IFS=$'\t' read -r pub psk endpoint allowed hs rx tx ka; do
        name=$(get_value interfaces wireguard $WG_IF peer "$pub" description)
        if [ "$hs" = 0 ]; then ago=never; else ago="$(( now - hs ))s ago"; fi
        printf '[router]     %-16s %-16s %-22s %-20s %s/%s\n' "${name:-?}" "$allowed" "$endpoint" "$ago" \
            "$(human "$rx")" "$(human "$tx")"
    done

    section "Listening on UDP $WG_PORT"
    ss -lun | grep -E ":$WG_PORT\b" | indent || warn "nothing is listening on UDP $WG_PORT"
}

human() { # bytes -> B/K/M/G (EdgeOS has no numfmt)
    local b=$1
    if [ "$b" -ge 1073741824 ]; then echo "$((b / 1073741824))G"
    elif [ "$b" -ge 1048576 ]; then echo "$((b / 1048576))M"
    elif [ "$b" -ge 1024 ]; then echo "$((b / 1024))K"
    else echo "${b}B"; fi
}

fw_counters() {
    if [ -z "$WAN_FW" ]; then say "(no local firewall on $WAN_IF)"; return 0; fi
    iptables -L "$WAN_FW" -n -v --line-numbers 2>&1 | indent || true
}

# Watch the WAN for WireGuard packets while a device connects. Handshake
# initiations are 148 bytes, the router's responses 92 bytes.
cmd_diagnose() {
    need_root diagnose
    local secs=${1:-45} dd=/sys/kernel/debug/dynamic_debug/control debug=no
    load_wan
    command -v tcpdump >/dev/null 2>&1 || die "tcpdump is not installed on the router"

    section "Port forwards and destination NAT on port $WG_PORT"
    check_port_conflicts

    section "Firewall counters before ($WAN_FW on $WAN_IF)"
    fw_counters

    if [ -w "$dd" ] && echo 'module wireguard +p' > "$dd" 2>/dev/null; then
        debug=yes
        say "WireGuard kernel debug logging is on for this capture"
    else
        say "WireGuard kernel debug logging is not available on this kernel"
    fi
    local kmsg_before cap pid i
    kmsg_before=$(dmesg 2>/dev/null | wc -l)

    # All interfaces: from the LAN a device reaches the WAN address via
    # switch0, from the internet via the WAN. TCP too, for a browser test.
    # EdgeOS has no timeout(1), so run tcpdump in the background and stop it.
    section "Watching port $WG_PORT (UDP and TCP) on all interfaces for ${secs}s: turn the tunnel on NOW"
    cap=$(mktemp /tmp/erx-wg-capture.XXXXXX)
    tcpdump -l -n -i any -c 60 "port $WG_PORT" > "$cap" 2>&1 &
    pid=$!
    for i in $(seq "$secs"); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    indent < "$cap"
    rm -f "$cap"

    if [ "$debug" = yes ]; then echo 'module wireguard -p' > "$dd" 2>/dev/null || true; fi

    section "Firewall counters after"
    fw_counters
    section "New kernel messages during the capture (WireGuard lines)"
    dmesg 2>/dev/null | tail -n +"$((kmsg_before + 1))" | grep -i wireguard | indent || say "(none)"
    section "wg show $WG_IF"
    wg show "$WG_IF" | indent
}

cmd_add_peer() {
    local name=$1 pub=$2 n ip=""
    as_config_group add-peer "$name" "$pub"
    cfg_exists interfaces wireguard $WG_IF || die "$WG_IF is not set up; run install.sh first"
    load_peers
    if peer_by_name "$name" >/dev/null; then die "a device named '$name' already exists"; fi
    if in_list "$pub" "${PEERS[@]}"; then die "this public key is already a device"; fi
    for n in $(seq 2 254); do
        if ! in_list "$WG_NET.$n/32" "${USED[@]}"; then ip=$WG_NET.$n; break; fi
    done
    [ -n "$ip" ] || die "no free addresses left in $WG_NET.0/24"

    section "Adding device '$name' as $ip"
    save_backup
    apply_cmds "set interfaces wireguard $WG_IF peer $pub allowed-ips $ip/32" \
               "set interfaces wireguard $WG_IF peer $pub description $name" \
        || die "configuration change failed and was discarded; nothing changed"
    emit address "$ip/32"
    emit dns "$WG_NET.1"
    emit port "$WG_PORT"
    emit server_pubkey "$(wg pubkey < "$KEY")"
}

cmd_remove_peer() {
    local name=$1 pub
    as_config_group remove-peer "$name"
    load_peers
    pub=$(peer_by_name "$name") || die "no device named '$name' on the router"
    section "Removing device '$name' ($pub)"
    save_backup
    apply_cmds "delete interfaces wireguard $WG_IF peer $pub" \
        || die "configuration change failed and was discarded; nothing changed"
    emit removed "$pub"
}

cmd_uninstall() {
    as_config_group uninstall
    section "Removing WireGuard"
    local line key path
    local -a cmds=()
    if cfg_exists interfaces wireguard $WG_IF; then cmds+=("delete interfaces wireguard $WG_IF"); fi
    if [ -f "$STATE" ]; then
        while IFS= read -r line; do
            key=${line%%=*}; path=${line#*=}
            case "$key" in
                firewall|nat) if cfg_exists $path; then cmds+=("delete $path"); fi ;;
                dns-listen-on) cmds+=("delete service dns forwarding listen-on $path") ;;
            esac
        done < "$STATE"
    fi
    if [ ${#cmds[@]} -eq 0 ]; then say "nothing to remove"; return 0; fi
    save_backup
    apply_cmds "${cmds[@]}" || die "configuration change failed and was discarded; nothing changed"
    if [ -f "$STATE" ]; then run mv "$STATE" "$STATE.removed-$(date +%Y%m%d-%H%M%S)"; fi
    if [ -f "$KEY" ]; then
        run mv "$KEY" "$STATE_DIR/$(basename "$KEY").removed-$(date +%Y%m%d-%H%M%S)"
    fi
}

case "${1:-}" in
    check)       cmd_check ;;
    prepare)     cmd_prepare ;;
    setup)       cmd_setup ;;
    status)      cmd_status ;;
    add-peer)    validate_name "${2:-}"; validate_key "${3:-}"; cmd_add_peer "$2" "$3" ;;
    remove-peer) validate_name "${2:-}"; cmd_remove_peer "$2" ;;
    diagnose)    [[ ${2:-45} =~ ^[0-9]{1,3}$ ]] || die "seconds must be a number"; cmd_diagnose "${2:-45}" ;;
    uninstall)   cmd_uninstall ;;
    *) die "usage: $0 check|prepare|setup|status|add-peer NAME PUBKEY|remove-peer NAME|diagnose [SECONDS]|uninstall" ;;
esac
