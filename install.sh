#!/usr/bin/env bash
#
# edgerouter-x-sfp-wireguard
#
# Sets up WireGuard remote access on an EdgeRouter X SFP running EdgeOS 3
# (which has WireGuard built in), listening on UDP 51831. Safe to re-run: it
# only changes what is not already in place. Devices are managed with
# ./device.sh.
#
#   ./install.sh              set up, or check and repair, WireGuard
#   ./install.sh --check      report only: router support, versions vs
#                             upstream, known CVEs; change nothing
#   ./install.sh --uninstall  remove wg0 and the rules this added
#                             (saved device configs in clients/ are kept)

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$REPO_DIR/lib/common.sh"
# shellcheck source=lib/scout.sh
. "$REPO_DIR/lib/scout.sh"

usage() { sed -n '10,14p' "$0" | sed 's/^# \{0,1\}//'; }

MODE=install
case "${1:-}" in
    "") ;;
    --check) MODE=check ;;
    --uninstall) MODE=uninstall ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
start_log "$MODE"

choose_endpoint() { # choose_endpoint <router check output>
    local saved ddns wan answer resolved
    saved=$(local_setting ENDPOINT)
    ddns=$(result ddns_host "$1")
    wan=$(result wan_ip "$1")
    step "Address devices connect to"
    answer=$(ask "Public hostname or IP of the router" "${saved:-${ddns:-$wan}}")
    [[ $answer =~ ^[A-Za-z0-9.-]+$ ]] || die "not a hostname or IPv4 address: $answer"
    if [[ $answer =~ ^[0-9.]+$ ]]; then resolved=$answer; else resolved=$(dig +short "$answer" A | tail -1); fi
    info "$answer -> ${resolved:-<does not resolve>}; router WAN address: ${wan:-unknown}"
    if [ "$resolved" != "$wan" ]; then
        warn "$answer does not point at the router's WAN address; devices may not reach it"
    fi
    save_local_setting ENDPOINT "$answer"
    info "saved in $LOCAL_CONF (not committed)"
}

step "EdgeRouter WireGuard: $MODE"
info "log: $LOG"
info "local: $(uname -sm), $(ssh -V 2>&1)"

ask_login
connect
upload

case "$MODE" in
    check)
        out=$(remote root check | tee /dev/stderr) || warn "preflight reported problems (see above)"
        scout_versions "$out"
        remote root status
        info "saved endpoint: $(local_setting ENDPOINT || true)"
        ;;
    install)
        out=$(remote root check | tee /dev/stderr)
        scout_versions "$out"
        choose_endpoint "$out"
        remote root prepare
        remote admin setup
        remote root status
        step "Next"
        info "Add a device:  ./device.sh add phone"
        ;;
    uninstall)
        remote admin uninstall
        remote root status
        info "Saved device configs in $CLIENTS were kept; delete them if you no longer need them."
        ;;
esac
