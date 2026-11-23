# Compares the router's WireGuard with upstream and lists known CVEs in the
# Linux kernel WireGuard driver and wireguard-tools, marking for each kernel
# CVE whether its fix exists in the wireguard-linux-compat backport that
# kernels before 5.6 (like the ER-X's 4.14) use. Sourced by install.sh after
# lib/common.sh. Only public data is fetched (git.zx2c4.com, NVD); nothing
# about the router is sent anywhere. Downloads are cached in .cache/.

SCOUT_CACHE="$REPO_DIR/.cache"
NVD_URL='https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=wireguard&resultsPerPage=2000'

latest_tag() { # latest_tag <repo>: newest 1.0.YYYYMMDD tag, from git.zx2c4.com (GitHub mirror as fallback)
    local tags
    tags=$(git ls-remote --tags --refs "https://git.zx2c4.com/$1" 2>/dev/null \
        || git ls-remote --tags --refs "https://github.com/WireGuard/$1" 2>/dev/null || true)
    printf '%s\n' "$tags" | sed -n 's#.*refs/tags/v##p' | grep -E '^1\.0\.[0-9]{8}$' | sort | tail -1 || true
}

# version_date 1.0.20220627 -> 20220627 (empty if the version has no date)
version_date() { printf '%s' "$1" | sed -n 's/^1\.0\.\([0-9]\{8\}\)$/\1/p'; }

compare_version() { # compare_version <label> <router version> <latest upstream>
    local rd ld
    rd=$(version_date "$2"); ld=$(version_date "$3")
    if [ -z "$2" ]; then warn "$1: unknown on the router"
    elif [ -z "$3" ]; then warn "$1: could not fetch the upstream version"
    elif [ "$2" = "$3" ]; then info "$1: $2 is the latest upstream release"
    elif [ -n "$rd" ] && [ -n "$ld" ] && [ "$rd" -lt "$ld" ]; then warn "$1: router has $2, upstream has $3"
    elif [ -z "$rd" ]; then info "$1: router reports $2, which carries no release date (vendor or in-tree build); upstream is $3"
    else info "$1: router has $2, upstream $3"
    fi
}

# Commit subjects of the compat backport, one per line, into the given file.
compat_subjects() {
    local dir="$SCOUT_CACHE/wireguard-linux-compat.git"
    mkdir -p "$SCOUT_CACHE"
    if [ -d "$dir" ]; then
        git -C "$dir" fetch -q origin '+refs/heads/*:refs/heads/*' 2>/dev/null || true
    else
        git clone -q --bare https://git.zx2c4.com/wireguard-linux-compat "$dir" 2>/dev/null \
            || git clone -q --bare https://github.com/WireGuard/wireguard-linux-compat "$dir" 2>/dev/null \
            || return 1
    fi
    git -C "$dir" log --format=%s --all > "$1"
}

# NVD search results for "wireguard"; falls back to the cached copy when NVD
# rate-limits or is down. Prints the path of the JSON file.
nvd_json() {
    local f="$SCOUT_CACHE/nvd-wireguard.json"
    mkdir -p "$SCOUT_CACHE"
    if curl -fsS --max-time 60 "$NVD_URL" -o "$f.new" 2>/dev/null \
        && python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))["vulnerabilities"]' "$f.new" 2>/dev/null; then
        mv -f "$f.new" "$f"
    else
        rm -f "$f.new"
        [ -f "$f" ] || return 1
        warn "NVD did not answer; using the copy from $(date -r "$f" '+%F %R')" >&2
    fi
    echo "$f"
}

NVD_FILTER=$(cat <<'EOF'
import json, re, sys
nvd_file, subjects_file = sys.argv[1], sys.argv[2]
subjects = set()
if subjects_file != "-":
    subjects = {s.strip().lower() for s in open(subjects_file)}
rows = []
for item in json.load(open(nvd_file)).get("vulnerabilities", []):
    cve = item["cve"]
    desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
    if re.search(r"resolved:\s+wireguard:", desc):
        kind = "kernel"
        # Kernel CVE texts are "...resolved:\n\nwireguard: <commit subject>\n\n<body>".
        title = re.split(r"resolved:\s*", desc, maxsplit=1)[1].strip().split("\n")[0].strip()
        # compat commit subjects drop the "wireguard: " prefix.
        subject = re.sub(r"^wireguard:\s*", "", title).lower()
        if not subjects:
            status = "unchecked"
        elif subject in subjects:
            status = "in compat"
        else:
            status = "NOT in compat"
    elif "wireguard-tools" in desc.lower():
        kind, status = "tools", "-"
        title = re.sub(r"\s+", " ", desc)[:100]
    else:
        continue
    sev = "-"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = cve.get("metrics", {}).get(key)
        if m:
            sev = m[0]["cvssData"].get("baseSeverity") or m[0].get("baseSeverity") or "-"
            break
    rows.append((cve["published"][:10], cve["id"], sev, kind, status, title))
print(f"{'CVE':<16} {'PUBLISHED':<10}  {'SEVERITY':<8} {'WHERE':<6} {'FIX':<13} SUBJECT")
for published, cid, sev, kind, status, title in sorted(rows):
    print(f"{cid:<16} {published}  {sev:<8} {kind:<6} {status:<13} {title[:80]}")
missing = sum(1 for r in rows if r[4] == "NOT in compat")
print(f"{len(rows)} CVE(s); {missing} kernel fix(es) not in the compat backport. "
      "Details: https://nvd.nist.gov/vuln/detail/<CVE id>")
EOF
)

scout_versions() { # scout_versions <router check output>
    local out=$1 module tools kernel latest_tools latest_compat nvd subjects="$WORK/compat-subjects"
    module=$(result module_version "$out")
    tools=$(result tools_version "$out")
    kernel=$(result kernel "$out")
    step "WireGuard versions vs upstream"
    latest_tools=$(latest_tag wireguard-tools)
    latest_compat=$(latest_tag wireguard-linux-compat)
    info "router kernel $kernel, WireGuard module ${module:-unknown}, wg tool ${tools:-unknown}"
    info "kernels before 5.6 get WireGuard from the wireguard-linux-compat backport"
    compare_version "kernel module (vs wireguard-linux-compat)" "$module" "$latest_compat"
    compare_version "wg tool (vs wireguard-tools)" "$tools" "$latest_tools"

    step "Known CVEs: Linux kernel WireGuard driver and wireguard-tools (NVD)"
    if compat_subjects "$subjects"; then
        info "FIX column: whether the fix is in wireguard-linux-compat (last commit $(git -C "$SCOUT_CACHE/wireguard-linux-compat.git" log -1 --all --format=%ad --date=short))."
        info "'NOT in compat' means the router's module lacks the fix unless Ubiquiti patched it."
    else
        warn "could not fetch wireguard-linux-compat; the FIX column is unchecked"
        subjects="-"
    fi
    if nvd=$(nvd_json); then
        python3 -I -c "$NVD_FILTER" "$nvd" "$subjects" | sed 's/^/      /'
    else
        warn "could not query NVD (rate limit or offline) and no cached copy; try again later"
    fi
}
