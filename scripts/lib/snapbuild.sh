# Sourced, not executed. Source freeze for builds: rustdesk + its entire path-dep closure
# (../fgtw ../tohu ../ihi ../vsf, discovered from the Cargo.tomls) reflink-copy (btrfs CoW)
# into a stable snapshot dir, and cargo builds from the frozen tree — so editing continues
# fearlessly in the live tree without tearing a multi-minute cross-platform deploy.
#
# Same design as photon's (see that file for the full why): stable snap path keeps path-dep
# fingerprints valid; CARGO_TARGET_DIR stays the real ./target; snapshot destroyed on every
# exit; each crate's target/ and sibling .git dirs skipped — rustdesk's own .git rides along
# (hbb_common submodule gitfile + version stamping resolve against it). Shares the one
# .build-snap flock with photon deploys: mutual exclusion between deploys is a feature.

SNAPBUILD_CODE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.."
SNAPBUILD_ROOT="$SNAPBUILD_CODE_ROOT/.build-snap"

snapbuild_crates() {
    local pending=(rustdesk) done_list=() c dep
    while [ ${#pending[@]} -gt 0 ]; do
        c="${pending[0]}"
        pending=("${pending[@]:1}")
        case " ${done_list[*]} " in *" $c "*) continue ;; esac
        done_list+=("$c")
        [ -f "$SNAPBUILD_CODE_ROOT/$c/Cargo.toml" ] || continue
        for dep in $(grep -o 'path = "\.\./[A-Za-z0-9_-]*"' "$SNAPBUILD_CODE_ROOT/$c/Cargo.toml" | sed 's|.*"\.\./||; s|"||'); do
            pending+=("$dep")
        done
    done
    echo "${done_list[@]}"
}

snapbuild_take() {
    command -v flock >/dev/null 2>&1 || return 1
    case "$SNAPBUILD_ROOT" in
        */.build-snap) ;;
        *) return 1 ;;
    esac
    exec 8>>"$SNAPBUILD_ROOT.lock" 2>/dev/null || return 1
    flock 8 || return 1
    rm -rf "$SNAPBUILD_ROOT" || return 1
    mkdir -p "$SNAPBUILD_ROOT" || return 1
    local c entry base
    for c in $(snapbuild_crates); do
        [ -d "$SNAPBUILD_CODE_ROOT/$c" ] || continue
        mkdir "$SNAPBUILD_ROOT/$c" || { snapbuild_drop; return 1; }
        for entry in "$SNAPBUILD_CODE_ROOT/$c"/* "$SNAPBUILD_CODE_ROOT/$c"/.[!.]*; do
            { [ -e "$entry" ] || [ -L "$entry" ]; } || continue
            base="${entry##*/}"
            case "$base" in
                target) continue ;;
                .git) [ "$c" = rustdesk ] || continue ;;
            esac
            cp -a --reflink=always "$entry" "$SNAPBUILD_ROOT/$c/" 2>/dev/null || { snapbuild_drop; return 1; }
        done
    done
    trap snapbuild_drop EXIT
    return 0
}

snapbuild_drop() {
    rm -rf "$SNAPBUILD_ROOT"
}
