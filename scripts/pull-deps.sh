#!/bin/bash
# Fast-forward this fork AND every sibling repo it depends on, so a build can't mix a fresh rustdesk with a stale sibling — then move the hbb_common submodule to the commit this fork records.
#
# Photon's scripts/pull-deps.sh, carried here. A stale sibling is the "missing fgtw symbol" class: rustdesk compiles against a sibling that lacks what its new code calls (2026-11-25: the dialler hub constants landed in fgtw and rustdesk together), and the errors look like rustdesk's fault. Fast-forward everything together or nothing.
#
# The sibling set is the CLOSURE of the Cargo.toml `path = "..."` graph from this repo (fgtw, tohu, ihi, vsf, fluor, and whatever they reach), derived rather than hardcoded so it stays right when deps change. Paths that land inside this repo (libs/*) are this repo's own.
#
# Two things differ from Photon's:
#   - Each repo fetches from ITS OWN upstream remote. This checkout tracks `fork` (nickspiker/rustdesk); `origin` and `upstream` are rustdesk/rustdesk, which must never be what we follow.
#   - libs/hbb_common is a submodule pinned by commit. After the fast-forward it is moved to the pin — unless it holds uncommitted work or a commit no remote has, which a checkout would strand (the deploy dirty-tree trap); then it stops and says so.
#
# Then build and install with scripts/dev-install.sh.
#
# Exit status: 0 = every repo current and clean, non-zero = at least one needs a human.

set -u
# Resolve the tree from THIS SCRIPT's location, never $HOME or a hardcoded path: the checkout lives wherever the machine keeps it. readlink -f so a symlinked invocation still lands on the real tree.
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
REPO="$(cd "$(dirname "$SELF")/.." && pwd)"
ROOT="$(cd "$REPO/.." && pwd)"   # the parent that holds every sibling checkout
NAME="$(basename "$REPO")"

# SELF-UPDATE SAFETY: this script fast-forwards the repo that contains THIS FILE. Bash reads a script incrementally by byte offset, so a file rewritten mid-run can resume parsing inside new bytes. The whole body is a function called on the last line, so bash has parsed all of it before any git command runs — which is also why there is no need to `git pull` first.
main() {
    if [ ! -d "$REPO/.git" ]; then
        echo "pull-deps: $REPO is not a git checkout" >&2
        exit 1
    fi
    echo "repo:     $REPO"
    echo "siblings: $ROOT"

    # The closure: walk the Cargo.toml path deps transitively, keeping anything that resolves to a sibling of the root. Pure shell by rule (no python in build scripts).
    closure() {
        local todo="$NAME" seen="" cur dir rel abs name
        while [ -n "$todo" ]; do
            cur="${todo%% *}"
            case "$todo" in *" "*) todo="${todo#* }" ;; *) todo="" ;; esac
            case " $seen " in *" $cur "*) continue ;; esac
            seen="$seen $cur"
            dir="$ROOT/$cur"
            [ -f "$dir/Cargo.toml" ] || continue
            for rel in $(sed -n 's/.*path[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$dir/Cargo.toml"); do
                abs="$(cd "$dir/$rel" 2>/dev/null && pwd)" || continue
                case "$abs" in
                    "$ROOT"/*) name="${abs#"$ROOT"/}"; name="${name%%/*}" ;;
                    *) continue ;;
                esac
                case " $seen $todo " in *" $name "*) ;; *) todo="$todo $name" ;; esac
            done
        done
        echo $(printf '%s\n' $seen | sort)
    }
    REPOS="$(closure)"

    echo "closure:  $REPOS"
    echo

    fail=0
    dirty=""
    for r in $REPOS; do
        d="$ROOT/$r"
        [ -d "$d/.git" ] || { printf '  %-12s SKIP   not a git checkout: %s\n' "$r" "$d"; continue; }

        # Detached HEAD or no tracking branch = a deliberate pin. Never yank those.
        branch=$(git -C "$d" symbolic-ref --quiet --short HEAD 2>/dev/null) || {
            printf '  %-12s SKIP   detached HEAD (pinned)\n' "$r"; continue; }
        git -C "$d" rev-parse --abbrev-ref "@{upstream}" >/dev/null 2>&1 || {
            printf '  %-12s SKIP   no upstream for %s\n' "$r" "$branch"; continue; }
        remote=$(git -C "$d" config "branch.$branch.remote")

        if ! git -C "$d" fetch --quiet "$remote" 2>/dev/null; then
            printf '  %-12s FAIL   fetch from %s failed (network?): %s\n' "$r" "$remote" "$d"; fail=1; continue
        fi

        local_sha=$(git -C "$d" rev-parse HEAD)
        remote_sha=$(git -C "$d" rev-parse "@{upstream}")
        if [ "$local_sha" = "$remote_sha" ]; then
            state="current"
        elif git -C "$d" merge-base --is-ancestor HEAD "@{upstream}" 2>/dev/null; then
            if git -C "$d" merge --ff-only --quiet "@{upstream}" 2>/dev/null; then
                state="PULLED  $(git -C "$d" log --oneline -1 | cut -c1-52)"
            else
                printf '  %-12s FAIL   ff-only merge refused (uncommitted changes in the way?): %s\n' "$r" "$d"; fail=1; continue
            fi
        elif git -C "$d" merge-base --is-ancestor "@{upstream}" HEAD 2>/dev/null; then
            state="ahead — you have unpushed commits"
        else
            ahead=$(git -C "$d" rev-list --count "@{upstream}..HEAD" 2>/dev/null || echo '?')
            behind=$(git -C "$d" rev-list --count "HEAD..@{upstream}" 2>/dev/null || echo '?')
            printf '  %-12s FAIL   DIVERGED from %s: %s ahead, %s behind\n' "$r" "$branch" "$ahead" "$behind"
            printf '               %s\n' "$d"
            printf '               local-only commits:\n'
            git -C "$d" log --oneline "@{upstream}..HEAD" 2>/dev/null | sed 's/^/                 /'
            printf '               fix: git -C %s pull --rebase\n' "$d"
            fail=1; continue
        fi

        # Report a dirty tree but never touch it: uncommitted work is the human's to judge.
        if [ -n "$(git -C "$d" status --porcelain --ignore-submodules=all 2>/dev/null)" ]; then
            dirty="$dirty $r"
            state="$state  [DIRTY]"
        fi
        printf '  %-12s %s\n' "$r" "$state"
    done

    # The submodules this repo pins, moved to the recorded commit now that the parent is current.
    for sub in $(git -C "$REPO" config --file .gitmodules --get-regexp 'submodule\..*\.path' 2>/dev/null | awk '{print $2}'); do
        s="$REPO/$sub"
        label="${sub##*/}"
        pin=$(git -C "$REPO" ls-tree HEAD "$sub" | awk '{print $3}')
        if [ ! -e "$s/.git" ]; then
            if git -C "$REPO" submodule update --init --quiet -- "$sub" 2>/dev/null; then
                printf '  %-12s CLONED at the pin %s\n' "$label" "$(echo "$pin" | cut -c1-12)"
            else
                printf '  %-12s FAIL   submodule init failed: %s\n' "$label" "$s"; fail=1
            fi
            continue
        fi
        cur=$(git -C "$s" rev-parse HEAD)
        if [ "$cur" = "$pin" ]; then
            state="at the pin"
        elif [ -n "$(git -C "$s" status --porcelain 2>/dev/null)" ]; then
            printf '  %-12s FAIL   uncommitted work in the submodule; moving it to the pin would bury it: %s\n' "$label" "$s"; fail=1; continue
        elif [ -z "$(git -C "$s" branch -r --contains "$cur" 2>/dev/null)" ] && ! git -C "$s" merge-base --is-ancestor "$cur" "$pin" 2>/dev/null; then
            printf '  %-12s FAIL   HEAD %s is on no remote branch — push it (then commit the pointer in %s) before it is stranded: %s\n' "$label" "$(echo "$cur" | cut -c1-12)" "$NAME" "$s"; fail=1; continue
        elif git -C "$REPO" submodule update --quiet -- "$sub" 2>/dev/null; then
            state="MOVED to the pin $(echo "$pin" | cut -c1-12)"
        else
            printf '  %-12s FAIL   could not check out the pin %s: %s\n' "$label" "$(echo "$pin" | cut -c1-12)" "$s"; fail=1; continue
        fi
        printf '  %-12s %s\n' "$label" "$state"
    done

    echo
    if [ -n "$dirty" ]; then
        echo "WARNING: uncommitted changes in:$dirty"
        for r in $dirty; do printf '         %s\n' "$ROOT/$r"; done
        echo "         a build from a dirty tree runs bits no commit can reproduce — commit or stash first."
        fail=1
    fi

    if [ "$fail" -ne 0 ]; then
        echo "NOT build-ready — resolve the above first."
        exit 1
    fi
    echo "all ${REPOS// /, } current, clean, and fast-forwarded — next: scripts/dev-install.sh"
    echo "completed $(date '+%F %T')"
}

main "$@"
