# Sourced, not executed. GitHub Releases upload helper (via gh) — the redundant mirror behind R2.
# R2 is the primary serving origin (fastest edge, stable flat URLs the installer hardcodes); GitHub is
# the fallback. Upload to R2 FIRST, then here, so a failed GitHub step leaves R2 already serving and is
# cheap to retry alone. Integrity is origin-blind (.sha256 sidecars + signed manifest), so a
# GitHub-served binary is exactly as trusted.
#
# CDN STALENESS (photon learned this the hard way): GitHub release-asset URLs are fronted by Fastly and
# keep serving OLD bytes after a --clobber until the edge expires. So the release channel uses an
# IMMUTABLE per-version `fgtw-v<n>` tag — each asset name is written once, never clobbered.

GH_REPO="nickspiker/rustdesk"

# ensure_release <tag> <prerelease:true|false>
ensure_release() {
    local tag="$1" prerelease="$2"
    if gh release view "$tag" --repo "$GH_REPO" >/dev/null 2>&1; then
        return 0
    fi
    echo "Creating GitHub release $tag..."
    if [ "$prerelease" = "true" ]; then
        gh release create "$tag" --repo "$GH_REPO" --prerelease \
            --title "Development (rolling)" \
            --notes "Rolling development builds — not for production."
    else
        gh release create "$tag" --repo "$GH_REPO" \
            --title "$tag" \
            --notes "RustDesk passless fork, release $tag. Binaries are Ed25519-signed; install scripts verify .sha256 sidecars. Primary install: https://brobdingnagian.holdmyoscilloscope.com/rustdesk/install-release.sh"
    fi
}

# publish_github <tag> <asset-name> <local-file>
# The DOWNLOAD asset name is gh's basename of the uploaded path, so symlink the file under the flat
# asset name in a temp dir and upload that (gh dereferences symlinks).
publish_github() {
    local tag="$1" name="$2" file="$3"
    if [ ! -f "$file" ]; then
        echo "ERROR: asset not found for GitHub upload: $file"
        return 1
    fi
    local staging
    staging=$(mktemp -d)
    ln -sf "$(readlink -f "$file")" "$staging/$name"
    gh release upload "$tag" "$staging/$name" --repo "$GH_REPO" --clobber
    rm -rf "$staging"
    echo "  ↳ GitHub: https://github.com/$GH_REPO/releases/download/$tag/$name"
}
