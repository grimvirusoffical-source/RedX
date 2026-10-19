# Sourced by the build scripts. Release builds come from a clean checkout only, so that the commit stamped into
# every binary (vcs.revision) is exactly the source that was built.
#   require_clean_tree RELEASE   RELEASE=1: refuse a dirty tree unless REDX_ALLOW_DIRTY=1, which then appends
#                                "-dirty" to $VERSION. RELEASE=0 (dev build): only append "-dirty".
# Untracked files count as dirty; ignored files (dist/, bin/, ...) do not.
require_clean_tree() {
  local release="$1" changes
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "note: not a git checkout; the source of this build cannot be checked" >&2
    return 0
  fi
  changes="$(git status --porcelain --untracked-files=normal 2>/dev/null)"
  [ -z "$changes" ] && return 0
  case "$VERSION" in *-dirty) ;; *) VERSION="${VERSION}-dirty" ;; esac
  if [ "$release" = 1 ] && [ "${REDX_ALLOW_DIRTY:-}" != 1 ]; then
    echo "refusing a release build from a dirty working tree (commit or stash these first):" >&2
    printf '%s\n' "$changes" | head -20 >&2
    echo "(REDX_ALLOW_DIRTY=1 builds anyway and stamps the version as ${VERSION})" >&2
    exit 1
  fi
  echo "warning: dirty working tree: version stamped ${VERSION}" >&2
}
