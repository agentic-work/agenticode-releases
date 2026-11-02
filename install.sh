#!/bin/sh
# =============================================================================
# agenticode installer — macOS / Linux
#
#   curl -fsSL https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.sh | sh
#
# Pin a version:
#   curl -fsSL https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.sh | AGENTICODE_VERSION=0.8.4 sh
#
# Options (flags need `sh -s --`, e.g. `... | sh -s -- --prefix ~/bin`):
#   --version <v>   install a specific version           (env AGENTICODE_VERSION)
#   --prefix <dir>  install directory                    (env AGENTICODE_PREFIX)
#   --print-plan    show exactly what would be done, then exit
#   --help
#
# Env:
#   AGENTICODE_INSTALL_BASE   endpoint root (default https://get.agenticwork.io)
#
# -----------------------------------------------------------------------------
# Notes for whoever edits this next
#
# 1. This is piped into `sh`. That means the whole file is UNTRUSTED INPUT to
#    your shell, and the two failure modes that actually bite are:
#      (a) the download is truncated and a half-script executes, and
#      (b) the endpoint answers 200 with an HTML error/SPA page and the shell
#          happily treats a web page as a version string, a manifest, or a
#          binary.
#    Both are defended against here. Do not remove either defence:
#      (a) everything lives inside one `{ ... }` group, so the shell cannot
#          execute ANY of it until it has parsed the closing brace on the last
#          line. A truncated file is a syntax error, not a partial install.
#      (b) every downloaded artefact is shape-checked (version regex, manifest
#          parse, HTML sniff) and the binary is SHA256-verified.
#
# 2. SHA256 verification is MANDATORY and there is deliberately no way to turn
#    it off. No --no-verify, no env escape hatch. For a curl-pipe-to-shell
#    install it is the one control that makes the whole thing defensible; an
#    off switch is just the exploit's first step.
#
# 3. POSIX sh only — this runs under dash (Debian /bin/sh), busybox ash
#    (Alpine) and bash-in-posix-mode (macOS /bin/sh). No arrays, no [[ ]],
#    no `set -o pipefail`, no `echo -e`.
#
# 4. No GitHub credential, ever — this script must never read a personal access
#    token or touch the GitHub API. The public path fetches only from
#    AGENTICODE_INSTALL_BASE. The release repo is private; mirroring the
#    release assets to that endpoint is the distribution pipeline's job.
#
# 5. The one thing this script CANNOT defend is its own delivery. Everything it
#    downloads gets shape-checked, but by then `sh` is already executing
#    whatever the endpoint returned for /install.sh. So the endpoint MUST answer
#    404 for a path it does not have, never 200-with-HTML. A single-page-app
#    catch-all in front of these paths turns "the install is broken" into "pipe
#    a web page into your shell".
#
# The URLs this builds, from an endpoint root $BASE (see also --print-plan):
#     $BASE/latest.txt                  version pointer, plain text
#     $BASE/v<version>/<asset>          the binary
#     $BASE/v<version>/checksums.txt    release manifest, verbatim
#     $BASE/v<version>/<asset>.sha256   sidecar, for assets the
#                                                  manifest does not cover
# =============================================================================

{

set -eu

RELEASES_REPO='agentic-work/agenticode-releases'
DEFAULT_BASE="https://github.com/$RELEASES_REPO/releases/download"
BIN_NAME='agenticode'

# A custom base keeps the mirror layout; the default is GitHub Releases, whose
# version pointer has to live in the repository, not in a release.
if [ -n "${AGENTICODE_INSTALL_BASE:-}" ]; then
    BASE="$AGENTICODE_INSTALL_BASE/agenticode"
    LATEST_URL="$BASE/latest.txt"
else
    BASE="$DEFAULT_BASE"
    LATEST_URL="https://raw.githubusercontent.com/$RELEASES_REPO/main/latest.txt"
fi
VERSION="${AGENTICODE_VERSION:-latest}"
PREFIX="${AGENTICODE_PREFIX:-}"
PRINT_PLAN=''
STAGE=''
TMP_DIR=''

if [ -t 1 ]; then
    C_B=$(printf '\033[1m'); C_G=$(printf '\033[32m')
    C_R=$(printf '\033[31m'); C_Y=$(printf '\033[33m'); C_0=$(printf '\033[0m')
else
    C_B=''; C_G=''; C_R=''; C_Y=''; C_0=''
fi

info() { printf '%s==>%s %s\n' "$C_G" "$C_0" "$1"; }
warn() { printf '%s!%s %s\n' "$C_Y" "$C_0" "$1" >&2; }

die() {
    printf '%serror:%s %s\n' "$C_R" "$C_0" "$1" >&2
    shift
    for hint in "$@"; do printf '       %s\n' "$hint" >&2; done
    exit 1
}

cleanup() {
    [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"
    [ -n "$STAGE" ] && rm -f "$STAGE"
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
${C_B}agenticode installer${C_0}

  curl -fsSL https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.sh | sh

Options
  --version <v>    install a specific version (default: latest)
  --prefix <dir>   install directory (default: \$HOME/.local/bin)
  --print-plan     print the resolved plan and exit without installing
  --help           this text

Environment
  AGENTICODE_INSTALL_BASE   endpoint root (default: $DEFAULT_BASE)
  AGENTICODE_VERSION        same as --version
  AGENTICODE_PREFIX         same as --prefix

SHA256 verification is always on and cannot be disabled.
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                [ $# -ge 2 ] || die '--version needs a value, e.g. --version 0.8.4'
                VERSION="$2"; shift 2 ;;
            --version=*) VERSION="${1#--version=}"; shift ;;
            --prefix)
                [ $# -ge 2 ] || die '--prefix needs a value, e.g. --prefix ~/bin'
                PREFIX="$2"; shift 2 ;;
            --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
            --print-plan) PRINT_PLAN=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *)
                die "unknown option: $1" \
                    'Run with --help to see what is supported.' \
                    'Note: SHA256 verification is mandatory and has no off switch.' ;;
        esac
    done
}

# --- endpoint sanity -------------------------------------------------------
# A one-liner that will pull an executable over plaintext HTTP from an
# arbitrary host is a downgrade attack waiting to happen. Allow https
# anywhere; allow http only against loopback (local mirrors, CI, tests).
check_base() {
    BASE="${BASE%/}"
    case "$BASE" in
        https://*) return 0 ;;
        http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*) return 0 ;;
        http://localhost|http://localhost:*|http://localhost/*) return 0 ;;
        'http://[::1]'|'http://[::1]:'*|'http://[::1]/'*) return 0 ;;
        http://*)
            die "refusing to install over plaintext http from '$BASE'" \
                'Use an https endpoint. http is only allowed against loopback.' ;;
        *)
            die "AGENTICODE_INSTALL_BASE must be a URL, got '$BASE'" ;;
    esac
}

# --- platform --------------------------------------------------------------
detect_os() {
    uname_s=$(uname -s 2>/dev/null || printf 'unknown')
    case "$uname_s" in
        Linux)  printf 'linux' ;;
        Darwin) printf 'darwin' ;;
        MINGW*|MSYS*|CYGWIN*)
            die "this script does not install on Windows ($uname_s)" \
                'Use PowerShell instead:' \
                '  irm https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.ps1 | iex' ;;
        *)
            die "unsupported operating system: $uname_s" \
                'agenticode publishes binaries for macOS (darwin) and Linux only.' ;;
    esac
}

detect_arch() {
    uname_m=$(uname -m 2>/dev/null || printf 'unknown')
    case "$uname_m" in
        x86_64|amd64)  printf 'x64' ;;
        arm64|aarch64) printf 'arm64' ;;
        *)
            die "unsupported CPU architecture: $uname_m" \
                'Published architectures are x86_64 (x64) and arm64/aarch64.' ;;
    esac
}

# --- version ---------------------------------------------------------------
normalize_version() {
    v="${1#v}"
    if ! printf '%s' "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
        die "'$1' is not a version number" \
            'Expected something like 0.8.4 or v0.8.4.'
    fi
    printf '%s' "$v"
}

resolve_latest() {
    url="$LATEST_URL"
    fetch "$url" "$TMP_DIR/latest.txt" \
        'the endpoint did not serve a version pointer'
    raw=$(tr -d ' \t\r\n' < "$TMP_DIR/latest.txt")
    if [ -z "$raw" ] || ! printf '%s' "${raw#v}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
        short=$(printf '%s' "$raw" | cut -c1-60)
        die "$url did not return a version number (got: '$short')" \
            'That usually means the endpoint answered with an HTML page — a' \
            'single-page-app catch-all rather than the real install channel.' \
            'Pin explicitly to work around it: AGENTICODE_VERSION=0.8.4'
    fi
    printf '%s' "${raw#v}"
}

# --- download --------------------------------------------------------------
fetch() {
    _url="$1"; _dest="$2"; _what="${3:-download failed}"
    if have curl; then
        if [ -t 1 ] && [ "${4:-}" = 'progress' ]; then
            curl -fL --progress-bar -o "$_dest" "$_url" && return 0
        else
            curl -fsSL -o "$_dest" "$_url" && return 0
        fi
    elif have wget; then
        wget -q -O "$_dest" "$_url" && return 0
    else
        die 'neither curl nor wget is available' \
            'Install one of them and re-run.'
    fi
    die "$_what: $_url" \
        'Check the URL is reachable, then re-run. If you are behind a proxy,' \
        'export https_proxy before piping this script into sh.'
}

# Non-fatal fetch, for the places where a 404 is a legitimate answer we then
# handle ourselves. Never use `fetch` for those: `fetch` calls `die`, and a
# `die` inside an `if` condition with stderr suppressed aborts the script with
# no message at all.
try_fetch() {
    if have curl; then
        curl -fsSL -o "$2" "$1" 2>/dev/null
    elif have wget; then
        wget -q -O "$2" "$1" 2>/dev/null
    else
        return 1
    fi
}

# An endpoint that serves its SPA for unknown paths answers 200 with HTML.
# curl -f cannot see that, so sniff it ourselves and say so plainly.
looks_like_html() {
    head -c 512 "$1" 2>/dev/null | LC_ALL=C tr 'A-Z' 'a-z' | grep -q '<!doctype html\|<html'
}

reject_html() {
    if looks_like_html "$1"; then
        die "$2 returned an HTML page, not a file" \
            'The install endpoint is falling through to a web app instead of' \
            'serving the release artefacts. Nothing has been installed.'
    fi
}

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif have openssl; then
        openssl dgst -sha256 "$1" | sed 's/.*= *//'
    else
        die 'no SHA256 tool found (need sha256sum, shasum or openssl)' \
            'Verification is mandatory, so the install cannot continue.' \
            'macOS ships shasum; on Linux install coreutils or openssl.'
    fi
}

# Look the asset up in the release manifest, falling back to a per-asset
# sidecar for artefacts built outside the main release job (the Windows
# desktop bundle is produced by a separate workflow and is therefore absent
# from the release's checksums.txt).
# Sets the global EXPECTED. Deliberately NOT `EXPECTED=$(expected_sha ...)`:
# inside a command substitution `die` only kills the subshell, which makes
# failure modes here hard to reason about.
EXPECTED=''
expected_sha() {
    _asset="$1"; _tag="$2"

    _sums="$TMP_DIR/checksums.txt"
    if try_fetch "$BASE/$_tag/checksums.txt" "$_sums"; then
        reject_html "$_sums" 'the checksum manifest'
        # sha256sum writes "<hash>  <name>"; binary mode writes "<hash> *<name>"
        _hash=$(awk -v n="$_asset" '$2 == n || $2 == "*" n { print $1; exit }' "$_sums")
        if printf '%s' "$_hash" | grep -Eq '^[0-9a-fA-F]{64}$'; then
            EXPECTED="$_hash"; return 0
        fi
    fi

    _side="$TMP_DIR/sidecar.sha256"
    if try_fetch "$BASE/$_tag/$_asset.sha256" "$_side"; then
        reject_html "$_side" 'the checksum sidecar'
        _hash=$(awk '{ print $1; exit }' "$_side")
        if printf '%s' "$_hash" | grep -Eq '^[0-9a-fA-F]{64}$'; then
            EXPECTED="$_hash"; return 0
        fi
    fi

    die "no published checksum for $_asset at $_tag" \
        "Looked in $BASE/$_tag/checksums.txt" \
        "and       $BASE/$_tag/$_asset.sha256" \
        'Verification is mandatory, so the install has been aborted.'
}

pick_prefix() {
    if [ -n "$PREFIX" ]; then printf '%s' "$PREFIX"; return 0; fi
    # Per-user by default. Never silently escalate into /usr/local just
    # because it happens to be writable.
    if [ "$(id -u 2>/dev/null || printf 1)" = '0' ]; then
        printf '/usr/local/bin'
    elif [ -n "${HOME:-}" ]; then
        printf '%s/.local/bin' "$HOME"
    else
        die 'HOME is not set, so there is no per-user install directory' \
            'Pass one explicitly: ... | sh -s -- --prefix /somewhere/bin'
    fi
}

main() {
    parse_args "$@"
    check_base

    OS=$(detect_os)
    ARCH=$(detect_arch)
    ASSET="$BIN_NAME-$OS-$ARCH"
    PREFIX=$(pick_prefix)
    DEST="$PREFIX/$BIN_NAME"

    TMP_DIR=$(mktemp -d 2>/dev/null) || die 'could not create a temporary directory'
    trap cleanup EXIT INT TERM HUP

    if [ "$VERSION" = 'latest' ]; then
        VERSION=$(resolve_latest)
    else
        VERSION=$(normalize_version "$VERSION")
    fi
    TAG="v$VERSION"
    ASSET_URL="$BASE/$TAG/$ASSET"

    if [ -n "$PRINT_PLAN" ]; then
        printf 'os=%s\n'            "$OS"
        printf 'arch=%s\n'          "$ARCH"
        printf 'flavor=cli\n'
        printf 'asset=%s\n'         "$ASSET"
        printf 'version=%s\n'       "$VERSION"
        printf 'tag=%s\n'           "$TAG"
        printf 'base=%s\n'          "$BASE"
        printf 'asset_url=%s\n'     "$ASSET_URL"
        printf 'checksums_url=%s\n' "$BASE/$TAG/checksums.txt"
        printf 'prefix=%s\n'        "$PREFIX"
        printf 'dest=%s\n'          "$DEST"
        printf 'verify=required\n'
        exit 0
    fi

    mkdir -p "$PREFIX" 2>/dev/null \
        || die "cannot create $PREFIX — no write permission" \
               'Choose somewhere you own: ... | sh -s -- --prefix ~/bin'
    [ -w "$PREFIX" ] \
        || die "cannot write to $PREFIX — no write permission" \
               'Choose somewhere you own: ... | sh -s -- --prefix ~/bin'

    info "agenticode $VERSION ($OS-$ARCH)"

    expected_sha "$ASSET" "$TAG"

    info "Downloading $ASSET"
    fetch "$ASSET_URL" "$TMP_DIR/$ASSET" 'could not download the binary' progress
    reject_html "$TMP_DIR/$ASSET" 'the binary URL'

    ACTUAL=$(sha256_of "$TMP_DIR/$ASSET")
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        die 'SHA256 checksum mismatch — refusing to install' \
            "expected $EXPECTED" \
            "actual   $ACTUAL" \
            'The download does not match the published manifest. Nothing has' \
            'been changed on disk. Re-run; if it persists, do not install.'
    fi
    info "Checksum OK ($ACTUAL)"

    # Stage inside the destination directory so the final move is an atomic
    # rename on the same filesystem: an interrupted install can never leave a
    # half-written binary at $DEST, and replacing a running agenticode works
    # (rename-over is allowed; writing into the running file is not).
    STAGE="$PREFIX/.$BIN_NAME.install.$$"
    cp "$TMP_DIR/$ASSET" "$STAGE"
    chmod 0755 "$STAGE"
    mv -f "$STAGE" "$DEST"
    STAGE=''

    printf '\n%sInstalled agenticode %s%s — %s\n' "$C_B" "$VERSION" "$C_0" "$DEST"

    case ":${PATH:-}:" in
        *":$PREFIX:"*) ;;
        *)
            printf '\n'
            warn "$PREFIX is not on your PATH. Add it:"
            printf '\n    export PATH="%s:$PATH"\n' "$PREFIX"
            printf '\n  (put that in ~/.zshrc or ~/.bashrc to make it stick)\n'
            ;;
    esac

    # A different agenticode earlier on PATH would keep winning; say so rather
    # than let the user think the upgrade did nothing.
    if have "$BIN_NAME"; then
        WHICH=$(command -v "$BIN_NAME")
        if [ "$WHICH" != "$DEST" ]; then
            printf '\n'
            warn "another agenticode is earlier on your PATH: $WHICH"
            warn "it will be used instead of $DEST until you reorder PATH"
        fi
    fi

    printf '\nNext:\n'
    printf '  agenticode --version\n'
    printf '  agenticode login\n'
    printf '  agenticode doctor\n'
}

main "$@"

}
