#!/bin/sh
# envdrift universal installer for macOS and Linux
# Usage: curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh
#    or: curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh -s -- [options]
#
# Options:
#   --no-agent          Skip downloading the envdrift-agent binary
#   --version X.Y.Z     Install a specific envdrift version
#   --agent-version X.Y.Z  Install a specific agent version
#   --uninstall         Remove envdrift installation
#   --help              Show this help message

set -eu

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
INSTALL_DIR="${HOME}/.envdrift"
VENV_DIR="${INSTALL_DIR}/venv"
BIN_DIR="${INSTALL_DIR}/bin"
GITHUB_REPO="jainal09/envdrift"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11

# -------------------------------------------------------------------
# Defaults
# -------------------------------------------------------------------
INSTALL_AGENT=1
ENVDRIFT_VERSION=""
AGENT_VERSION=""
UNINSTALL=0

# -------------------------------------------------------------------
# Cleanup trap
# -------------------------------------------------------------------
TMP_FILES=""
cleanup() {
    for f in ${TMP_FILES}; do
        rm -f "${f}" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

add_tmp() {
    TMP_FILES="${TMP_FILES} $1"
}

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
info()  { printf '  \033[1;34m>\033[0m %s\n' "$*"; }
ok()    { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[1;33m⚠\033[0m %s\n' "$*" >&2; }
err()   { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; }
die()   { err "$@"; exit 1; }

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "Required command not found: $1"
    fi
}

# Portable download helper (curl preferred, wget fallback)
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "${dest}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${dest}" "${url}"
    else
        die "Neither curl nor wget found. Please install one of them."
    fi
}

# -------------------------------------------------------------------
# Argument parsing
# -------------------------------------------------------------------
usage() {
    cat <<'EOF'
envdrift installer

Usage:
  install.sh [options]

Options:
  --no-agent              Skip downloading the envdrift-agent binary
  --version X.Y.Z         Install a specific envdrift Python package version
  --agent-version X.Y.Z   Install a specific agent binary version
  --uninstall             Remove the envdrift installation (~/.envdrift)
  --help                  Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-agent)
            INSTALL_AGENT=0
            shift
            ;;
        --version)
            [ $# -ge 2 ] || die "--version requires a value"
            ENVDRIFT_VERSION="$2"
            shift 2
            ;;
        --agent-version)
            [ $# -ge 2 ] || die "--agent-version requires a value"
            AGENT_VERSION="$2"
            shift 2
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
    esac
done

# -------------------------------------------------------------------
# Uninstall
# -------------------------------------------------------------------
if [ "${UNINSTALL}" -eq 1 ]; then
    info "Uninstalling envdrift..."
    if [ -d "${VENV_DIR}" ]; then
        rm -rf "${VENV_DIR}"
        ok "Removed ${VENV_DIR}"
    fi
    if [ -d "${BIN_DIR}" ]; then
        rm -rf "${BIN_DIR}"
        ok "Removed ${BIN_DIR}"
    fi
    # Remove install dir only if empty (preserve projects.json etc.)
    if [ -d "${INSTALL_DIR}" ]; then
        if [ -z "$(ls -A "${INSTALL_DIR}" 2>/dev/null)" ]; then
            rmdir "${INSTALL_DIR}"
            ok "Removed ${INSTALL_DIR}"
        else
            warn "${INSTALL_DIR} not empty — kept remaining files (e.g. projects.json)"
        fi
    fi
    ok "envdrift uninstalled"
    exit 0
fi

# -------------------------------------------------------------------
# Banner
# -------------------------------------------------------------------
printf '\n\033[1m  envdrift installer\033[0m\n\n'

# -------------------------------------------------------------------
# Detect OS & architecture
# -------------------------------------------------------------------
detect_platform() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "${os}" in
        darwin) os="darwin" ;;
        linux)  os="linux"  ;;
        *)      die "Unsupported OS: ${os}" ;;
    esac

    case "${arch}" in
        x86_64|amd64)   arch="amd64" ;;
        arm64|aarch64)  arch="arm64" ;;
        *)              die "Unsupported architecture: ${arch}" ;;
    esac

    PLATFORM="${os}-${arch}"
    info "Detected platform: ${PLATFORM}"
}

# -------------------------------------------------------------------
# Find Python ≥ 3.11
# -------------------------------------------------------------------
find_python() {
    # Try common names first
    for cmd in python3 python; do
        if command -v "${cmd}" >/dev/null 2>&1; then
            ver="$("${cmd}" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)"
            if [ -n "${ver}" ]; then
                major="${ver%%.*}"
                minor="${ver#*.}"
                if [ "${major}" -eq ${MIN_PYTHON_MAJOR} ] && [ "${minor}" -ge ${MIN_PYTHON_MINOR} ]; then
                    PYTHON="$(command -v "${cmd}")"
                    info "Found Python ${ver} at ${PYTHON}"
                    return
                fi
            fi
        fi
    done

    # Try version-specific names (3.19 down to 3.11)
    minor=19
    while [ ${minor} -ge ${MIN_PYTHON_MINOR} ]; do
        cmd="python3.${minor}"
        if command -v "${cmd}" >/dev/null 2>&1; then
            PYTHON="$(command -v "${cmd}")"
            ver="$("${PYTHON}" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)"
            info "Found Python ${ver} at ${PYTHON}"
            return
        fi
        minor=$((minor - 1))
    done

    die "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ is required but not found. Please install Python first."
}

# -------------------------------------------------------------------
# Ensure venv module is available (fallback to virtualenv.pyz)
# -------------------------------------------------------------------
ensure_venv() {
    if "${PYTHON}" -c "import venv" 2>/dev/null; then
        return
    fi

    warn "Python venv module not available — downloading virtualenv bootstrap"
    VIRTUALENV_PYZ="${INSTALL_DIR}/virtualenv.pyz"
    add_tmp "${VIRTUALENV_PYZ}"
    mkdir -p "${INSTALL_DIR}"
    download "https://bootstrap.pypa.io/virtualenv.pyz" "${VIRTUALENV_PYZ}"

    # Verify the downloaded file is a valid zip/pyz (basic sanity check)
    if ! "${PYTHON}" -c "import zipfile, sys; z=zipfile.ZipFile(sys.argv[1]); z.testzip(); z.close()" "${VIRTUALENV_PYZ}" 2>/dev/null; then
        die "Downloaded virtualenv.pyz is not a valid archive. Aborting for safety."
    fi

    USE_VIRTUALENV_PYZ=1
}

# -------------------------------------------------------------------
# Create / reuse virtual environment
# -------------------------------------------------------------------
setup_venv() {
    if [ -d "${VENV_DIR}" ] && [ -x "${VENV_DIR}/bin/python" ]; then
        info "Reusing existing venv at ${VENV_DIR}"
    else
        info "Creating virtual environment at ${VENV_DIR}"
        mkdir -p "${INSTALL_DIR}"
        if [ "${USE_VIRTUALENV_PYZ:-0}" = "1" ]; then
            "${PYTHON}" "${VIRTUALENV_PYZ}" "${VENV_DIR}"
        else
            "${PYTHON}" -m venv "${VENV_DIR}"
        fi
    fi

    VENV_PYTHON="${VENV_DIR}/bin/python"
    VENV_PIP="${VENV_DIR}/bin/pip"

    # Upgrade pip silently
    "${VENV_PYTHON}" -m pip install --upgrade pip >/dev/null 2>&1 || true
}

# -------------------------------------------------------------------
# Install envdrift Python package
# -------------------------------------------------------------------
install_envdrift() {
    pkg="envdrift[vault]"
    if [ -n "${ENVDRIFT_VERSION}" ]; then
        pkg="envdrift[vault]==${ENVDRIFT_VERSION}"
    fi

    info "Installing ${pkg} ..."
    "${VENV_PIP}" install --upgrade "${pkg}" || die "pip install failed"
    ok "envdrift Python package installed"
}

# -------------------------------------------------------------------
# Create wrapper script
# -------------------------------------------------------------------
create_wrapper() {
    mkdir -p "${BIN_DIR}"

    wrapper="${BIN_DIR}/envdrift"
    cat > "${wrapper}" <<WRAPPER
#!/bin/sh
# envdrift wrapper — delegates to the venv installation
exec "${VENV_DIR}/bin/envdrift" "\$@"
WRAPPER
    chmod +x "${wrapper}"
    ok "Created wrapper at ${wrapper}"
}

# -------------------------------------------------------------------
# Download agent binary
# -------------------------------------------------------------------
install_agent() {
    if [ "${INSTALL_AGENT}" -eq 0 ]; then
        info "Skipping agent download (--no-agent)"
        return
    fi

    # Determine download URL
    if [ -n "${AGENT_VERSION}" ]; then
        base_url="https://github.com/${GITHUB_REPO}/releases/download/agent-v${AGENT_VERSION}"
    else
        base_url="https://github.com/${GITHUB_REPO}/releases/latest/download"
    fi

    binary_name="envdrift-agent-${PLATFORM}"
    agent_url="${base_url}/${binary_name}"
    checksum_url="${base_url}/checksums.txt"
    dest="${BIN_DIR}/envdrift-agent"

    info "Downloading envdrift-agent for ${PLATFORM} ..."

    tmp_binary="$(mktemp)"
    add_tmp "${tmp_binary}"

    if ! download "${agent_url}" "${tmp_binary}" 2>/dev/null; then
        warn "Could not download agent binary from ${agent_url}"
        warn "The agent can be installed later with: envdrift install agent"
        return
    fi

    # Verify checksum (best-effort)
    verify_checksum "${tmp_binary}" "${binary_name}" "${checksum_url}"

    mv "${tmp_binary}" "${dest}"
    chmod +x "${dest}"
    ok "Installed envdrift-agent to ${dest}"
}

# -------------------------------------------------------------------
# SHA256 checksum verification
# -------------------------------------------------------------------
verify_checksum() {
    file="$1"
    name="$2"
    url="$3"

    tmp_checksums="$(mktemp)"
    add_tmp "${tmp_checksums}"

    if ! download "${url}" "${tmp_checksums}" 2>/dev/null; then
        warn "Checksums file not available — skipping verification"
        return
    fi

    expected=""
    while IFS= read -r line; do
        # Format: "sha256  filename"
        cs_hash="$(echo "${line}" | awk '{print $1}')"
        cs_file="$(echo "${line}" | awk '{print $NF}')"
        if [ "${cs_file}" = "${name}" ]; then
            expected="${cs_hash}"
            break
        fi
    done < "${tmp_checksums}"

    if [ -z "${expected}" ]; then
        warn "No checksum entry for ${name} — skipping verification"
        return
    fi

    # Compute SHA256
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${file}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "${file}" | awk '{print $1}')"
    else
        warn "No sha256sum or shasum found — skipping verification"
        return
    fi

    if [ "${actual}" != "${expected}" ]; then
        die "Checksum mismatch! Expected ${expected}, got ${actual}. Aborting."
    fi

    ok "Checksum verified"
}

# -------------------------------------------------------------------
# PATH instructions
# -------------------------------------------------------------------
print_path_instructions() {
    case ":${PATH}:" in
        *":${BIN_DIR}:"*)
            return
            ;;
    esac

    printf '\n'
    warn "${BIN_DIR} is not in your PATH."
    printf '\n'
    info "Add it to your shell configuration:"
    printf '\n'

    shell_name="$(basename "${SHELL:-sh}")"
    case "${shell_name}" in
        zsh)
            printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc\n' "${BIN_DIR}"
            printf '    source ~/.zshrc\n'
            ;;
        bash)
            printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.bashrc\n' "${BIN_DIR}"
            printf '    source ~/.bashrc\n'
            ;;
        fish)
            printf '    set -Ux fish_user_paths %s $fish_user_paths\n' "${BIN_DIR}"
            ;;
        *)
            printf '    export PATH="%s:$PATH"\n' "${BIN_DIR}"
            ;;
    esac

    printf '\n'
    info "Or run directly with: ${BIN_DIR}/envdrift"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    detect_platform
    find_python
    ensure_venv
    setup_venv
    install_envdrift
    create_wrapper
    install_agent
    print_path_instructions

    printf '\n\033[1;32m  ✓ envdrift installation complete!\033[0m\n\n'
}

main
