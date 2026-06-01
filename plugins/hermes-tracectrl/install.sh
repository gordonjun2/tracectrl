#!/bin/bash
set -euo pipefail

# Install TraceCtrl plugin for Hermes Agent
#
# Usage: ./install.sh [--endpoint URL] [--protocol http|grpc]
#
# This script:
#   1. Installs the tracectrl SDK and OTel dependencies via pip
#   2. Copies the plugin to ~/.hermes/plugins/observability/tracectrl/
#   3. Verifies TRACECTRL_ENDPOINT in ~/.hermes/.env (or prompts to add it)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENDPOINT="${TRACECTRL_ENDPOINT:-http://localhost:4318}"
PROTOCOL="${TRACECTRL_PROTOCOL:-http}"
SERVICE_NAME="${TRACECTRL_SERVICE_NAME:-hermes-agent}"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint)
      ENDPOINT="$2"
      shift 2
      ;;
    --endpoint=*)
      ENDPOINT="${1#*=}"
      shift
      ;;
    --protocol)
      PROTOCOL="$2"
      shift 2
      ;;
    --protocol=*)
      PROTOCOL="${1#*=}"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--endpoint URL] [--protocol http|grpc]"
      echo ""
      echo "Options:"
      echo "  --endpoint URL       OTLP collector endpoint (default: http://localhost:4318)"
      echo "  --protocol http|grpc OTLP transport protocol (default: http)"
      echo ""
      echo "Environment variables:"
      echo "  TRACECTRL_ENDPOINT    Override default OTLP collector endpoint"
      echo "  TRACECTRL_PROTOCOL    Override default transport protocol"
      echo "  TRACECTRL_SERVICE_NAME Override default service name"
      echo "  HERMES_HOME           Override default ~/.hermes install location"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  RED='\033[0;31m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  GREEN='' YELLOW='' RED='' BOLD='' RESET=''
fi

info()  { echo -e "${GREEN}[tracectrl]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[tracectrl]${RESET} $*"; }
error() { echo -e "${RED}[tracectrl]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Step 1: Install Python dependencies
# ---------------------------------------------------------------------------
info "Installing Python dependencies..."

if [ "$PROTOCOL" = "grpc" ]; then
  OTEL_PKG="opentelemetry-exporter-otlp-proto-grpc"
else
  OTEL_PKG="opentelemetry-exporter-otlp-proto-http"
fi

if pip install --quiet tracectrl "$OTEL_PKG" 2>/dev/null || \
   pip3 install --quiet tracectrl "$OTEL_PKG" 2>/dev/null; then
  info "Dependencies installed"
else
  warn "Could not install dependencies via pip. Install manually:"
  warn "  pip install tracectrl $OTEL_PKG"
fi

# ---------------------------------------------------------------------------
# Step 2: Copy plugin to ~/.hermes/plugins/observability/tracectrl/
# ---------------------------------------------------------------------------
HERMES_HOME="${HERMES_HOME:-${HOME}/.hermes}"
DEST_DIR="${HERMES_HOME}/plugins/observability/tracectrl"

info "Installing to ${DEST_DIR}..."
mkdir -p "${DEST_DIR}"

cp "${SCRIPT_DIR}/__init__.py" "${DEST_DIR}/__init__.py"
cp "${SCRIPT_DIR}/hooks.py" "${DEST_DIR}/hooks.py"
cp "${SCRIPT_DIR}/config.py" "${DEST_DIR}/config.py"
cp "${SCRIPT_DIR}/telemetry.py" "${DEST_DIR}/telemetry.py"
cp "${SCRIPT_DIR}/security.py" "${DEST_DIR}/security.py"
cp "${SCRIPT_DIR}/plugin.yaml" "${DEST_DIR}/plugin.yaml"

info "Plugin installed to ${DEST_DIR}"

# ---------------------------------------------------------------------------
# Step 3: Verify / add config to .env
# ---------------------------------------------------------------------------
ENV_FILE="${HERMES_HOME}/.env"

TC_BLOCK=""
TC_BLOCK+="\n# TraceCtrl observability\n"
TC_BLOCK+="TRACECTRL_ENDPOINT=${ENDPOINT}\n"
TC_BLOCK+="TRACECTRL_PROTOCOL=${PROTOCOL}\n"
TC_BLOCK+="TRACECTRL_SERVICE_NAME=${SERVICE_NAME}\n"
TC_BLOCK+="#TRACECTRL_API_KEY=your-api-key\n"
TC_BLOCK+="#TRACECTRL_CAPTURE_CONTENT=false\n"

if [[ -f "$ENV_FILE" ]]; then
  if grep -q "^TRACECTRL_ENDPOINT=" "$ENV_FILE" 2>/dev/null; then
    info "TRACECTRL_ENDPOINT already set in ${ENV_FILE}"
  else
    echo -e "$TC_BLOCK" >> "$ENV_FILE"
    info "Added TraceCtrl config to ${ENV_FILE}"
  fi
else
  warn "No .env file found at ${ENV_FILE}"
  warn "Create one with:"
  echo -e "$TC_BLOCK"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}====================================${RESET}"
echo -e "${GREEN}  TraceCtrl Hermes plugin installed${RESET}"
echo -e "${BOLD}====================================${RESET}"
echo ""
echo "  Plugin location:  ${DEST_DIR}"
echo "  OTLP endpoint:    ${ENDPOINT}"
echo "  Protocol:         ${PROTOCOL}"
echo "  Service name:     ${SERVICE_NAME}"
echo ""
echo "  To enable the plugin:"
echo ""
echo "    hermes plugins enable observability/tracectrl"
echo ""
echo -e "  ${YELLOW}Restart Hermes to activate:${RESET}"
echo "    hermes restart"
echo ""
