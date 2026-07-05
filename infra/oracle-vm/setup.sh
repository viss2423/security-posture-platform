#!/usr/bin/env bash
# Oracle Cloud Always Free ARM VM — one-shot bootstrap
# Run as a non-root user with sudo access.
# Usage: curl -fsSL https://raw.githubusercontent.com/YOUR_REPO/main/infra/oracle-vm/setup.sh | bash
#   or:  git clone ... && cd infra/oracle-vm && bash setup.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$REPO_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${GREEN}══════════════════════════════════════${NC}"; info "$*"; }

# ── 0. Preflight ───────────────────────────────────────────────────────────────
step "Preflight checks"
[[ "$(uname -m)" == aarch64 ]] || warn "Expected ARM64 (aarch64) — you're on $(uname -m)"
[[ "$EUID" -ne 0 ]] || error "Do not run as root — run as a sudo-capable user"
command -v curl &>/dev/null || error "curl not found"

if [ ! -f "$COMPOSE_DIR/.env" ]; then
  if [ -f "$COMPOSE_DIR/.env.example" ]; then
    cp "$COMPOSE_DIR/.env.example" "$COMPOSE_DIR/.env"
    warn ".env created from .env.example — EDIT IT BEFORE CONTINUING"
    warn "  nano $COMPOSE_DIR/.env"
    read -rp "Press Enter once you've filled in .env, or Ctrl+C to abort..."
  else
    error ".env not found — copy .env.example and fill in your secrets"
  fi
fi
source "$COMPOSE_DIR/.env"

# ── 1. System packages ─────────────────────────────────────────────────────────
step "Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y -qq \
  apt-transport-https ca-certificates curl gnupg lsb-release \
  git jq unzip python3-pip htop ufw fail2ban

# ── 2. Docker ─────────────────────────────────────────────────────────────────
step "Installing Docker"
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sudo bash
  sudo usermod -aG docker "$USER"
  info "Docker installed — you may need to log out and back in for group membership"
else
  info "Docker already installed: $(docker --version)"
fi

# Docker Compose v2 plugin
if ! docker compose version &>/dev/null; then
  sudo apt-get install -y -qq docker-compose-plugin
fi
info "Docker Compose: $(docker compose version)"

# ── 3. Kernel tuning ──────────────────────────────────────────────────────────
step "Kernel parameters (required for Elasticsearch/OpenSearch)"
sudo sysctl -w vm.max_map_count=1048575
grep -q 'vm.max_map_count' /etc/sysctl.conf \
  && sudo sed -i 's/vm.max_map_count.*/vm.max_map_count=1048575/' /etc/sysctl.conf \
  || echo 'vm.max_map_count=1048575' | sudo tee -a /etc/sysctl.conf
info "vm.max_map_count=$(sysctl -n vm.max_map_count)"

# ── 4. Firewall ───────────────────────────────────────────────────────────────
step "Configuring UFW firewall"
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp    # Wazuh cert gen / future Nginx
sudo ufw allow 443/tcp   # Wazuh dashboard
sudo ufw allow 3567/tcp  # SuperTokens
sudo ufw allow 8080/tcp  # DefectDojo
sudo ufw allow 8082/tcp  # Claude proxy
sudo ufw allow 8083/tcp  # ClaudeSlim
sudo ufw allow 8090/tcp  # OpenCTI
sudo ufw allow 8180/tcp  # Keycloak
sudo ufw allow 9091/tcp  # Authelia
sudo ufw allow 1514/udp  # Wazuh agent events
sudo ufw allow 1515/tcp  # Wazuh agent enrollment
sudo ufw --force enable
info "UFW status:"
sudo ufw status numbered

# ── 5. Fail2ban ────────────────────────────────────────────────────────────────
step "Enabling fail2ban"
sudo systemctl enable --now fail2ban
info "fail2ban active: $(sudo fail2ban-client status | head -1)"

# ── 6. Clone free-claude-code proxy ───────────────────────────────────────────
step "Setting up free-claude-code proxy"
PROXY_SRC="$COMPOSE_DIR/build/free-claude-code"
if [ ! -d "$PROXY_SRC" ]; then
  git clone --depth=1 https://github.com/Alishahryar1/free-claude-code "$PROXY_SRC"
  info "Cloned free-claude-code proxy to $PROXY_SRC"
else
  info "free-claude-code already present — pulling latest"
  git -C "$PROXY_SRC" pull --ff-only
fi

# Install Python deps for proxy build
pip3 install uv --quiet
(cd "$PROXY_SRC" && uv sync --quiet)
info "Proxy dependencies installed"

# ── 7. Pull Docker images ──────────────────────────────────────────────────────
step "Pulling Docker images (this takes a few minutes)"
docker compose -f "$COMPOSE_DIR/docker-compose.auth.yml"      pull --quiet
docker compose -f "$COMPOSE_DIR/docker-compose.defectdojo.yml" pull --quiet
docker compose -f "$COMPOSE_DIR/docker-compose.opencti.yml"   pull --quiet
info "Base images pulled. Wazuh requires cert generation — run start-wazuh.sh separately."

# ── 8. Start core services ─────────────────────────────────────────────────────
step "Starting auth stack (SuperTokens + Keycloak + Authelia)"
docker compose -f "$COMPOSE_DIR/docker-compose.auth.yml" up -d
info "Auth stack started"

step "Starting DefectDojo"
docker compose -f "$COMPOSE_DIR/docker-compose.defectdojo.yml" up -d
info "DefectDojo starting (first boot takes ~2 min)"

step "Starting OpenCTI"
docker compose -f "$COMPOSE_DIR/docker-compose.opencti.yml" up -d
info "OpenCTI starting (first boot takes ~3 min — Elasticsearch init)"

step "Building and starting Claude proxy"
docker compose -f "$COMPOSE_DIR/docker-compose.proxy.yml" up -d --build
info "Claude proxy + ClaudeSlim started"

# ── 9. Wazuh cert generation (interactive) ────────────────────────────────────
step "Wazuh TLS certificates"
WAZUH_CERT_DIR="$COMPOSE_DIR/config/wazuh/wazuh_indexer_ssl_certs"
if [ ! -d "$WAZUH_CERT_DIR" ] || [ -z "$(ls -A "$WAZUH_CERT_DIR" 2>/dev/null)" ]; then
  mkdir -p "$WAZUH_CERT_DIR"
  warn "Wazuh requires TLS certificates. Generating now..."
  curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh
  curl -sO https://packages.wazuh.com/4.9/config.yml
  cat > config.yml <<WAZUHCFG
nodes:
  indexer:
    - name: wazuh.indexer
      ip: "127.0.0.1"
  server:
    - name: wazuh.manager
      ip: "127.0.0.1"
  dashboard:
    - name: wazuh.dashboard
      ip: "127.0.0.1"
WAZUHCFG
  bash ./wazuh-certs-tool.sh -A
  tar -xf ./wazuh-certificates.tar -C "$WAZUH_CERT_DIR" --strip-components=1
  rm -f wazuh-certs-tool.sh config.yml wazuh-certificates.tar
  info "Wazuh certs generated in $WAZUH_CERT_DIR"
  docker compose -f "$COMPOSE_DIR/docker-compose.wazuh.yml" up -d
  info "Wazuh started"
else
  info "Wazuh certs already present — starting Wazuh"
  docker compose -f "$COMPOSE_DIR/docker-compose.wazuh.yml" up -d
fi

# ── 10. Summary ────────────────────────────────────────────────────────────────
VM_IP=$(curl -s https://ifconfig.me 2>/dev/null || echo "<your-vm-ip>")
step "Setup complete!"
echo ""
echo "  Service          URL"
echo "  ───────────────────────────────────────────────────"
echo "  DefectDojo       http://$VM_IP:8080   admin/defectdojo"
echo "  Wazuh            https://$VM_IP:443   admin/<WAZUH_INDEXER_PASSWORD>"
echo "  OpenCTI          http://$VM_IP:8090   admin@opencti.io/<OPENCTI_ADMIN_PASSWORD>"
echo "  Keycloak         http://$VM_IP:8180   admin/<KEYCLOAK_ADMIN_PASSWORD>"
echo "  Authelia         http://$VM_IP:9091   admin/<see users_database.yml>"
echo "  SuperTokens      http://$VM_IP:3567   (API only — use SDK)"
echo "  Claude proxy     http://$VM_IP:8082"
echo "  ClaudeSlim       http://$VM_IP:8083"
echo ""
warn "Change all default passwords before exposing this VM to the internet."
warn "Point your local ANTHROPIC_BASE_URL=http://$VM_IP:8082 and ANTHROPIC_AUTH_TOKEN=freecc"
echo ""
info "Check service health: docker compose -f docker-compose.*.yml ps"
