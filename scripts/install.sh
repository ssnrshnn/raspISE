#!/usr/bin/env bash
# =============================================================================
#  RaspISE — Installation Script
#  Tested on: Raspberry Pi OS 64-bit Lite (Bookworm)
#  Target:    Raspberry Pi Zero 2W
# =============================================================================
set -euo pipefail

RASPISE_USER="raspise"
RASPISE_DIR="/opt/raspise"
CONFIG_DIR="/etc/raspise"
DATA_DIR="/var/lib/raspise"
LOG_DIR="/var/log/raspise"
VENV="$RASPISE_DIR/venv"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash scripts/install.sh"

# ─── 1. System packages ───────────────────────────────────────────────────────
info "Updating package list…"
apt-get update -qq

info "Installing system dependencies…"
apt-get install -y -qq \
  python3 python3-pip python3-venv python3-dev \
  libssl-dev libffi-dev \
  gcc g++ git curl \
  iptables iptables-persistent \
  # SPI / GPIO for TFT display
  python3-spidev python3-rpi.gpio \
  # Font for TFT rendering
  fonts-dejavu-core

# ─── 2. SPI enable ────────────────────────────────────────────────────────────
info "Enabling SPI interface…"
if ! grep -q "^dtparam=spi=on" /boot/firmware/config.txt 2>/dev/null; then
  echo "dtparam=spi=on" >> /boot/firmware/config.txt
  warn "SPI enabled — a reboot will be required after install."
fi

# ─── 3. Create system user ────────────────────────────────────────────────────
info "Creating system user: $RASPISE_USER"
if ! id "$RASPISE_USER" &>/dev/null; then
  useradd --system --no-create-home \
    --groups gpio,spi,i2c,netdev \
    --shell /usr/sbin/nologin \
    "$RASPISE_USER"
fi

# ─── 4. Create directories ────────────────────────────────────────────────────
info "Creating directories…"
mkdir -p "$RASPISE_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chown "$RASPISE_USER:$RASPISE_USER" "$DATA_DIR" "$LOG_DIR"

# ─── 5. Copy source ───────────────────────────────────────────────────────────
info "Installing RaspISE to $RASPISE_DIR…"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='venv' --exclude='.venv' \
  "$REPO_DIR/" "$RASPISE_DIR/"

# ─── 6. Python virtual environment ───────────────────────────────────────────
info "Creating Python virtual environment…"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip setuptools wheel

info "Installing Python dependencies (this may take several minutes on Pi Zero 2W)…"
"$VENV/bin/pip" install --quiet -r "$RASPISE_DIR/requirements.txt"

# Pi-specific display libraries
info "Installing Pi display libraries…"
"$VENV/bin/pip" install --quiet \
  adafruit-circuitpython-ili9341 \
  adafruit-blinka \
  st7789 \
  || warn "Display libraries install had warnings — check manually if display doesn't work."

# ─── 7. Config file ───────────────────────────────────────────────────────────
info "Setting up configuration…"
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  cp "$RASPISE_DIR/raspise/config/config.yaml" "$CONFIG_DIR/config.yaml"
  # Generate random secret key
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/CHANGE_ME_USE_A_STRONG_RANDOM_STRING/$SECRET/" "$CONFIG_DIR/config.yaml"
  warn "Config written to $CONFIG_DIR/config.yaml — edit NAS clients and secrets!"
else
  warn "Config already exists at $CONFIG_DIR/config.yaml — not overwriting."
fi
chown root:"$RASPISE_USER" "$CONFIG_DIR/config.yaml"
chmod 640 "$CONFIG_DIR/config.yaml"

# ─── 8. Download OUI database ─────────────────────────────────────────────────
info "Downloading IEEE OUI database…"
OUI_URL="https://standards-oui.ieee.org/oui/oui.csv"
if curl -sf --connect-timeout 10 "$OUI_URL" -o "$DATA_DIR/oui.csv"; then
  chown "$RASPISE_USER:$RASPISE_USER" "$DATA_DIR/oui.csv"
  info "OUI database downloaded ($(wc -l < "$DATA_DIR/oui.csv") entries)"
else
  warn "Could not download OUI database — device vendor lookup will be unavailable."
  touch "$DATA_DIR/oui.csv"
fi

# ─── 9. Systemd services ──────────────────────────────────────────────────────
info "Installing systemd service files…"
cp "$RASPISE_DIR/systemd/raspise.service"         /etc/systemd/system/
cp "$RASPISE_DIR/systemd/raspise-display.service" /etc/systemd/system/

# Patch paths in service files
sed -i "s|/opt/raspise|$RASPISE_DIR|g" /etc/systemd/system/raspise.service
sed -i "s|/opt/raspise|$RASPISE_DIR|g" /etc/systemd/system/raspise-display.service

systemctl daemon-reload
systemctl enable raspise.service raspise-display.service

# ─── 10. iptables captive portal redirect ─────────────────────────────────────
info "Setting up captive portal iptables rules…"
# Redirect HTTP (80) from guest VLAN to portal (8082) — adjust GUEST_IFACE as needed
GUEST_IFACE="${GUEST_IFACE:-wlan0}"
iptables -t nat -A PREROUTING -i "$GUEST_IFACE" -p tcp --dport 80 \
  -j REDIRECT --to-port 8082 2>/dev/null || warn "iptables redirect rule skipped (may already exist)"
netfilter-persistent save 2>/dev/null || warn "netfilter-persistent save failed"

# ─── 11. First run ────────────────────────────────────────────────────────────
info "Initialising database…"
RASPISE_CONFIG="$CONFIG_DIR/config.yaml" \
  "$VENV/bin/python" -c "
import asyncio
from raspise.db import init_db
asyncio.run(init_db())
print('Database initialised.')
"

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   RaspISE installation complete!                         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  1. Edit config:  sudo nano $CONFIG_DIR/config.yaml   ${NC}"
echo -e "${GREEN}║  2. Start:        sudo systemctl start raspise           ║${NC}"
echo -e "${GREEN}║  3. Admin UI:     http://$(hostname -I | awk '{print $1}'):8080      ║${NC}"
echo -e "${GREEN}║  4. Default creds: admin / RaspISE@admin1                ║${NC}"
echo -e "${GREEN}║     ⚠ Change password on first login!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
