#!/usr/bin/env bash
# =============================================================================
#  RaspISE — Display Setup Script
#  Configures SPI and installs the correct TFT display driver.
#
#  Usage:
#    sudo bash scripts/setup_display.sh [ili9341|st7789]
#
#  Default: ili9341 (most common 2.4" 240x320 module)
# =============================================================================
set -euo pipefail

DRIVER="${1:-ili9341}"
CONFIG_FILE="/etc/raspise/config.yaml"
BOOT_CONFIG="/boot/firmware/config.txt"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash scripts/setup_display.sh"

case "$DRIVER" in
  ili9341|st7789|simulation) ;;
  *) error "Unknown driver '$DRIVER'. Choose: ili9341, st7789, or simulation" ;;
esac

# ─── 1. SPI kernel module ─────────────────────────────────────────────────────
info "Checking SPI configuration…"
if ! grep -q "^dtparam=spi=on" "$BOOT_CONFIG" 2>/dev/null; then
  echo "dtparam=spi=on" >> "$BOOT_CONFIG"
  warn "SPI added to $BOOT_CONFIG"
fi

# Remove conflicting overlays
sed -i '/^dtoverlay=spi-dev/d' "$BOOT_CONFIG" 2>/dev/null || true

# ─── 2. Driver-specific boot overlays ────────────────────────────────────────
if [[ "$DRIVER" == "ili9341" ]]; then
  info "Configuring ILI9341 overlay…"
  # Standard wiring: CE0 (BCM8), DC=BCM24, RST=BCM25
  if ! grep -q "dtoverlay=ili9341" "$BOOT_CONFIG"; then
    cat >> "$BOOT_CONFIG" << 'EOF'
# RaspISE ILI9341 TFT Display
dtoverlay=ili9341,speed=40000000,rotate=270,fps=60
EOF
  fi
elif [[ "$DRIVER" == "st7789" ]]; then
  info "Configuring ST7789 overlay…"
  if ! grep -q "dtoverlay=st7789v" "$BOOT_CONFIG"; then
    cat >> "$BOOT_CONFIG" << 'EOF'
# RaspISE ST7789 TFT Display
dtoverlay=st7789v,speed=40000000,width=240,height=320,dc_pin=24,reset_pin=25,fps=60
EOF
  fi
fi

# ─── 3. Python libraries ──────────────────────────────────────────────────────
VENV="/opt/raspise/venv"
PIP="$VENV/bin/pip"

if [[ ! -x "$PIP" ]]; then
  warn "RaspISE venv not found at $VENV — install RaspISE first (scripts/install.sh)"
  PIP="pip3"
fi

if [[ "$DRIVER" == "ili9341" ]]; then
  info "Installing Adafruit CircuitPython ILI9341 driver…"
  "$PIP" install --quiet \
    adafruit-blinka \
    adafruit-circuitpython-ili9341 \
    adafruit-circuitpython-rgb-display \
    RPi.GPIO

elif [[ "$DRIVER" == "st7789" ]]; then
  info "Installing ST7789 driver…"
  "$PIP" install --quiet \
    st7789 \
    RPi.GPIO

elif [[ "$DRIVER" == "simulation" ]]; then
  info "Simulation mode — no hardware driver needed."
fi

# ─── 4. Update RaspISE config ─────────────────────────────────────────────────
if [[ -f "$CONFIG_FILE" ]]; then
  info "Updating display driver in $CONFIG_FILE…"
  sed -i "s/^  driver:.*/  driver: $DRIVER/" "$CONFIG_FILE"
  info "Display driver set to: $DRIVER"
else
  warn "Config file not found: $CONFIG_FILE"
  warn "Manually set 'display.driver: $DRIVER' in your config.yaml"
fi

# ─── 5. Permission for SPI/GPIO devices ──────────────────────────────────────
info "Setting up device permissions…"
for GRP in spi gpio; do
  if getent group "$GRP" &>/dev/null; then
    usermod -aG "$GRP" raspise 2>/dev/null || true
    info "  Added 'raspise' to group '$GRP'"
  fi
done

# udev rules so the raspise user can access SPI/GPIO without root
cat > /etc/udev/rules.d/99-raspise-display.rules << 'EOF'
# RaspISE display access
SUBSYSTEM=="spidev", GROUP="spi", MODE="0660"
SUBSYSTEM=="gpio", GROUP="gpio", MODE="0660"
EOF
udevadm control --reload-rules

# ─── 6. Quick wiring reference ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Display setup complete — driver: $DRIVER               ${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Wiring (Pi Zero 2W 40-pin header):                      ║${NC}"
echo -e "${GREEN}║   TFT VCC  → Pin 1  (3.3V)                               ║${NC}"
echo -e "${GREEN}║   TFT GND  → Pin 6  (GND)                                ║${NC}"
echo -e "${GREEN}║   TFT CLK  → Pin 23 (BCM11 / SCLK)                      ║${NC}"
echo -e "${GREEN}║   TFT MOSI → Pin 19 (BCM10 / MOSI)                      ║${NC}"
echo -e "${GREEN}║   TFT CS   → Pin 24 (BCM8  / CE0)                       ║${NC}"
echo -e "${GREEN}║   TFT DC   → Pin 18 (BCM24)                              ║${NC}"
echo -e "${GREEN}║   TFT RST  → Pin 22 (BCM25)                              ║${NC}"
echo -e "${GREEN}║   TFT LED  → Pin 17 (3.3V) or PWM for dimming           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  IMPORTANT: Reboot required for SPI overlay to take      ║${NC}"
echo -e "${GREEN}║  effect:   sudo reboot                                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
