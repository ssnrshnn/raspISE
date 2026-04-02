#!/usr/bin/env bash
# =============================================================================
#  RaspISE — Update Script
#  Pulls latest code from git and redeploys to /opt/raspise
# =============================================================================
set -euo pipefail

RASPISE_DIR="/opt/raspise"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$RASPISE_DIR/venv"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash scripts/update.sh"

info "Pulling latest code from git…"
cd "$REPO_DIR"
if git rev-parse --git-dir > /dev/null 2>&1; then
  git pull
else
  warn "REPO_DIR ($REPO_DIR) is not a git repository — skipping git pull."
  warn "Run this script from your local clone: sudo bash ~/raspISE/scripts/update.sh"
fi

info "Syncing source to $RASPISE_DIR…"
rsync -a --delete \
  --exclude='.git' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='venv' \
  --exclude='.venv' \
  "$REPO_DIR/" "$RASPISE_DIR/"

info "Updating Python dependencies…"
"$VENV/bin/pip" install --quiet -r "$RASPISE_DIR/requirements.txt"

info "Installing/updating systemd service units…"
cp "$RASPISE_DIR/systemd/raspise.service"         /etc/systemd/system/raspise.service
cp "$RASPISE_DIR/systemd/raspise-display.service" /etc/systemd/system/raspise-display.service

# Ensure log dir exists and logrotate config is current
mkdir -p /var/log/raspise
chown raspise:raspise /var/log/raspise 2>/dev/null || true
cp "$RASPISE_DIR/scripts/raspise.logrotate" /etc/logrotate.d/raspise 2>/dev/null || true

# Ensure config dir + file are writable by the service user
chown raspise:raspise /etc/raspise 2>/dev/null || true
chown raspise:raspise /etc/raspise/config.yaml 2>/dev/null || true
chmod 600 /etc/raspise/config.yaml 2>/dev/null || true

# Ensure polkit rule is current (replaces the old sudoers approach)
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/10-raspise.rules << 'EOF'
polkit.addRule(function(action, subject) {
    if (action.id === "org.freedesktop.systemd1.manage-units" &&
            (action.lookup("unit") === "raspise.service" ||
             action.lookup("unit") === "raspise-display.service") &&
            subject.user === "raspise") {
        return polkit.Result.YES;
    }
});
EOF
chmod 644 /etc/polkit-1/rules.d/10-raspise.rules
# Remove old sudoers rule if present
rm -f /etc/sudoers.d/raspise

info "Restarting raspise service…"
systemctl daemon-reload
systemctl restart raspise
systemctl restart raspise-display 2>/dev/null || true

sleep 2
systemctl status raspise --no-pager
