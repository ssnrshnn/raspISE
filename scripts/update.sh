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

info "Running database migrations…"
DB_PATH="/var/lib/raspise/raspise.db"
if [[ -f "$DB_PATH" ]]; then
  # If the DB exists but has no alembic_version table, stamp it with
  # the initial schema revision so future migrations apply cleanly.
  HAS_ALEMBIC=$("$VENV/bin/python" -c "
import sqlite3, sys
con = sqlite3.connect('$DB_PATH')
cur = con.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'\")
print('yes' if cur.fetchone() else 'no')
con.close()
")
  if [[ "$HAS_ALEMBIC" == "no" ]]; then
    info "First-time Alembic setup — stamping existing DB with initial revision…"
    cd "$RASPISE_DIR"
    "$VENV/bin/python" -m alembic stamp bd6e57d105df
  fi
fi
cd "$RASPISE_DIR"
"$VENV/bin/python" -m alembic upgrade head

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

# Migrate old portal config keys (renamed in v1.1)
# session_duration_hours → session_hours, wifi_ssid → guest_ssid, wifi_password → guest_psk
CFG=/etc/raspise/config.yaml
if [[ -f "$CFG" ]]; then
  sed -i 's/session_duration_hours:/session_hours:/g' "$CFG"
  sed -i 's/wifi_ssid:/guest_ssid:/g' "$CFG"
  sed -i 's/wifi_password:/guest_psk:/g' "$CFG"
fi

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
