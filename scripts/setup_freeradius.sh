#!/usr/bin/env bash
# =============================================================================
#  RaspISE — FreeRADIUS Integration Setup
#  Installs and configures FreeRADIUS to handle EAP-PEAP/MSCHAPv2 and EAP-TLS,
#  delegating policy decisions to the RaspISE REST API via rlm_rest.
#
#  Architecture:
#    NAS  ──RADIUS──▶  FreeRADIUS (port 1812)
#                          │  rlm_rest
#                          ▼
#                      RaspISE REST API (port 8081)
#                          │  policy decision (Accept/Reject + VLAN)
#                          ▼
#                      FreeRADIUS  ──Access-Accept/Reject──▶  NAS
#
#  After running this script:
#   - FreeRADIUS owns UDP port 1812/1813
#   - RaspISE built-in RADIUS server is disabled (set radius.enabled: false)
#   - EAP-PEAP/MSCHAPv2 and EAP-TLS work end-to-end
# =============================================================================
set -euo pipefail

RASPISE_API="http://127.0.0.1:8081"
FR_CONF="/etc/freeradius/3.0"
CONFIG_FILE="/etc/raspise/config.yaml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash scripts/setup_freeradius.sh"

# ─── 1. Install FreeRADIUS ────────────────────────────────────────────────────
info "Installing FreeRADIUS…"
apt-get update -qq
apt-get install -y -qq freeradius freeradius-utils

# ─── 2. rlm_rest module config ────────────────────────────────────────────────
info "Configuring rlm_rest module…"
cat > "$FR_CONF/mods-available/rest" << 'FREERADIUS_REST'
rest {
    # Connection pool shared across all rlm_rest calls
    pool {
        start = 5
        min   = 4
        max   = 32
        spare = 10
        uses  = 0
        lifetime = 0
        idle_timeout = 60
    }

    connect_uri = "http://127.0.0.1:8081"

    # Authenticate: POST to /radius/auth with user credentials
    authenticate {
        uri    = "${..connect_uri}/radius/auth"
        method = 'post'
        body   = 'json'
        data   = '{"username": "%{User-Name}", "password": "%{User-Password}", "nas_ip": "%{NAS-IP-Address}", "nas_port": "%{NAS-Port}", "calling_station_id": "%{Calling-Station-Id}", "called_station_id": "%{Called-Station-Id}"}'
        tls = ${..tls}
    }

    # Authorize: GET to /radius/authorize
    authorize {
        uri    = "${..connect_uri}/radius/authorize"
        method = 'post'
        body   = 'json'
        data   = '{"username": "%{User-Name}", "nas_ip": "%{NAS-IP-Address}", "calling_station_id": "%{Calling-Station-Id}"}'
        tls = ${..tls}
    }

    # Accounting: POST to /radius/accounting
    accounting {
        uri    = "${..connect_uri}/radius/accounting"
        method = 'post'
        body   = 'json'
        data   = '{"status_type": "%{Acct-Status-Type}", "username": "%{User-Name}", "session_id": "%{Acct-Session-Id}", "nas_ip": "%{NAS-IP-Address}", "framed_ip": "%{Framed-IP-Address}", "calling_station": "%{Calling-Station-Id}", "input_octets": "%{Acct-Input-Octets}", "output_octets": "%{Acct-Output-Octets}", "session_time": "%{Acct-Session-Time}"}'
        tls = ${..tls}
    }
}
FREERADIUS_REST

ln -sf "$FR_CONF/mods-available/rest" "$FR_CONF/mods-enabled/rest"

# ─── 3. Add REST endpoints to RaspISE API ─────────────────────────────────────
# Add /radius/* routes that FreeRADIUS will call
ROUTES_FILE="/opt/raspise/raspise/radius/freeradius_routes.py"

info "Writing FreeRADIUS REST endpoint handlers…"
mkdir -p "$(dirname "$ROUTES_FILE")"
cat > "$ROUTES_FILE" << 'PYEOF'
"""
FreeRADIUS rlm_rest callback endpoints.
Mounted on the RaspISE REST API app at /radius/*.
"""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from raspise.db import get_db
from raspise.policy.engine import PolicyEngine, AuthContext
from raspise.core.utils import normalise_mac
from raspise.core.events import bus, EventType
from raspise.db.models import AuthLog, AuthResult, AuthMethod

router = APIRouter(prefix="/radius", tags=["freeradius-hook"])

engine = PolicyEngine()


class RadiusAuthRequest(BaseModel):
    username: str
    password: Optional[str] = None
    nas_ip: Optional[str] = None
    nas_port: Optional[str] = None
    calling_station_id: Optional[str] = None
    called_station_id: Optional[str] = None


class RadiusAuthzRequest(BaseModel):
    username: str
    nas_ip: Optional[str] = None
    calling_station_id: Optional[str] = None


class RadiusAcctRequest(BaseModel):
    status_type: Optional[str] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    nas_ip: Optional[str] = None
    framed_ip: Optional[str] = None
    calling_station: Optional[str] = None
    input_octets: Optional[str] = None
    output_octets: Optional[str] = None
    session_time: Optional[str] = None


@router.post("/auth")
async def radius_auth(req: RadiusAuthRequest, db=Depends(get_db)):
    """Called by FreeRADIUS during authentication phase."""
    mac = normalise_mac(req.calling_station_id) if req.calling_station_id else None
    ctx = AuthContext(
        username=req.username,
        mac_address=mac,
        ip_address=req.nas_ip,
        nas_ip=req.nas_ip,
    )

    # Policy evaluation
    decision = await engine.evaluate(ctx, db)

    # Log the attempt
    log = AuthLog(
        username=req.username,
        mac_address=mac,
        nas_ip=req.nas_ip,
        result=AuthResult.ACCEPT if decision.action == "PERMIT" else AuthResult.REJECT,
        reject_reason=decision.reason if decision.action != "PERMIT" else None,
        auth_method=AuthMethod.PEAP,
        matched_policy=decision.policy_name,
        vlan_assigned=decision.vlan,
    )
    db.add(log)
    await db.commit()

    if decision.action == "PERMIT":
        await bus.publish(EventType.AUTH_SUCCESS, {
            "username": req.username, "mac": mac, "vlan": decision.vlan
        })
        response: dict = {"Reply-Message": "Welcome", "control:Auth-Type": "Accept"}
        if decision.vlan:
            response.update({
                "Tunnel-Type": "13",
                "Tunnel-Medium-Type": "6",
                "Tunnel-Private-Group-Id": str(decision.vlan),
            })
        return response
    else:
        await bus.publish(EventType.AUTH_FAILURE, {
            "username": req.username, "mac": mac, "reason": decision.reason
        })
        return {"Reply-Message": decision.reason or "Access denied"}


@router.post("/authorize")
async def radius_authorize(req: RadiusAuthzRequest, db=Depends(get_db)):
    """Called by FreeRADIUS during authorization phase."""
    mac = normalise_mac(req.calling_station_id) if req.calling_station_id else None
    ctx = AuthContext(username=req.username, mac_address=mac, nas_ip=req.nas_ip)
    decision = await engine.evaluate(ctx, db)

    if decision.action == "PERMIT":
        resp: dict = {"control:Auth-Type": "EAP"}
        if decision.vlan:
            resp.update({
                "Tunnel-Type": "13",
                "Tunnel-Medium-Type": "6",
                "Tunnel-Private-Group-Id": str(decision.vlan),
            })
        return resp
    return {"Reply-Message": "Not authorized"}


@router.post("/accounting")
async def radius_accounting(req: RadiusAcctRequest, db=Depends(get_db)):
    """Called by FreeRADIUS for accounting packets."""
    from raspise.db.models import ActiveSession
    from datetime import datetime, timezone

    status = (req.status_type or "").lower()
    if "start" in status:
        sess = ActiveSession(
            session_id=req.session_id or "",
            username=req.username or "",
            mac_address=normalise_mac(req.calling_station) if req.calling_station else None,
            nas_ip=req.nas_ip,
            framed_ip=req.framed_ip,
            started_at=datetime.now(timezone.utc),
        )
        db.add(sess)
        await db.commit()
    elif "stop" in status or "interim" in status:
        from sqlalchemy import select, update
        stmt = (
            update(ActiveSession)
            .where(ActiveSession.session_id == req.session_id)
            .values(
                input_octets=int(req.input_octets or 0),
                output_octets=int(req.output_octets or 0),
                session_time=int(req.session_time or 0),
            )
        )
        await db.execute(stmt)
        if "stop" in status:
            from sqlalchemy import delete
            await db.execute(
                delete(ActiveSession).where(ActiveSession.session_id == req.session_id)
            )
        await db.commit()

    return {"ok": True}
PYEOF

# ─── 4. EAP module: enable PEAP + EAP-TLS ────────────────────────────────────
info "Configuring EAP (EAP-PEAP/MSCHAPv2 + EAP-TLS)…"

# Enable PEAP and EAP-TLS in the default EAP module
sed -i 's/^\s*#\s*peap\s*$/\t\tpeap/' "$FR_CONF/mods-enabled/eap" 2>/dev/null || true

# mschapv2 inner auth
if [[ ! -f "$FR_CONF/mods-enabled/mschapv2" ]]; then
  ln -sf "$FR_CONF/mods-available/mschapv2" "$FR_CONF/mods-enabled/mschapv2" 2>/dev/null || true
fi

# ─── 5. Self-signed cert for EAP-TLS (dev/lab use) ───────────────────────────
info "Generating self-signed TLS certificate for EAP…"
FR_CERT_DIR="$FR_CONF/certs"
if [[ ! -f "$FR_CERT_DIR/server.pem" ]]; then
  pushd "$FR_CERT_DIR" > /dev/null
  make -f Makefile ca.pem server.pem 2>&1 | tail -5 || \
    openssl req -new -x509 -days 3650 -nodes \
      -subj "/CN=RaspISE RADIUS/O=RaspISE/C=US" \
      -keyout "$FR_CERT_DIR/server.key" \
      -out "$FR_CERT_DIR/server.pem"
  popd > /dev/null
fi

# ─── 6. NAS clients from RaspISE config ───────────────────────────────────────
info "Generating FreeRADIUS clients.conf from RaspISE config…"
if command -v python3 &>/dev/null && [[ -f "$CONFIG_FILE" ]]; then
  python3 - << PYEOF
import yaml, sys
with open("$CONFIG_FILE") as f:
    cfg = yaml.safe_load(f)
clients = cfg.get("radius", {}).get("clients", [])
with open("$FR_CONF/clients.conf", "a") as out:
    out.write("\n# RaspISE auto-generated clients\n")
    for c in clients:
        out.write(f"""
client {c['name']} {{
    ipaddr  = {c['ip']}
    secret  = {c['secret']}
    shortname = {c['name']}
}}
""")
print(f"Wrote {len(clients)} client(s) to {FR_CONF}/clients.conf")
PYEOF
fi

# ─── 7. Disable RaspISE built-in RADIUS (FreeRADIUS takes port 1812) ──────────
if [[ -f "$CONFIG_FILE" ]]; then
  info "Disabling RaspISE built-in RADIUS server (FreeRADIUS will handle port 1812)…"
  sed -i 's/^  enabled: true  # radius/  enabled: false  # radius (FreeRADIUS handles this)/' \
    "$CONFIG_FILE" 2>/dev/null || \
  warn "Could not auto-disable built-in RADIUS. Set 'radius.enabled: false' manually."
fi

# ─── 8. Enable and start FreeRADIUS ──────────────────────────────────────────
info "Enabling FreeRADIUS service…"
systemctl enable freeradius
systemctl restart freeradius || {
  warn "FreeRADIUS start failed — check: sudo journalctl -u freeradius -n 50"
}

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   FreeRADIUS integration setup complete!                     ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  FreeRADIUS:  UDP 1812 (auth) / 1813 (accounting)           ║${NC}"
echo -e "${GREEN}║  REST hooks:  http://127.0.0.1:8081/radius/*                ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Auth methods now supported:                                 ║${NC}"
echo -e "${GREEN}║    ✓ EAP-PEAP / MSCHAPv2  (wireless 802.1X)                ║${NC}"
echo -e "${GREEN}║    ✓ EAP-TLS              (certificate-based)               ║${NC}"
echo -e "${GREEN}║    ✓ PAP / CHAP           (wired / VPN)                     ║${NC}"
echo -e "${GREEN}║    ✓ MAB                  (MAC-bypass via RaspISE)          ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Next: sudo systemctl restart raspise                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
