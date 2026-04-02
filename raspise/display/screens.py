"""
All display screens for RaspISE.

Each screen fetches data synchronously from SQLite and renders a 240×320 PIL
Image.  Screens run in a background thread so they must not use async/await.
"""
from __future__ import annotations

import asyncio
import io
import socket
import subprocess
from datetime import datetime, timezone

import psutil
from PIL import Image, ImageDraw

from raspise.config import get_config
from raspise.display.manager import (
    BaseScreen, C, FONT_SM, FONT_MD, FONT_LG, FONT_XL, W, H
)

# Sync DB helper — runs a coroutine from a non-async thread
def _sync_run(coro):
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _fetch_recent_auth(limit: int = 8):
    from sqlalchemy import select
    from raspise.db.database import AsyncSessionLocal
    from raspise.db.models import AuthLog, AuthResult
    async with AsyncSessionLocal() as db:
        stmt = select(AuthLog).order_by(AuthLog.timestamp.desc()).limit(limit)
        return (await db.execute(stmt)).scalars().all()


async def _fetch_counts():
    from sqlalchemy import select, func
    from raspise.db.database import AsyncSessionLocal
    from raspise.db.models import AuthLog, AuthResult, ActiveSession, GuestSession
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    async with AsyncSessionLocal() as db:
        ok  = (await db.execute(select(func.count()).select_from(AuthLog).where(
            AuthLog.timestamp >= today, AuthLog.result == AuthResult.SUCCESS
        ))).scalar_one()
        fail = (await db.execute(select(func.count()).select_from(AuthLog).where(
            AuthLog.timestamp >= today, AuthLog.result == AuthResult.FAILURE
        ))).scalar_one()
        sess = (await db.execute(select(func.count()).select_from(ActiveSession))).scalar_one()
        guest = (await db.execute(select(func.count()).select_from(GuestSession).where(
            GuestSession.active == True,
            GuestSession.expires_at > datetime.now(timezone.utc),
        ))).scalar_one()
    return ok, fail, sess, guest


# ---------------------------------------------------------------------------
# Screen 1: Live Auth Log
# ---------------------------------------------------------------------------

class AuthLogScreen(BaseScreen):
    title = "Auth Log"

    def render(self) -> Image.Image:
        img, draw = self._blank()
        self._header(draw, "Auth Log")

        try:
            logs = _sync_run(_fetch_recent_auth(8))
        except Exception:
            logs = []

        y = 36
        for log in logs:
            result_color = C["success"] if log.result == "SUCCESS" else C["danger"]
            symbol       = "✓" if log.result == "SUCCESS" else "✗"

            # Result indicator bar
            draw.rectangle([(0, y), (3, y + 19)], fill=result_color)

            # Timestamp
            ts = log.timestamp.strftime("%H:%M:%S")
            draw.text((7, y), ts, font=FONT_SM, fill=C["muted"])

            # Username or MAC
            name = (log.username or log.mac_address or "?")[:16]
            draw.text((58, y), name, font=FONT_SM, fill=C["text"])

            # Method badge
            method = str(log.auth_method)[:8]
            draw.text((160, y), method, font=FONT_SM, fill=C["info"])

            # Result symbol
            draw.text((218, y), symbol, font=FONT_MD, fill=result_color)

            y += 20
            if y > H - 30:
                break

        self._footer(draw, f"Auth Log · {datetime.now().strftime('%d/%m %H:%M')}")
        return img


# ---------------------------------------------------------------------------
# Screen 2: System Stats
# ---------------------------------------------------------------------------

class StatsScreen(BaseScreen):
    title = "System Stats"

    def render(self) -> Image.Image:
        img, draw = self._blank()
        self._header(draw, "System Stats")

        cpu    = psutil.cpu_percent(interval=0.5)
        mem    = psutil.virtual_memory()
        disk   = psutil.disk_usage("/")
        uptime = self._uptime()
        temp   = self._temp()

        y = 38
        self._meter(draw, y, "CPU", cpu, C["info"])
        y += 44
        self._meter(draw, y, "RAM", mem.percent, C["success"])
        y += 44
        self._meter(draw, y, "Disk", disk.percent, C["warning"])
        y += 44

        # Temperature & uptime
        draw.text((12, y), f"Temp:   {temp}", font=FONT_SM, fill=C["text"])
        y += 18
        draw.text((12, y), f"Uptime: {uptime}", font=FONT_SM, fill=C["text"])

        self._footer(draw, "Pi Zero 2W · RaspISE")
        return img

    def _meter(self, draw: ImageDraw.ImageDraw, y: int, label: str, pct: float, color: tuple) -> None:
        bar_w = W - 24
        fill_w = int(bar_w * pct / 100)

        draw.text((12, y), label, font=FONT_MD, fill=C["text"])
        draw.text((W - 50, y), f"{pct:.0f}%", font=FONT_MD, fill=color)

        bar_y = y + 20
        draw.rectangle([(12, bar_y), (12 + bar_w, bar_y + 12)], fill=C["surface"])
        if fill_w > 0:
            draw.rectangle([(12, bar_y), (12 + fill_w, bar_y + 12)], fill=color)
        draw.rectangle([(12, bar_y), (12 + bar_w, bar_y + 12)], outline=C["border"], width=1)

    def _uptime(self) -> str:
        secs = int(psutil.boot_time())
        delta = int(datetime.now().timestamp()) - secs
        h = delta // 3600
        m = (delta % 3600) // 60
        return f"{h}h {m}m"

    def _temp(self) -> str:
        try:
            temps = psutil.sensors_temperatures()
            for key in ("cpu_thermal", "coretemp", "acpitz"):
                if key in temps and temps[key]:
                    return f"{temps[key][0].current:.0f}°C"
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["vcgencmd", "measure_temp"], text=True, timeout=2
            )
            return out.strip().replace("temp=", "")
        except Exception:
            return "N/A"


# ---------------------------------------------------------------------------
# Screen 3: Active Sessions Counter
# ---------------------------------------------------------------------------

class SessionsScreen(BaseScreen):
    title = "Sessions"

    def render(self) -> Image.Image:
        img, draw = self._blank()
        self._header(draw, "Sessions")

        try:
            ok, fail, sessions, guests = _sync_run(_fetch_counts())
        except Exception:
            ok = fail = sessions = guests = 0

        cx, cy = W // 2, 90

        # Big session count
        draw.text((cx, cy), str(sessions), font=FONT_XL, fill=C["accent"], anchor="mm")
        draw.text((cx, cy + 30), "Active Sessions", font=FONT_SM, fill=C["muted"], anchor="mm")

        # Stats grid
        items = [
            ("Today OK",  str(ok),      C["success"]),
            ("Today Fail",str(fail),    C["danger"]),
            ("Guests",    str(guests),  C["warning"]),
        ]
        y = 160
        for label, value, color in items:
            draw.rectangle([(12, y), (W - 12, y + 38)], fill=C["surface"], outline=C["border"])
            draw.text((24, y + 6), label, font=FONT_SM, fill=C["muted"])
            draw.text((W - 20, y + 6), value, font=FONT_LG, fill=color, anchor="ra")
            y += 46

        self._footer(draw, f"Updated {datetime.now().strftime('%H:%M:%S')}")
        return img


# ---------------------------------------------------------------------------
# Screen 4: Network Interfaces
# ---------------------------------------------------------------------------

class NetworkScreen(BaseScreen):
    title = "Network"

    def render(self) -> Image.Image:
        img, draw = self._blank()
        self._header(draw, "Network")

        y = 36
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface, addr_list in addrs.items():
            if iface == "lo":
                continue
            st    = stats.get(iface)
            up    = st.isup if st else False
            color = C["success"] if up else C["danger"]
            dot   = "●" if up else "○"

            # Interface name
            draw.text((8, y), dot, font=FONT_SM, fill=color)
            draw.text((22, y), iface, font=FONT_MD, fill=C["text"])

            y += 18
            for addr in addr_list:
                import socket
                if addr.family == socket.AF_INET:
                    draw.text((22, y), addr.address, font=FONT_SM, fill=C["info"])
                    y += 15
                elif addr.family.name == "AF_INET6":
                    short = addr.address.split("%")[0][:28]
                    draw.text((22, y), short, font=FONT_SM, fill=C["muted"])
                    y += 15

            y += 6
            if y > H - 30:
                break

        # Hostname
        hostname = socket.gethostname()
        self._footer(draw, f"host: {hostname}")
        return img


# ---------------------------------------------------------------------------
# Screen 5: Guest Wi-Fi QR Code
# ---------------------------------------------------------------------------

class QrCodeScreen(BaseScreen):
    title = "QR Code"

    def render(self) -> Image.Image:
        img, draw = self._blank()
        self._header(draw, "Guest Wi-Fi")

        from raspise.config import get_config
        cfg = get_config().portal
        ssid = cfg.guest_ssid
        psk  = cfg.guest_psk
        payload = f"WIFI:T:WPA;S:{ssid};P:{psk};;"

        try:
            import qrcode as qrc
            qr_img = qrc.make(payload, box_size=4, border=1)
            qr_img = qr_img.convert("RGB").resize((160, 160))
            img.paste(qr_img, ((W - 160) // 2, 40))
        except ImportError:
            draw.text((W // 2, 110), "qrcode", font=FONT_SM, fill=C["muted"], anchor="mm")
            draw.text((W // 2, 126), "not installed", font=FONT_SM, fill=C["muted"], anchor="mm")

        y = 212
        draw.text((W // 2, y), "Scan to join:", font=FONT_SM, fill=C["muted"], anchor="mm")
        y += 18
        draw.text((W // 2, y), ssid, font=FONT_MD, fill=C["info"], anchor="mm")
        y += 22
        # Mask password — show first 3 chars + asterisks
        masked = psk[:3] + "*" * max(0, len(psk) - 3) if psk else "—"
        draw.text((W // 2, y), f"Key: {masked}", font=FONT_SM, fill=C["muted"], anchor="mm")

        self._footer(draw, "Guest Portal · :8082")
        return img


# ---------------------------------------------------------------------------
# Factory — build screens from config name list
# ---------------------------------------------------------------------------

_SCREEN_MAP: dict[str, type[BaseScreen]] = {
    "auth_log":  AuthLogScreen,
    "stats":     StatsScreen,
    "sessions":  SessionsScreen,
    "network":   NetworkScreen,
    "qr_code":   QrCodeScreen,
}


def build_screens() -> list[BaseScreen]:
    cfg = get_config().display
    screens = []
    for name in cfg.screens:
        cls = _SCREEN_MAP.get(name)
        if cls:
            screens.append(cls())
        else:
            import logging
            logging.getLogger(__name__).warning("Unknown display screen: %r", name)
    return screens or [StatsScreen()]
