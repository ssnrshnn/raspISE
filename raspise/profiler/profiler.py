"""
RaspISE Device Profiler
=======================
Passively identifies devices on the network using three signals:

  1. DHCP sniffer (Scapy)  — captures hostname, vendor class, DHCP option 55
  2. ARP monitor           — detects new MAC addresses on the LAN
  3. OUI database lookup   — vendor name from IEEE OUI table

The profiler runs as a background asyncio task and updates the `devices`
table in the database, then publishes NEW_DEVICE / DEVICE_UPDATED events.

DHCP Fingerprinting
-------------------
The DHCP option 55 (Parameter Request List) fingerprint is a comma-separated
string of option numbers that uniquely identifies most operating systems.
For example:
  1,3,15,6,119,12,44,47,26,121,42  →  Windows
  1,121,3,6,15,119,252,95,44,46    →  macOS / iOS
  1,3,6,12,15,17,23,28,29,31,33... →  Linux

Device Type Inference
---------------------
Combined from: OUI vendor string + DHCP fingerprint + hostname patterns.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from raspise.config import get_config
from raspise.core.events import bus, Event, EventType
from raspise.core.logger import get_logger
from raspise.core.utils import normalise_mac
from raspise.db.database import AsyncSessionLocal
from raspise.db.models import Device

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# OUI Database
# ---------------------------------------------------------------------------

class OuiDatabase:
    """Loads the IEEE OUI CSV and looks up vendor names by MAC prefix."""

    def __init__(self, path: str) -> None:
        self._db: dict[str, str] = {}
        self._load(Path(path))

    def _load(self, path: Path) -> None:
        if not path.exists():
            log.warning("OUI database not found at %s — vendor lookup disabled", path)
            return
        try:
            with path.open(encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(",", 2)
                    if len(parts) >= 2:
                        oui = parts[0].replace(":", "").replace("-", "").lower()[:6]
                        vendor = parts[1].strip().strip('"')
                        self._db[oui] = vendor
            log.info("OUI database loaded: %d entries", len(self._db))
        except Exception as exc:
            log.error("Failed to load OUI database: %s", exc)

    def lookup(self, mac: str) -> str:
        try:
            oui = normalise_mac(mac).replace(":", "")[:6]
            return self._db.get(oui, "Unknown")
        except ValueError:
            return "Unknown"


# ---------------------------------------------------------------------------
# Device type inference
# ---------------------------------------------------------------------------

# (pattern on vendor/hostname, device_type)
_VENDOR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"apple",            re.I), "apple-device"),
    (re.compile(r"samsung",          re.I), "android-phone"),
    (re.compile(r"cisco",            re.I), "network-device"),
    (re.compile(r"juniper",          re.I), "network-device"),
    (re.compile(r"aruba|ruckus",     re.I), "access-point"),
    (re.compile(r"raspberry",        re.I), "raspberry-pi"),
    (re.compile(r"intel|dell|hp|lenovo|asus|acer", re.I), "laptop"),
    (re.compile(r"vmware|virtualbox|qemu|xen",     re.I), "virtual-machine"),
    (re.compile(r"android",          re.I), "android-phone"),
    (re.compile(r"microsoft",        re.I), "windows-device"),
    (re.compile(r"tp-link|netgear|asus router", re.I), "router"),
    (re.compile(r"printer|xerox|canon|epson",   re.I), "printer"),
    (re.compile(r"camera|axis|hikvision|dahua", re.I), "ip-camera"),
    (re.compile(r"voip|cisco ip phone|yealink",  re.I), "voip-phone"),
]

# DHCP fingerprint → OS
_DHCP_FP: dict[str, str] = {
    "1,15,3,6,44,46,47,31,33,121,249,43":          "Windows",
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252":  "Windows",
    "1,121,3,6,15,119,252,95,44,46":               "macOS/iOS",
    "1,121,3,6,15,119,252,95,44,46,47":            "macOS",
    "1,3,6,12,15,17,23,28,29,31,33,40,41,42":      "Linux",
    "1,33,3,6,15,26,28,51,58,59,119,145":           "Linux",
    "1,3,28,6":                                     "Android",
}


def infer_device_type(vendor: str, hostname: str, dhcp_fp: str) -> tuple[str, str]:
    """Returns (device_type, os_type)."""
    combined = f"{vendor} {hostname}".lower()

    device_type = "unknown"
    for pattern, dtype in _VENDOR_PATTERNS:
        if pattern.search(combined):
            device_type = dtype
            break

    os_type = _DHCP_FP.get(dhcp_fp, "unknown")
    if os_type == "unknown":
        if "windows" in combined: os_type = "Windows"
        elif "apple" in combined: os_type = "macOS"
        elif "android" in combined: os_type = "Android"
        elif "linux" in combined or "ubuntu" in combined: os_type = "Linux"

    return device_type, os_type


# ---------------------------------------------------------------------------
# DHCP / ARP Sniffer (Scapy)
# ---------------------------------------------------------------------------

class DeviceProfiler:
    """
    Background sniffer that updates the device inventory in real time.
    Runs in a separate thread (Scapy is not async-native).
    """

    def __init__(self) -> None:
        cfg = get_config()
        self._iface    = cfg.profiler.listen_interface
        self._oui      = OuiDatabase(cfg.profiler.oui_db)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running  = False

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._running = True
        import threading
        t = threading.Thread(target=self._sniff_loop, daemon=True, name="profiler-sniffer")
        t.start()
        log.info("Device profiler started on interface %s", self._iface)

    def _resolve_iface(self) -> str:
        """Return configured interface if it exists, else first non-loopback interface."""
        import psutil
        stats = psutil.net_if_stats()
        if self._iface in stats:
            return self._iface
        # Fall back to first active non-loopback interface
        for iface, st in stats.items():
            if iface != "lo" and st.isup:
                log.warning(
                    "Interface %r not found — profiler using %r instead. "
                    "Update profiler.listen_interface in config.yaml.",
                    self._iface, iface,
                )
                return iface
        return self._iface  # last resort: return original (will fail gracefully in scapy)

    def stop(self) -> None:
        self._running = False

    def _sniff_loop(self) -> None:
        try:
            from scapy.all import sniff, DHCP, ARP, Ether, IP
        except ImportError:
            log.warning("Scapy not available — device profiler disabled. Install scapy.")
            return

        iface = self._resolve_iface()
        backoff = 1.0
        max_backoff = 60.0
        while self._running:
            try:
                # Use timeout=1.0 so the loop re-checks self._running at least once per
                # second even when no packets arrive, ensuring stop() returns promptly.
                sniff(
                    iface=iface,
                    filter="udp port 67 or 68 or arp",
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda _: not self._running,
                    timeout=1.0,
                )
                backoff = 1.0  # reset on clean iteration
            except Exception as exc:
                if not self._running:
                    break
                log.error("Profiler sniffer error (restarting in %.0fs): %s", backoff, exc)
                import time
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

    def _process_packet(self, pkt) -> None:
        try:
            from scapy.all import DHCP, Ether, ARP
            if pkt.haslayer(DHCP):
                self._process_dhcp(pkt)
            elif pkt.haslayer(ARP):
                self._process_arp(pkt)
        except Exception as exc:
            log.debug("Profiler packet error: %s", exc)

    def _process_dhcp(self, pkt) -> None:
        from scapy.all import Ether, BOOTP, DHCP
        mac        = pkt[Ether].src
        options    = {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple)}

        hostname   = (options.get("hostname", b"") or b"").decode("utf-8", errors="replace")
        vendor_cls = (options.get("vendor_class_id", b"") or b"").decode("utf-8", errors="replace")
        param_list = options.get("param_req_list", b"")
        if isinstance(param_list, (bytes, bytearray)):
            dhcp_fp = ",".join(str(b) for b in param_list)
        else:
            dhcp_fp = ""

        ip_offered = str(pkt[BOOTP].yiaddr) if pkt.haslayer("BOOTP") else ""

        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._upsert_device(mac, hostname, ip_offered, vendor_cls, dhcp_fp),
                self._loop,
            )

    def _process_arp(self, pkt) -> None:
        from scapy.all import ARP
        mac = pkt[ARP].hwsrc
        ip  = pkt[ARP].psrc
        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._upsert_device(mac, "", ip, "", ""),
                self._loop,
            )

    async def _upsert_device(
        self,
        mac_raw: str,
        hostname: str,
        ip: str,
        vendor_cls: str,
        dhcp_fp: str,
    ) -> None:
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            return

        vendor                 = self._oui.lookup(mac)
        device_type, os_type   = infer_device_type(vendor + " " + vendor_cls, hostname, dhcp_fp)

        from sqlalchemy.exc import IntegrityError
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(Device).where(Device.mac_address == mac)
            dev  = (await db.execute(stmt)).scalar_one_or_none()

            is_new = dev is None
            if is_new:
                dev = Device(mac_address=mac)
                db.add(dev)

            if hostname:        dev.hostname          = hostname
            if ip:              dev.ip_address        = ip
            if vendor:          dev.vendor            = vendor
            if device_type:     dev.device_type       = device_type
            if os_type:         dev.os_type           = os_type
            if dhcp_fp:         dev.dhcp_fingerprint  = dhcp_fp

            try:
                await db.commit()
            except IntegrityError:
                # Race condition: another coroutine inserted the same MAC
                await db.rollback()
                # Retry as update only
                dev = (await db.execute(stmt)).scalar_one_or_none()
                if dev:
                    if hostname:    dev.hostname         = hostname
                    if ip:          dev.ip_address       = ip
                    if vendor:      dev.vendor           = vendor
                    if device_type: dev.device_type      = device_type
                    if os_type:     dev.os_type          = os_type
                    if dhcp_fp:     dev.dhcp_fingerprint = dhcp_fp
                    await db.commit()
                is_new = False

        etype = EventType.NEW_DEVICE if is_new else EventType.DEVICE_UPDATED
        bus.publish_sync(Event(etype, data={
            "mac": mac, "hostname": hostname, "ip": ip,
            "vendor": vendor, "device_type": device_type,
        }))
        if is_new:
            log.info("New device: mac=%s vendor=%s type=%s host=%s", mac, vendor, device_type, hostname)


# Module-level singleton
profiler = DeviceProfiler()
