"""
RaspISE TFT Display Manager
============================
Drives the 2.4" ILI9341 / ST7789 SPI display (240 × 320 px) connected to
the Raspberry Pi Zero 2W's SPI0 bus.

Architecture
------------
The display manager runs in its own thread.  Each "screen" is a Python class
that knows how to render a PIL Image sized 240 × 320.  The manager cycles
through the configured screen list every N seconds, pushing frames to the
hardware via SPI.

Simulation mode
---------------
When driver = "simulation", frames are saved as PNGs in /tmp/raspise_display/
instead of talking to hardware.  This lets you develop / test on a desktop.

Hardware wiring (ILI9341 via SPI0)
------------------------------------
  Display Pin  │ Pi Physical Pin  │ GPIO
  ─────────────┼──────────────────┼──────────────────────────────
  VCC          │ Pin 1 or 17      │ 3.3 V   ── use 3.3 V, NOT 5 V
  GND          │ Pin 6, 9 or 25   │ GND
  CS           │ Pin 24           │ GPIO 8  (SPI0 CE0)
  DC           │ Pin 18           │ GPIO 24 (Data/Command)
  RST          │ Pin 22           │ GPIO 25 (Reset)
  SDA          │ Pin 19           │ GPIO 10 (SPI0 MOSI)
  SCK          │ Pin 23           │ GPIO 11 (SPI0 SCLK)
  LED/BL       │ Pin 12           │ GPIO 18 (optional PWM backlight)
"""
from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from PIL import Image, ImageDraw, ImageFont

from raspise.config import get_config
from raspise.core.logger import get_logger

if TYPE_CHECKING:
    pass

log = get_logger(__name__)

W, H = 240, 320   # Display dimensions

# Try to load a monospace font; fall back to default PIL font
def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


FONT_SM  = _load_font(11)
FONT_MD  = _load_font(14)
FONT_LG  = _load_font(18)
FONT_XL  = _load_font(24)

# Colour palette
C = {
    "bg":       (13,  17,  23),       # near-black
    "surface":  (22,  27,  34),
    "border":   (48,  54,  61),
    "text":     (230, 237, 243),
    "muted":    (110, 118, 129),
    "info":     ( 56, 189, 248),
    "success":  ( 74, 222, 128),
    "danger":   (248,  81, 100),
    "warning":  (250, 204,  21),
    "accent":   ( 13, 202, 240),
}


class BaseScreen:
    """Abstract screen — sub-classes implement render()."""

    title = "Screen"

    def render(self) -> Image.Image:
        raise NotImplementedError

    def _blank(self) -> tuple[Image.Image, ImageDraw.ImageDraw]:
        img  = Image.new("RGB", (W, H), C["bg"])
        draw = ImageDraw.Draw(img)
        return img, draw

    def _header(self, draw: ImageDraw.ImageDraw, title: str) -> None:
        """Draw a top header bar."""
        draw.rectangle([(0, 0), (W, 28)], fill=C["surface"])
        draw.line([(0, 28), (W, 28)], fill=C["border"], width=1)
        # RaspISE logo text + title
        draw.text((8, 6), "◉", font=FONT_MD, fill=C["accent"])
        draw.text((26, 7), "RaspISE", font=FONT_SM, fill=C["accent"])
        draw.text((90, 7), f"· {title}", font=FONT_SM, fill=C["muted"])
        # Clock top-right
        now = datetime.now().strftime("%H:%M")
        draw.text((W - 38, 7), now, font=FONT_SM, fill=C["muted"])

    def _footer(self, draw: ImageDraw.ImageDraw, text: str) -> None:
        draw.rectangle([(0, H - 18), (W, H)], fill=C["surface"])
        draw.line([(0, H - 18), (W, H - 18)], fill=C["border"], width=1)
        draw.text((8, H - 14), text, font=FONT_SM, fill=C["muted"])


# ---------------------------------------------------------------------------
# Display driver abstraction
# ---------------------------------------------------------------------------

class DisplayDriver:
    """Push a PIL Image to the hardware display."""

    def __init__(self) -> None:
        cfg = get_config().display
        self._driver   = cfg.driver
        self._sim_path = Path("/tmp/raspise_display")
        self._device   = None
        self._init()

    def _init(self) -> None:
        if self._driver == "simulation":
            self._sim_path.mkdir(parents=True, exist_ok=True)
            log.info("Display: simulation mode — frames → %s", self._sim_path)
            return

        try:
            cfg = get_config().display
            if self._driver == "ili9341":
                self._init_ili9341(cfg)
            elif self._driver == "st7789":
                self._init_st7789(cfg)
        except Exception as exc:
            log.error("Display hardware init failed: %s — falling back to simulation", exc)
            self._driver = "simulation"
            self._sim_path.mkdir(parents=True, exist_ok=True)

    def _init_ili9341(self, cfg) -> None:
        """
        Full ILI9341 init over raw spidev + RPi.GPIO.
        Includes all power-control registers required by most ILI9341 modules.
        """
        import spidev
        import RPi.GPIO as GPIO

        # ── GPIO setup ───────────────────────────────────────────────
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(cfg.dc_pin,  GPIO.OUT)
        GPIO.setup(cfg.rst_pin, GPIO.OUT)

        # Hardware reset – pulse low for 100 ms, then settle 150 ms
        GPIO.output(cfg.rst_pin, GPIO.HIGH); time.sleep(0.05)
        GPIO.output(cfg.rst_pin, GPIO.LOW);  time.sleep(0.10)
        GPIO.output(cfg.rst_pin, GPIO.HIGH); time.sleep(0.15)

        # ── SPI setup ────────────────────────────────────────────────
        spi = spidev.SpiDev()
        spi.open(cfg.spi_port, cfg.spi_device)
        spi.max_speed_hz = 24_000_000   # 24 MHz – stable on Pi Zero
        spi.mode = 0
        spi.bits_per_word = 8

        # ── Store handles ─────────────────────────────────────────────
        self._spi      = spi
        self._gpio     = GPIO
        self._dc_pin   = cfg.dc_pin
        self._rotation = cfg.rotation

        # ── Command helper ────────────────────────────────────────────
        def _c(cmd, *data):
            GPIO.output(cfg.dc_pin, GPIO.LOW)
            spi.writebytes([cmd])
            if data:
                GPIO.output(cfg.dc_pin, GPIO.HIGH)
                spi.writebytes2(bytes(data))

        # ── Full ILI9341 init sequence (Adafruit-equivalent) ──────────
        _c(0xEF, 0x03, 0x80, 0x02)
        _c(0xCF, 0x00, 0xC1, 0x30)
        _c(0xED, 0x64, 0x03, 0x12, 0x81)
        _c(0xE8, 0x85, 0x00, 0x78)
        _c(0xCB, 0x39, 0x2C, 0x00, 0x34, 0x02)
        _c(0xF7, 0x20)
        _c(0xEA, 0x00, 0x00)
        _c(0xC0, 0x23)                          # Power Control 1
        _c(0xC1, 0x10)                          # Power Control 2
        _c(0xC5, 0x3E, 0x28)                    # VCOM Control 1
        _c(0xC7, 0x86)                          # VCOM Control 2
        # MADCTL controls the panel scan direction.
        # For 90°/270° (landscape), the controller's column addr range is 0..319
        # and row addr range is 0..239 — PIL image must be 320×240.
        madctl = {0: 0x48, 90: 0x28, 180: 0x88, 270: 0xE8}.get(cfg.rotation, 0x48)
        _c(0x36, madctl)                        # Memory Access Control
        _c(0x3A, 0x55)                          # Pixel Format: 16-bit RGB565
        _c(0xB1, 0x00, 0x18)                    # Frame Rate: ~73 Hz
        _c(0xB6, 0x08, 0x82, 0x27)             # Display Function Control
        _c(0xF2, 0x00)                          # 3Gamma disable
        _c(0x26, 0x01)                          # Gamma curve 1
        # Positive gamma correction
        _c(0xE0, 0x0F,0x31,0x2B,0x0C,0x0E,0x08,0x4E,0xF1,0x37,0x07,0x10,0x03,0x0E,0x09,0x00)
        # Negative gamma correction
        _c(0xE1, 0x00,0x0E,0x14,0x03,0x11,0x07,0x31,0xC1,0x48,0x08,0x0F,0x0C,0x31,0x36,0x0F)
        _c(0x11)                                # Sleep Out
        time.sleep(0.12)
        _c(0x29)                                # Display On
        time.sleep(0.02)

        # ── Flood screen black so we know SPI is alive ────────────────
        self._ili_fill(0x0000)

        log.info("ILI9341 display initialised via spidev (rotation=%d)", cfg.rotation)

    def _ili_fill(self, color: int) -> None:
        """Fill the entire ILI9341 frame buffer with a 16-bit RGB565 colour."""
        GPIO  = self._gpio
        dc    = self._dc_pin
        spi   = self._spi
        rot   = getattr(self, "_rotation", 0)
        # For landscape MADCTL (90°/270°) controller sees 320 cols × 240 rows
        cw = H if rot in (90, 270) else W
        rh = W if rot in (90, 270) else H
        hi, lo = (color >> 8) & 0xFF, color & 0xFF

        def _c(cmd, *data):
            GPIO.output(dc, GPIO.LOW);  spi.writebytes([cmd])
            if data: GPIO.output(dc, GPIO.HIGH); spi.writebytes2(bytes(data))

        _c(0x2A, 0x00, 0x00, (cw - 1) >> 8, (cw - 1) & 0xFF)
        _c(0x2B, 0x00, 0x00, (rh - 1) >> 8, (rh - 1) & 0xFF)
        GPIO.output(dc, GPIO.LOW);  spi.writebytes([0x2C])
        GPIO.output(dc, GPIO.HIGH)
        row = bytes([hi, lo] * cw)
        for _ in range(rh):
            spi.writebytes2(row)

    def _init_st7789(self, cfg) -> None:
        import st7789

        self._device = st7789.ST7789(
            port=cfg.spi_port,
            cs=cfg.spi_device,
            dc=cfg.dc_pin,
            rst=cfg.rst_pin,
            backlight=cfg.backlight_pin,
            rotation=cfg.rotation,
            width=W,
            height=H,
        )
        self._device.begin()
        log.info("ST7789 display initialised (rotation=%d)", cfg.rotation)

    def show(self, img: Image.Image, frame_no: int = 0) -> None:
        if self._driver == "simulation":
            img.save(self._sim_path / "current.png")
            return

        try:
            if self._driver == "ili9341":
                import numpy as np
                rot = getattr(self, "_rotation", 0)
                # Rotate PIL image to match physical panel orientation.
                # Screens always render 240×320; for landscape we transpose
                # the pixel data so the controller sees cw×rh pixels.
                if rot == 90:
                    # 90° CW: transpose then flip horizontally → PIL rotate(-90)
                    img = img.rotate(-90, expand=True)
                elif rot == 180:
                    img = img.rotate(180)
                elif rot == 270:
                    # 270° CW: transpose then flip vertically → PIL rotate(90)
                    img = img.rotate(90, expand=True)
                # After PIL rotation: 90/270 → 320×240; 0/180 → 240×320
                pw, ph = img.size          # pixel width / height to send
                arr    = np.array(img.convert("RGB"), dtype=np.uint16)
                rgb565 = (
                    ((arr[..., 0] & 0xF8) << 8) |
                    ((arr[..., 1] & 0xFC) << 3) |
                    ( arr[..., 2]         >> 3)
                ).byteswap().flatten().tobytes()
                GPIO = self._gpio
                dc   = self._dc_pin
                spi  = self._spi
                GPIO.output(dc, GPIO.LOW);  spi.writebytes([0x2A])
                GPIO.output(dc, GPIO.HIGH); spi.writebytes2(bytes([0x00, 0x00, (pw-1)>>8, (pw-1)&0xFF]))
                GPIO.output(dc, GPIO.LOW);  spi.writebytes([0x2B])
                GPIO.output(dc, GPIO.HIGH); spi.writebytes2(bytes([0x00, 0x00, (ph-1)>>8, (ph-1)&0xFF]))
                GPIO.output(dc, GPIO.LOW);  spi.writebytes([0x2C])
                GPIO.output(dc, GPIO.HIGH)
                spi.writebytes2(rgb565)
                if frame_no % 10 == 0:
                    log.debug("ILI9341 frame %d pushed (%d bytes, rot=%d)", frame_no, len(rgb565), rot)
            elif self._driver == "st7789":
                self._device.display(img)
        except Exception as exc:
            log.warning("Display write error (frame %d): %s", frame_no, exc)


# ---------------------------------------------------------------------------
# Display Manager
# ---------------------------------------------------------------------------

class DisplayManager:
    """
    Runs a background thread that cycles through screen objects and pushes
    frames to the hardware every screen_cycle_seconds.
    """

    def __init__(self) -> None:
        self._driver  = DisplayDriver()
        self._screens: list[BaseScreen] = []
        self._current = 0
        self._running = False
        self._thread: threading.Thread | None = None

    def register_screens(self, screens: list[BaseScreen]) -> None:
        self._screens = screens

    def start(self) -> None:
        if not get_config().display.enabled:
            log.info("Display disabled in config")
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="display-manager")
        self._thread.start()
        log.info("Display manager started (%d screens)", len(self._screens))

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        cycle_s = get_config().display.screen_cycle_seconds
        frame   = 0
        while self._running:
            if self._screens:
                screen = self._screens[self._current % len(self._screens)]
                try:
                    img = screen.render()
                    self._driver.show(img, frame)
                except Exception as exc:
                    log.warning("Screen %s render error: %s", screen.title, exc)
                frame += 1
                time.sleep(cycle_s)
                self._current = (self._current + 1) % max(len(self._screens), 1)
            else:
                time.sleep(1)


# Module-level singleton
display_manager = DisplayManager()
