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
        Minimal ILI9341 driver over raw spidev + RPi.GPIO.
        Works regardless of adafruit-circuitpython-ili9341 version.
        """
        import spidev
        import RPi.GPIO as GPIO

        # ── GPIO setup ───────────────────────────────────────────────
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(cfg.dc_pin,  GPIO.OUT)
        GPIO.setup(cfg.rst_pin, GPIO.OUT)

        # Hardware reset
        GPIO.output(cfg.rst_pin, GPIO.HIGH); time.sleep(0.01)
        GPIO.output(cfg.rst_pin, GPIO.LOW);  time.sleep(0.10)
        GPIO.output(cfg.rst_pin, GPIO.HIGH); time.sleep(0.12)

        # ── SPI setup ────────────────────────────────────────────────
        spi = spidev.SpiDev()
        spi.open(0, 0)                  # bus 0, CE0 = GPIO 8 = CS pin
        spi.max_speed_hz = 32_000_000
        spi.mode = 0

        # ── Store handles on self so show() can reach them ───────────
        self._spi     = spi
        self._gpio    = GPIO
        self._dc_pin  = cfg.dc_pin
        self._rst_pin = cfg.rst_pin

        # ── ILI9341 init sequence ────────────────────────────────────
        def cmd(c, data=None):
            GPIO.output(cfg.dc_pin, GPIO.LOW)
            spi.xfer2([c])
            if data:
                GPIO.output(cfg.dc_pin, GPIO.HIGH)
                for i in range(0, len(data), 4096):
                    spi.xfer2(data[i:i + 4096])

        cmd(0x01)           ; time.sleep(0.15)   # Software reset
        cmd(0x11)           ; time.sleep(0.12)   # Sleep out
        cmd(0x3A, [0x55])                         # 16-bit RGB565 pixels
        madctl = {0: 0x48, 90: 0x28, 180: 0x88, 270: 0xE8}.get(cfg.rotation, 0x48)
        cmd(0x36, [madctl])                       # Memory Access Control / rotation
        cmd(0x13)                                  # Normal display mode on
        cmd(0x29)                                  # Display on

        log.info("ILI9341 display initialised via spidev (rotation=%d)", cfg.rotation)

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
                # Convert PIL RGB → RGB565 big-endian, then push as raw bytes
                arr = np.array(img.convert("RGB"), dtype=np.uint16)
                rgb565 = (
                    ((arr[..., 0] & 0xF8) << 8) |
                    ((arr[..., 1] & 0xFC) << 3) |
                    ( arr[..., 2]         >> 3)
                ).byteswap().flatten().tobytes()
                # Full-frame window
                self._gpio.output(self._dc_pin, self._gpio.LOW)
                self._spi.xfer2([0x2A])                      # CASET
                self._gpio.output(self._dc_pin, self._gpio.HIGH)
                self._spi.xfer2([0x00, 0x00, 0x00, W - 1])
                self._gpio.output(self._dc_pin, self._gpio.LOW)
                self._spi.xfer2([0x2B])                      # PASET
                self._gpio.output(self._dc_pin, self._gpio.HIGH)
                self._spi.xfer2([0x00, 0x00, (H - 1) >> 8, (H - 1) & 0xFF])
                self._gpio.output(self._dc_pin, self._gpio.LOW)
                self._spi.xfer2([0x2C])                      # RAMWR
                self._gpio.output(self._dc_pin, self._gpio.HIGH)
                for i in range(0, len(rgb565), 4096):
                    self._spi.xfer2(list(rgb565[i:i + 4096]))
            elif self._driver == "st7789":
                self._device.display(img)
        except Exception as exc:
            log.warning("Display write error: %s", exc)


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

    def register_screens(self, screens: list[BaseScreen]) -> None:
        self._screens = screens

    def start(self) -> None:
        if not get_config().display.enabled:
            log.info("Display disabled in config")
            return
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="display-manager")
        t.start()
        log.info("Display manager started (%d screens)", len(self._screens))

    def stop(self) -> None:
        self._running = False

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
