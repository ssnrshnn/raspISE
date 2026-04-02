"""
RaspISE Display entry point
============================
Run this as a separate process on the Pi so the TFT screen operates
independently of the main server.  It reads live data from the shared SQLite
database and refreshes the display at the configured cycle interval.

Usage:
    raspise-display          # from installed package
    python -m raspise.display_main
"""
from __future__ import annotations

from raspise.core import setup_logging, get_logger
from raspise.core.logger import setup_display_logging
from raspise.display import display_manager, build_screens

log = get_logger(__name__)


def main() -> None:
    setup_logging()
    setup_display_logging()
    log.info("RaspISE Display service starting…")
    screens = build_screens()
    display_manager.register_screens(screens)
    display_manager.start()

    # Keep process alive — the display loop runs in a daemon thread
    try:
        import time
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        display_manager.stop()
        log.info("Display service stopped.")


if __name__ == "__main__":
    main()
