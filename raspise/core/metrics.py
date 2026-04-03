"""
Prometheus-compatible /metrics exporter
=======================================
Subscribes to the EventBus and maintains in-memory counters/gauges.
Exposes metrics in Prometheus text exposition format — no external
dependency required.
"""
from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timezone

from raspise.core.events import EventBus, Event, EventType


class _Counter:
    """Thread-safe monotonic counter with optional labels."""

    def __init__(self) -> None:
        self._values: dict[tuple[tuple[str, str], ...], float] = {}
        self._lock = threading.Lock()

    def inc(self, labels: dict[str, str] | None = None, amount: float = 1) -> None:
        key = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            self._values[key] = self._values.get(key, 0) + amount

    def collect(self) -> dict[tuple[tuple[str, str], ...], float]:
        with self._lock:
            return dict(self._values)


class _Gauge:
    """Thread-safe gauge (set/inc/dec)."""

    def __init__(self) -> None:
        self._value: float = 0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1) -> None:
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1) -> None:
        with self._lock:
            self._value -= amount

    def get(self) -> float:
        with self._lock:
            return self._value


# ── Metric instances ──────────────────────────────────────────────────────────

auth_total = _Counter()           # labels: result=success|failure
radius_requests = _Counter()      # labels: type=auth|acct
tacacs_requests = _Counter()      # labels: type=auth|authz|acct
new_devices = _Counter()          # no labels
active_sessions = _Gauge()        # set from DB periodically
uptime_gauge = _Gauge()           # seconds since start

_start_time: float = time.monotonic()


# ── Event handler ─────────────────────────────────────────────────────────────

_EVENT_MAP: dict[EventType, callable] = {}


def _handle_event(event: Event) -> None:
    match event.type:
        case EventType.AUTH_SUCCESS:
            auth_total.inc({"result": "success"})
            radius_requests.inc({"type": "auth"})
        case EventType.AUTH_FAILURE:
            auth_total.inc({"result": "failure"})
            radius_requests.inc({"type": "auth"})
        case EventType.SESSION_START:
            active_sessions.inc()
        case EventType.SESSION_STOP:
            active_sessions.dec()
        case EventType.NEW_DEVICE:
            new_devices.inc()
        case EventType.TACACS_AUTH:
            tacacs_requests.inc({"type": "auth"})
        case EventType.TACACS_AUTHZ:
            tacacs_requests.inc({"type": "authz"})
        case EventType.TACACS_ACCT:
            tacacs_requests.inc({"type": "acct"})


# ── Background subscriber ────────────────────────────────────────────────────

async def run_metrics_collector(event_bus: EventBus) -> None:
    """Long-lived task: subscribe to EventBus and update counters."""
    global _start_time
    _start_time = time.monotonic()

    queue = await event_bus.subscribe()
    try:
        while True:
            event = await queue.get()
            _handle_event(event)
    except asyncio.CancelledError:
        await event_bus.unsubscribe(queue)


# ── Prometheus text format renderer ──────────────────────────────────────────

def _render_counter(name: str, help_text: str, counter: _Counter) -> str:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
    for labels, value in counter.collect().items():
        if labels:
            lbls = ",".join(f'{k}="{v}"' for k, v in labels)
            lines.append(f"{name}{{{lbls}}} {value}")
        else:
            lines.append(f"{name} {value}")
    # Ensure at least one sample line if counter was never incremented
    if not counter.collect():
        lines.append(f"{name} 0")
    return "\n".join(lines)


def _render_gauge(name: str, help_text: str, gauge: _Gauge) -> str:
    return "\n".join([
        f"# HELP {name} {help_text}",
        f"# TYPE {name} gauge",
        f"{name} {gauge.get()}",
    ])


def render_metrics() -> str:
    """Return all metrics in Prometheus text exposition format."""
    uptime_gauge.set(time.monotonic() - _start_time)

    sections = [
        _render_counter(
            "raspise_auth_total",
            "Total authentication attempts",
            auth_total,
        ),
        _render_counter(
            "raspise_radius_requests_total",
            "Total RADIUS requests by type",
            radius_requests,
        ),
        _render_counter(
            "raspise_tacacs_requests_total",
            "Total TACACS+ requests by type",
            tacacs_requests,
        ),
        _render_counter(
            "raspise_new_devices_total",
            "Total new devices discovered",
            new_devices,
        ),
        _render_gauge(
            "raspise_active_sessions",
            "Current number of active sessions",
            active_sessions,
        ),
        _render_gauge(
            "raspise_uptime_seconds",
            "Seconds since RaspISE started",
            uptime_gauge,
        ),
    ]
    return "\n\n".join(sections) + "\n"
