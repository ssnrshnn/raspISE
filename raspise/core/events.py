"""
RaspISE Event Bus
=================
A lightweight, in-process publish/subscribe bus backed by asyncio queues.
Any component can publish an AuthEvent; the display manager, REST API, and
logger all subscribe to receive real-time updates.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any


class EventType(str, Enum):
    # Authentication
    AUTH_SUCCESS   = "AUTH_SUCCESS"
    AUTH_FAILURE   = "AUTH_FAILURE"
    AUTH_CHALLENGE = "AUTH_CHALLENGE"
    # Sessions
    SESSION_START  = "SESSION_START"
    SESSION_STOP   = "SESSION_STOP"
    # Devices
    NEW_DEVICE     = "NEW_DEVICE"
    DEVICE_UPDATED = "DEVICE_UPDATED"
    # TACACS+
    TACACS_AUTH    = "TACACS_AUTH"
    TACACS_AUTHZ   = "TACACS_AUTHZ"
    TACACS_ACCT    = "TACACS_ACCT"
    # System
    SYSTEM_START   = "SYSTEM_START"
    SYSTEM_STOP    = "SYSTEM_STOP"


@dataclass
class Event:
    type: EventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.timestamp:%H:%M:%S}] {self.type.value} {self.data}"


class EventBus:
    """Thread-safe asyncio event bus with multiple subscriber queues."""

    def __init__(self, max_queue_size: int = 500) -> None:
        self._max_queue_size = max_queue_size
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._lock = asyncio.Lock()
        self._main_loop: asyncio.AbstractEventLoop | None = None
        self._pending_events: list[Event] = []  # buffer for events before loop is ready
        import threading
        self._pending_lock = threading.Lock()

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the main event loop so sync callers can schedule coroutines."""
        self._main_loop = loop
        # Flush any events that were published before the loop was ready
        with self._pending_lock:
            pending = list(self._pending_events)
            self._pending_events.clear()
        for evt in pending:
            asyncio.run_coroutine_threadsafe(self.publish(evt), loop)

    async def subscribe(self) -> asyncio.Queue[Event]:
        """Register a new subscriber and return its private queue."""
        async with self._lock:
            q: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._max_queue_size)
            self._subscribers.append(q)
            return q

    async def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        async with self._lock:
            try:
                self._subscribers.remove(queue)
            except ValueError:
                pass

    async def publish(self, event: Event) -> None:
        """Broadcast an event to all subscribers (non-blocking)."""
        async with self._lock:
            for q in self._subscribers:
                # Drop oldest event if queue is full rather than blocking
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                await q.put(event)

    def publish_sync(self, event: Event) -> None:
        """Fire-and-forget from sync code (e.g. RADIUS server thread)."""
        if self._main_loop and self._main_loop.is_running():
            asyncio.run_coroutine_threadsafe(self.publish(event), self._main_loop)
        else:
            # Buffer events published before the loop is ready
            with self._pending_lock:
                if len(self._pending_events) < self._max_queue_size:
                    self._pending_events.append(event)


# Module-level singleton — import this everywhere
bus = EventBus()


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def auth_success(username: str, mac: str, nas_ip: str, method: str,
                 vlan: int | None = None) -> Event:
    return Event(EventType.AUTH_SUCCESS, data={
        "username": username, "mac": mac, "nas_ip": nas_ip,
        "method": method, "vlan": vlan,
    })


def auth_failure(username: str, mac: str, nas_ip: str, method: str,
                 reason: str) -> Event:
    return Event(EventType.AUTH_FAILURE, data={
        "username": username, "mac": mac, "nas_ip": nas_ip,
        "method": method, "reason": reason,
    })
