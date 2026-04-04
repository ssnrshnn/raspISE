"""
Event Webhook Dispatcher
========================
Subscribes to the EventBus and forwards selected events to configured
HTTP endpoints.  Useful for SIEM integration, Slack alerts, or custom
automation (n8n, Home Assistant, etc.).

Configuration (config.yaml)::

    event_webhooks:
      - url: "https://hooks.slack.com/services/T00/B00/..."
        events: ["AUTH_FAILURE", "SESSION_STOP"]
        headers:
          Content-Type: "application/json"
        timeout: 5.0
      - url: "https://siem.corp.local/api/events"
        events: []            # empty = forward ALL events
        headers:
          Authorization: "Bearer <token>"
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from raspise.config import get_config
from raspise.core.events import Event, EventType, bus
from raspise.core.logger import get_logger

log = get_logger(__name__)


async def _dispatch_webhook(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
) -> None:
    """POST a single event payload to a webhook URL with retry + backoff."""
    max_retries = 3
    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            resp = await client.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code < 500:
                if resp.status_code >= 400:
                    log.warning("Webhook %s returned HTTP %d", url, resp.status_code)
                return  # success or client error (no retry)
            log.warning("Webhook %s returned HTTP %d (attempt %d/%d)", url, resp.status_code, attempt, max_retries)
        except httpx.TimeoutException:
            log.warning("Webhook %s timed out (attempt %d/%d)", url, attempt, max_retries)
        except Exception as exc:
            log.warning("Webhook %s error (attempt %d/%d): %s", url, attempt, max_retries, exc)
        if attempt < max_retries:
            await asyncio.sleep(backoff)
            backoff *= 2


def _event_to_payload(event: Event) -> dict[str, Any]:
    """Serialise an Event to a JSON-friendly dict."""
    return {
        "event": event.type.value,
        "timestamp": event.timestamp.isoformat(),
        "data": event.data,
        "source": "raspise",
    }


async def run_webhook_dispatcher() -> None:
    """Long-running task: subscribe to bus and forward matching events."""
    cfg = get_config()
    webhooks = cfg.event_webhooks
    if not webhooks:
        return

    log.info("Event webhook dispatcher started (%d target(s))", len(webhooks))
    queue = await bus.subscribe()

    async with httpx.AsyncClient() as client:
        while True:
            event = await queue.get()
            payload = _event_to_payload(event)

            tasks = []
            for wh in webhooks:
                # If events list is empty → forward everything
                if wh.events and event.type.value not in wh.events:
                    continue
                tasks.append(
                    _dispatch_webhook(
                        client, wh.url, payload, wh.headers, wh.timeout
                    )
                )

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
