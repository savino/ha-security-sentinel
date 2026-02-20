"""Persistent event storage for Security Sentinel."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import STORAGE_KEY, STORAGE_VERSION

_LOGGER = logging.getLogger(__name__)

MAX_STORED_EVENTS = 500


class EventStore:
    """Manages persistent JSON-backed storage of security events."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._events: list[dict[str, Any]] = []

    async def async_load(self) -> None:
        """Load events from persistent storage."""
        data = await self._store.async_load()
        if data and isinstance(data.get("events"), list):
            self._events = data["events"]
            _LOGGER.debug("Loaded %d events from storage.", len(self._events))

    async def async_save(self) -> None:
        """Persist events to storage (capped at MAX_STORED_EVENTS)."""
        await self._store.async_save({"events": self._events[-MAX_STORED_EVENTS:]})

    def add_event(self, event: dict[str, Any]) -> None:
        """Add a new security event, stamping timestamp if missing."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._events.append(event)
        if len(self._events) > MAX_STORED_EVENTS:
            self._events = self._events[-MAX_STORED_EVENTS:]

    def get_recent_events(self, hours: int = 24, limit: int = 50) -> list[dict[str, Any]]:
        """Return events from the last N hours, newest first."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        recent = [
            e for e in self._events
            if self._parse_ts(e.get("timestamp", "")) >= cutoff
        ]
        return list(reversed(recent[-limit:]))

    def get_all_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return all stored events, newest first."""
        return list(reversed(self._events[-limit:]))

    def count_failed_logins(self, hours: int = 24) -> int:
        """Count AUTH_FAILED events in the last N hours."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        return sum(
            1 for e in self._events
            if e.get("event_type") == "AUTH_FAILED"
            and self._parse_ts(e.get("timestamp", "")) >= cutoff
        )

    def get_last_event(self) -> dict[str, Any] | None:
        """Return the most recent event or None."""
        return self._events[-1] if self._events else None

    @staticmethod
    def _parse_ts(ts: str) -> float:
        """Parse ISO timestamp string to Unix float, return 0.0 on failure."""
        try:
            return datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            return 0.0
