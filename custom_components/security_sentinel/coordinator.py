"""DataUpdateCoordinator for Security Sentinel."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .actions import async_dispatch_event
from .const import (
    CONF_GEO_API_KEY,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SEVERITY_SCORES,
    THREAT_THRESHOLDS,
)
from .geo_lookup import async_get_geo_info
from .store import EventStore

_LOGGER = logging.getLogger(__name__)


def _calculate_threat_level(events: list[dict[str, Any]]) -> str:
    """Compute threat level from recent event severities."""
    score = sum(SEVERITY_SCORES.get(e.get("severity", "low"), 1) for e in events)
    for threshold, level in THREAT_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


class SecuritySentinelCoordinator(DataUpdateCoordinator):
    """Orchestrates geo lookup, action dispatch, and sensor aggregation."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        store: EventStore,
    ) -> None:
        scan_interval = entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self._entry = entry
        self._store = store

    async def _async_update_data(self) -> dict[str, Any]:
        """Aggregate current security metrics for sensor entities."""
        recent = self._store.get_recent_events(hours=24)
        last = self._store.get_last_event()
        failed_logins = self._store.count_failed_logins(hours=24)
        threat_level = _calculate_threat_level(recent)
        return {
            "failed_logins": failed_logins,
            "last_event": last,
            "threat_level": threat_level,
            "recent_events": recent,
            "total_events": len(self._store.get_all_events()),
        }

    async def async_process_event(self, event: dict[str, Any]) -> None:
        """Enrich, store, dispatch, and refresh sensors for a new security event."""
        ip = event.get("ip", "")
        if ip and ip not in ("internal", "N/A", ""):
            geo_api_key = self._entry.data.get(CONF_GEO_API_KEY, "")
            event["geo"] = await async_get_geo_info(self.hass, ip, geo_api_key)

        self._store.add_event(event)
        await self._store.async_save()
        await async_dispatch_event(self.hass, self._entry.data, event)
        await self.async_request_refresh()

        _LOGGER.info(
            "Security event: %s from %s [%s]",
            event.get("event_type"),
            event.get("ip"),
            event.get("severity"),
        )
