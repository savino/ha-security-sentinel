"""DataUpdateCoordinator for Security Sentinel."""
from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .actions import async_dispatch_event
from .const import (
    CONF_GEO_API_KEY,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_AUTH_FAILED,
    EVENT_BRUTE_FORCE,
    MAP_EVENTS_HOURS,
    MAP_EVENTS_LIMIT,
    SEVERITY_SCORES,
    THREAT_THRESHOLDS,
)
from .geo_lookup import async_get_geo_info
from .store import EventStore
from .traceroute import async_traceroute_to_ip

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
        raw_banned = await self.hass.async_add_executor_job(self._read_banned_ips)
        banned_ips = await self._async_enrich_banned_ips(raw_banned)
        # 30-day event history for the map tab (higher limit, longer window)
        map_events = self._store.get_recent_events(hours=MAP_EVENTS_HOURS, limit=MAP_EVENTS_LIMIT)
        return {
            "failed_logins": failed_logins,
            "last_event": last,
            "threat_level": threat_level,
            "recent_events": recent,
            "total_events": len(self._store.get_all_events()),
            "banned_ips": banned_ips,
            "map_events": map_events,
        }

    def _read_banned_ips(self) -> list[dict[str, Any]]:
        """Read the list of banned IPs from ip_bans.yaml."""
        ban_file = Path(self.hass.config.path("ip_bans.yaml"))
        if not ban_file.exists():
            return []
        try:
            with ban_file.open() as fh:
                data = yaml.safe_load(fh)
            if not data or not isinstance(data, dict):
                return []
            return [
                {
                    "ip": ip,
                    "banned_at": (
                        info.get("banned_at", "") if isinstance(info, dict) else ""
                    ),
                }
                for ip, info in data.items()
            ]
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Could not read ip_bans.yaml: %s", err)
            return []

    async def _async_enrich_banned_ips(
        self, raw_bans: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Enrich each banned IP entry with geo data and event history dossier."""
        geo_api_key = self._entry.data.get(CONF_GEO_API_KEY, "")
        enriched: list[dict[str, Any]] = []
        for ban in raw_bans:
            ip = ban["ip"]
            # Pull the historical snapshot from stored events (preserves point-in-time geo)
            ip_events = self._store.get_events_by_ip(ip)
            geo = self._store.get_latest_geo_for_ip(ip)
            # If no geo found in stored events, fetch a live lookup as a fallback
            if not geo and ip not in ("internal", "N/A", ""):
                geo = await async_get_geo_info(self.hass, ip, geo_api_key)
            enriched.append({
                **ban,
                "geo": geo,
                "attempt_count": len(ip_events),
                "events": ip_events[:20],
                "traceroute_hops": self._store.get_traceroute(ip),
            })
        return enriched

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

        # Schedule a background traceroute for the first attack from each
        # external IP.  Runs asynchronously so it never blocks event processing.
        event_type = event.get("event_type", "")
        if (
            ip
            and ip not in ("internal", "N/A", "")
            and event_type in (EVENT_AUTH_FAILED, EVENT_BRUTE_FORCE)
            and not self._store.get_traceroute(ip)
        ):
            self.hass.async_create_task(self._async_run_traceroute(ip))

        _LOGGER.info(
            "Security event: %s from %s [%s]",
            event.get("event_type"),
            event.get("ip"),
            event.get("severity"),
        )

    async def _async_run_traceroute(self, ip: str) -> None:
        """Run traceroute for *ip* in the background and persist the hops."""
        geo_api_key = self._entry.data.get(CONF_GEO_API_KEY, "")
        _LOGGER.debug("Starting background traceroute for %s", ip)
        try:
            hops = await async_traceroute_to_ip(self.hass, ip, geo_api_key)
            if hops:
                self._store.set_traceroute(ip, hops)
                await self._store.async_save()
                await self.async_request_refresh()
                _LOGGER.debug(
                    "Traceroute for %s completed: %d hops recorded", ip, len(hops)
                )
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Background traceroute task failed for %s: %s", ip, exc)
