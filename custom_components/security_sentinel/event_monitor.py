"""HA event bus monitor with brute-force detection state machine."""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import Event, HomeAssistant, callback

from .const import (
    CONF_BRUTE_FORCE_WINDOW,
    CONF_FAILED_LOGIN_THRESHOLD,
    DEFAULT_BRUTE_FORCE_WINDOW,
    DEFAULT_FAILED_LOGIN_THRESHOLD,
    EVENT_AUTH_FAILED,
    EVENT_BRUTE_FORCE,
    EVENT_NEW_DEVICE,
    EVENT_SUSPICIOUS_SERVICE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SUSPICIOUS_SERVICES,
)

_LOGGER = logging.getLogger(__name__)


def _is_external(ip: str) -> bool:
    """Return True if the IP is a routable (non-private) address."""
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class EventMonitor:
    """Subscribe to the HA event bus and detect security threats."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        coordinator: Any,
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._coordinator = coordinator
        self._unsub_handlers: list[Callable] = []
        # Brute-force state: {ip: [unix_timestamps]}
        self._bf_timestamps: dict[str, list[float]] = defaultdict(list)
        self._known_device_ids: set[str] = set()

    async def async_start(self) -> None:
        """Subscribe to HA event bus topics."""
        self._unsub_handlers.append(
            self._hass.bus.async_listen(
                "homeassistant_login_invalid", self._handle_login_event
            )
        )
        self._unsub_handlers.append(
            self._hass.bus.async_listen("call_service", self._handle_service_call)
        )
        self._unsub_handlers.append(
            self._hass.bus.async_listen(
                "device_registry_updated", self._handle_device_registry
            )
        )
        _LOGGER.debug("EventMonitor started.")

    async def async_stop(self) -> None:
        """Unsubscribe all event handlers."""
        for unsub in self._unsub_handlers:
            unsub()
        self._unsub_handlers.clear()
        _LOGGER.debug("EventMonitor stopped.")

    @callback
    def _handle_login_event(self, event: Event) -> None:
        """Handle a failed login event from HA auth."""
        ip = event.data.get("remote_addr") or event.data.get("ip", "")
        if ip:
            self._process_auth_failed(ip)

    @callback
    def _handle_service_call(self, event: Event) -> None:
        """Detect sensitive service calls."""
        domain = event.data.get("domain", "")
        service = event.data.get("service", "")
        full = f"{domain}.{service}"
        if full in SUSPICIOUS_SERVICES or domain in ("shell_command", "python_script"):
            user_id = getattr(event.context, "user_id", None)
            sec_event = {
                "event_type": EVENT_SUSPICIOUS_SERVICE,
                "ip": "internal",
                "detail": f"Sensitive service called: {full} by user_id={user_id}",
                "severity": SEVERITY_HIGH,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "geo": {"country": "Local", "city": "Internal"},
            }
            self._hass.async_create_task(
                self._coordinator.async_process_event(sec_event)
            )

    @callback
    def _handle_device_registry(self, event: Event) -> None:
        """Detect newly registered (unknown) devices."""
        if event.data.get("action") == "create":
            device_id = event.data.get("device_id", "")
            if device_id and device_id not in self._known_device_ids:
                self._known_device_ids.add(device_id)
                sec_event = {
                    "event_type": EVENT_NEW_DEVICE,
                    "ip": "N/A",
                    "detail": f"New device registered: {device_id}",
                    "severity": SEVERITY_LOW,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "geo": {"country": "Local", "city": "Internal"},
                }
                self._hass.async_create_task(
                    self._coordinator.async_process_event(sec_event)
                )

    def _process_auth_failed(self, ip: str) -> None:
        """Record AUTH_FAILED and fire BRUTE_FORCE if threshold is reached."""
        now = datetime.now(timezone.utc).timestamp()
        config = self._entry.data
        threshold = config.get(CONF_FAILED_LOGIN_THRESHOLD, DEFAULT_FAILED_LOGIN_THRESHOLD)
        window = config.get(CONF_BRUTE_FORCE_WINDOW, DEFAULT_BRUTE_FORCE_WINDOW)

        attempt_count = len(self._bf_timestamps[ip]) + 1
        auth_event: dict[str, Any] = {
            "event_type": EVENT_AUTH_FAILED,
            "ip": ip,
            "detail": f"Failed login attempt #{attempt_count}",
            "severity": SEVERITY_HIGH if _is_external(ip) else SEVERITY_MEDIUM,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "geo": {},
        }
        if _is_external(ip):
            auth_event["detail"] += " (external IP)"

        self._hass.async_create_task(
            self._coordinator.async_process_event(auth_event)
        )

        # Sliding-window brute-force check
        self._bf_timestamps[ip] = [
            ts for ts in self._bf_timestamps[ip] if now - ts <= window
        ]
        self._bf_timestamps[ip].append(now)

        if len(self._bf_timestamps[ip]) >= threshold:
            bf_event: dict[str, Any] = {
                "event_type": EVENT_BRUTE_FORCE,
                "ip": ip,
                "detail": (
                    f"Brute-force detected: {len(self._bf_timestamps[ip])} "
                    f"attempts in {window}s"
                ),
                "severity": SEVERITY_CRITICAL,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "geo": {},
            }
            self._bf_timestamps[ip].clear()
            self._hass.async_create_task(
                self._coordinator.async_process_event(bf_event)
            )
