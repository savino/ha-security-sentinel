"""Sensor entities for Security Sentinel."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, SENSOR_FAILED_LOGINS, SENSOR_LAST_EVENT, SENSOR_THREAT_LEVEL
from .coordinator import SecuritySentinelCoordinator

_LOGGER = logging.getLogger(__name__)

_DEVICE_INFO_BASE = {
    "manufacturer": "Community",
    "model": "Security Sentinel",
    "sw_version": "0.1.0",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Security Sentinel sensor entities from a config entry."""
    coordinator: SecuritySentinelCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities([
        FailedLoginsSensor(coordinator, entry),
        LastEventSensor(coordinator, entry),
        ThreatLevelSensor(coordinator, entry),
    ])


class _BaseSentinelSensor(CoordinatorEntity, SensorEntity):
    """Shared base for all Security Sentinel sensors."""

    def __init__(
        self,
        coordinator: SecuritySentinelCoordinator,
        entry: ConfigEntry,
        key: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_device_info = {
            **_DEVICE_INFO_BASE,
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Security Sentinel",
        }

    @property
    def _data(self) -> dict[str, Any]:
        return self.coordinator.data or {}


class FailedLoginsSensor(_BaseSentinelSensor):
    """Number of failed login attempts in the last 24 hours."""

    _attr_name = "Security Sentinel Failed Logins"
    _attr_icon = "mdi:shield-alert"
    _attr_native_unit_of_measurement = "attempts"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: SecuritySentinelCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, SENSOR_FAILED_LOGINS)

    @property
    def native_value(self) -> int:
        return self._data.get("failed_logins", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        last = self._data.get("last_event")
        return {
            "last_ip": last.get("ip") if last else None,
            "last_time": last.get("timestamp") if last else None,
            "recent_events": self._data.get("recent_events", [])[:10],
        }


class LastEventSensor(_BaseSentinelSensor):
    """Type string of the most recent security event."""

    _attr_name = "Security Sentinel Last Event"
    _attr_icon = "mdi:shield-search"

    def __init__(self, coordinator: SecuritySentinelCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, SENSOR_LAST_EVENT)

    @property
    def native_value(self) -> str:
        last = self._data.get("last_event")
        return last.get("event_type", "None") if last else "None"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        last = self._data.get("last_event") or {}
        return {
            "ip": last.get("ip"),
            "geo": last.get("geo", {}),
            "detail": last.get("detail"),
            "severity": last.get("severity"),
            "timestamp": last.get("timestamp"),
        }


class ThreatLevelSensor(_BaseSentinelSensor):
    """Overall threat level: low / medium / high / critical."""

    _attr_name = "Security Sentinel Threat Level"
    _attr_icon = "mdi:shield-half-full"

    def __init__(self, coordinator: SecuritySentinelCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, SENSOR_THREAT_LEVEL)

    @property
    def native_value(self) -> str:
        return self._data.get("threat_level", "low")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "total_events_loaded": self._data.get("total_events", 0),
            "recent_events": self._data.get("recent_events", [])[:10],
        }
