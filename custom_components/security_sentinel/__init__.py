"""Security Sentinel — Home Assistant Integration entry point."""
from __future__ import annotations

import logging
from pathlib import Path
import shutil

import yaml

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
import homeassistant.helpers.config_validation as cv
import voluptuous as vol

from .const import DOMAIN
from .coordinator import SecuritySentinelCoordinator
from .event_monitor import EventMonitor
from .store import EventStore

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]
CARD_FILENAME = "security-sentinel-card.js"

SERVICE_UNBAN_IP = "unban_ip"
SERVICE_UNBAN_IP_SCHEMA = vol.Schema({
    vol.Required("ip_address"): cv.string,
})


def _ensure_lovelace_card_file(hass: HomeAssistant) -> bool:
    """Ensure the Lovelace card JS file is available under /config/www."""
    source = Path(__file__).parent / "frontend" / CARD_FILENAME
    if not source.exists():
        _LOGGER.warning("Bundled Lovelace card source not found at %s", source)
        return False

    destination_dir = Path(hass.config.path("www"))
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / CARD_FILENAME

    shutil.copy2(source, destination)
    return True


def _remove_ban_from_file(config_dir: str, ip_address: str) -> bool:
    """Remove an IP from ip_bans.yaml (blocking, runs in executor)."""
    ban_file = Path(config_dir) / "ip_bans.yaml"
    if not ban_file.exists():
        return False
    try:
        with ban_file.open() as fh:
            data = yaml.safe_load(fh)
        if not data or not isinstance(data, dict) or ip_address not in data:
            return False
        del data[ip_address]
        with ban_file.open("w") as fh:
            yaml.dump(data, fh, default_flow_style=False)
        return True
    except Exception as err:  # noqa: BLE001
        _LOGGER.error("Failed to remove ban for %s: %s", ip_address, err)
        return False


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Security Sentinel from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    card_ready = await hass.async_add_executor_job(_ensure_lovelace_card_file, hass)
    if card_ready:
        _LOGGER.debug("Lovelace card available at /local/%s", CARD_FILENAME)

    store = EventStore(hass)
    await store.async_load()

    coordinator = SecuritySentinelCoordinator(hass, entry, store)
    monitor = EventMonitor(hass, entry, coordinator)
    await monitor.async_start()

    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "monitor": monitor,
        "store": store,
    }

    await coordinator.async_config_entry_first_refresh()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    async def _handle_unban_ip(call: ServiceCall) -> None:
        """Remove an IP address from the HA ban list."""
        ip_address: str = call.data["ip_address"]
        removed = await hass.async_add_executor_job(
            _remove_ban_from_file, hass.config.config_dir, ip_address
        )
        if removed:
            _LOGGER.info("Removed ban for IP: %s", ip_address)
            for entry_data in hass.data[DOMAIN].values():
                coord = entry_data.get("coordinator")
                if coord:
                    await coord.async_request_refresh()
        else:
            _LOGGER.warning("Could not remove ban for IP: %s (not found)", ip_address)

    if not hass.services.has_service(DOMAIN, SERVICE_UNBAN_IP):
        hass.services.async_register(
            DOMAIN,
            SERVICE_UNBAN_IP,
            _handle_unban_ip,
            schema=SERVICE_UNBAN_IP_SCHEMA,
        )

    _LOGGER.info("Security Sentinel integration loaded successfully.")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    data = hass.data[DOMAIN].get(entry.entry_id, {})
    monitor: EventMonitor | None = data.get("monitor")
    if monitor:
        await monitor.async_stop()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options change."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
