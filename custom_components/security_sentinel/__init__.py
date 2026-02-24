"""Security Sentinel — Home Assistant Integration entry point."""
from __future__ import annotations

import logging
from pathlib import Path
import shutil

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import SecuritySentinelCoordinator
from .event_monitor import EventMonitor
from .store import EventStore

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]
CARD_FILENAME = "security-sentinel-card.js"


def _ensure_lovelace_card_file(hass: HomeAssistant) -> bool:
    """Ensure the Lovelace card JS file is available under /config/www."""
    source = Path(__file__).parent / "frontend" / CARD_FILENAME
    if not source.exists():
        _LOGGER.warning("Bundled Lovelace card source not found at %s", source)
        return False

    destination_dir = Path(hass.config.path("www"))
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / CARD_FILENAME

    if destination.exists() and destination.stat().st_mtime >= source.stat().st_mtime:
        return True

    shutil.copy2(source, destination)
    return True


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
