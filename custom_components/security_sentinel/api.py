"""Websocket API for Security Sentinel."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN, MAP_EVENTS_HOURS, MAP_EVENTS_LIMIT
from .coordinator import SecuritySentinelCoordinator
from .store import EventStore


@callback
def async_register_api(hass: HomeAssistant) -> None:
    """Register the websocket API."""
    websocket_api.async_register_command(hass, ws_get_map_data)
    websocket_api.async_register_command(hass, ws_get_banned_dossier)


@websocket_api.websocket_command(
    {
        vol.Required("type"): "security_sentinel/get_map_data",
    }
)
@callback
def ws_get_map_data(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Handle get map data command."""
    if DOMAIN not in hass.data or not hass.data[DOMAIN]:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Integration not configured")
        return

    # Just pick the first entry
    entry_id = list(hass.data[DOMAIN].keys())[0]
    entry_data = hass.data[DOMAIN][entry_id]
    store: EventStore = entry_data["store"]
    coordinator: SecuritySentinelCoordinator = entry_data["coordinator"]
    
    map_events = store.get_recent_events(hours=MAP_EVENTS_HOURS, limit=MAP_EVENTS_LIMIT)
    banned_ips = coordinator.data.get("banned_ips", []) if coordinator.data else []
    
    traces = []
    for ban in banned_ips:
        ip = ban.get("ip")
        if ip:
            hops = store.get_traceroute(ip)
            if hops:
                traces.append({"ip": ip, "traceroute_hops": hops})
                
    connection.send_result(
        msg["id"],
        {
            "map_events": map_events,
            "traces": traces,
        },
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "security_sentinel/get_banned_dossier",
        vol.Required("ip"): str,
    }
)
@callback
def ws_get_banned_dossier(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Handle get banned dossier command."""
    if DOMAIN not in hass.data or not hass.data[DOMAIN]:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Integration not configured")
        return

    ip = msg["ip"]
    entry_id = list(hass.data[DOMAIN].keys())[0]
    store: EventStore = hass.data[DOMAIN][entry_id]["store"]
    ip_events = store.get_events_by_ip(ip)
    
    connection.send_result(
        msg["id"],
        {
            "ip": ip,
            "events": ip_events[:20],
            "traceroute_hops": store.get_traceroute(ip),
            "geo": store.get_latest_geo_for_ip(ip),
        },
    )
