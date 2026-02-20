"""IP geolocation enrichment with TTL cache and API fallback."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import aiohttp

from homeassistant.core import HomeAssistant

from .const import PRIVATE_IP_PREFIXES

_LOGGER = logging.getLogger(__name__)

CACHE_TTL = 3600  # seconds
_cache: dict[str, tuple[dict[str, Any], float]] = {}
_lock = asyncio.Lock()


def _is_private(ip: str) -> bool:
    """Return True if the IP is a private/loopback address."""
    return not ip or ip.startswith(PRIVATE_IP_PREFIXES)


def _get_cached(ip: str) -> dict[str, Any] | None:
    entry = _cache.get(ip)
    if entry and time.monotonic() - entry[1] < CACHE_TTL:
        return entry[0]
    return None


def _set_cache(ip: str, data: dict[str, Any]) -> None:
    _cache[ip] = (data, time.monotonic())
    if len(_cache) > 1000:
        oldest = sorted(_cache, key=lambda k: _cache[k][1])
        for key in oldest[:100]:
            del _cache[key]


async def async_get_geo_info(
    hass: HomeAssistant, ip: str, api_key: str = ""
) -> dict[str, Any]:
    """Return geolocation data for an IP with cache and fallback."""
    if _is_private(ip):
        return {"country": "Local", "country_code": "LO", "city": "Local Network", "org": "Local"}

    async with _lock:
        cached = _get_cached(ip)
        if cached:
            return cached

    result = await _fetch_ip_api(ip)
    if not result:
        result = await _fetch_ipinfo(ip, api_key)
    if not result:
        result = {"country": "Unknown", "country_code": "??", "city": "Unknown", "org": "Unknown"}

    _set_cache(ip, result)
    return result


async def _fetch_ip_api(ip: str) -> dict[str, Any] | None:
    """Fetch geo data from ip-api.com (free, no key required)."""
    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,country,countryCode,region,city,org,isp,lat,lon,timezone"
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country", ""),
                            "country_code": data.get("countryCode", ""),
                            "region": data.get("region", ""),
                            "city": data.get("city", ""),
                            "org": data.get("org", ""),
                            "isp": data.get("isp", ""),
                            "lat": data.get("lat"),
                            "lon": data.get("lon"),
                            "timezone": data.get("timezone", ""),
                        }
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("ip-api.com lookup failed for %s: %s", ip, err)
    return None


async def _fetch_ipinfo(ip: str, api_key: str) -> dict[str, Any] | None:
    """Fetch geo data from ipinfo.io (optional API key for higher limits)."""
    token = f"?token={api_key}" if api_key else ""
    url = f"https://ipinfo.io/{ip}/json{token}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    loc = data.get("loc", ",").split(",")
                    return {
                        "country": data.get("country", ""),
                        "country_code": data.get("country", ""),
                        "region": data.get("region", ""),
                        "city": data.get("city", ""),
                        "org": data.get("org", ""),
                        "isp": data.get("org", ""),
                        "lat": float(loc[0]) if len(loc) == 2 else None,
                        "lon": float(loc[1]) if len(loc) == 2 else None,
                        "timezone": data.get("timezone", ""),
                    }
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("ipinfo.io lookup failed for %s: %s", ip, err)
    return None
