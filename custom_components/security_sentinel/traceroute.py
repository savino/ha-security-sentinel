"""Async traceroute utility for Security Sentinel.

Runs the system ``traceroute`` (Linux/macOS) or ``tracert`` (Windows) command
in a thread-pool executor, parses the hop IPs, and geo-enriches each one using
the existing :func:`~.geo_lookup.async_get_geo_info` helper.

Returns an empty list when the traceroute binary is unavailable or the target
IP cannot be reached within the configured timeout — callers must handle this
gracefully.
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
from typing import Any

from homeassistant.core import HomeAssistant

from .geo_lookup import async_get_geo_info

_LOGGER = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

MAX_HOPS = 15
TRACEROUTE_TIMEOUT = 45  # seconds — hard limit for the subprocess


async def async_traceroute_to_ip(
    hass: HomeAssistant,
    target_ip: str,
    geo_api_key: str = "",
) -> list[dict[str, Any]]:
    """Run traceroute to *target_ip* and return a geo-enriched hop list.

    Each element in the returned list is a dict with at minimum ``ip``, plus
    all fields returned by :func:`~.geo_lookup.async_get_geo_info`
    (``country``, ``city``, ``lat``, ``lon``, …).

    Returns an empty list on any failure.
    """
    hop_ips: list[str] = await hass.async_add_executor_job(
        _run_traceroute, target_ip
    )
    if not hop_ips:
        return []

    hops: list[dict[str, Any]] = []
    for ip in hop_ips:
        geo = await async_get_geo_info(hass, ip, geo_api_key)
        hops.append({"ip": ip, **geo})
    return hops


# ---------------------------------------------------------------------------
# Blocking helpers (run inside executor)
# ---------------------------------------------------------------------------


def _run_traceroute(target_ip: str) -> list[str]:
    """Blocking traceroute call.  Returns a deduplicated list of hop IPs."""
    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", str(MAX_HOPS), "-w", "2000", target_ip]
    else:
        cmd = ["traceroute", "-n", "-m", str(MAX_HOPS), "-w", "2", target_ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TRACEROUTE_TIMEOUT,
        )
        return _parse_traceroute_output(result.stdout, target_ip)
    except FileNotFoundError:
        _LOGGER.debug("traceroute command not available on this system")
        return []
    except subprocess.TimeoutExpired:
        _LOGGER.debug("traceroute timed out for %s", target_ip)
        return []
    except Exception as exc:  # noqa: BLE001
        _LOGGER.debug("traceroute failed for %s: %s", target_ip, exc)
        return []


def _parse_traceroute_output(output: str, target_ip: str) -> list[str]:
    """Extract a unique, ordered list of hop IPs from traceroute text."""
    hops: list[str] = []
    seen: set[str] = set()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip header lines emitted by both traceroute and tracert
        if stripped.startswith(("traceroute", "Tracing", "over a maximum")):
            continue
        for ip in _IPV4_RE.findall(stripped):
            if ip not in seen:
                seen.add(ip)
                # Intermediate hops only — destination is appended once at the end
                if ip != target_ip:
                    hops.append(ip)

    # Ensure the destination IP appears exactly once as the final entry
    if target_ip not in hops:
        hops.append(target_ip)
    return hops
