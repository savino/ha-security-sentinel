"""Notification and email dispatcher for Security Sentinel."""
from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from homeassistant.core import HomeAssistant

from .const import (
    CONF_EMAIL_RECIPIENT,
    CONF_NOTIFY_SERVICE,
    CONF_SMTP_HOST,
    CONF_SMTP_PASSWORD,
    CONF_SMTP_PORT,
    CONF_SMTP_USERNAME,
    DEFAULT_NOTIFY_SERVICE,
    DEFAULT_SMTP_PORT,
    HA_EVENT_NAME,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)

_LOGGER = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "low": "#4CAF50",
    "medium": "#FF9800",
    "high": "#f44336",
    "critical": "#9C27B0",
}


async def async_dispatch_event(
    hass: HomeAssistant, config: dict[str, Any], event: dict[str, Any]
) -> None:
    """Dispatch all configured actions for a security event."""
    # Always: fire HA bus event
    hass.bus.async_fire(HA_EVENT_NAME, event)

    # Always: persistent notification
    await _async_persistent_notification(hass, event)

    # Optional: additional notify service
    notify_service = config.get(CONF_NOTIFY_SERVICE, DEFAULT_NOTIFY_SERVICE)
    if notify_service and notify_service != "persistent_notification":
        await _async_send_notify(hass, notify_service, event)

    # High/Critical: SMTP email
    severity = event.get("severity", "low")
    if severity in (SEVERITY_HIGH, SEVERITY_CRITICAL):
        smtp_host = config.get(CONF_SMTP_HOST, "")
        recipient = config.get(CONF_EMAIL_RECIPIENT, "")
        if smtp_host and recipient:
            await hass.async_add_executor_job(_send_email, config, event)


async def _async_persistent_notification(
    hass: HomeAssistant, event: dict[str, Any]
) -> None:
    severity = event.get("severity", "low")
    event_type = event.get("event_type", "Unknown")
    ip = event.get("ip", "N/A")
    geo = event.get("geo", {})
    detail = event.get("detail", "")
    ts = event.get("timestamp", "")

    title = f"Security Sentinel — {event_type} [{severity.upper()}]"
    message = (
        f"**Event:** {event_type}\n"
        f"**Severity:** {severity.upper()}\n"
        f"**Source IP:** `{ip}`\n"
        f"**Location:** {geo.get('city', '?')}, {geo.get('country', '?')} "
        f"({geo.get('org', '?')})\n"
        f"**Detail:** {detail}\n"
        f"**Time:** {ts}"
    )
    await hass.services.async_call(
        "persistent_notification",
        "create",
        {
            "title": title,
            "message": message,
            "notification_id": f"ss_{event_type}_{ip}",
        },
        blocking=False,
    )


async def _async_send_notify(
    hass: HomeAssistant, service: str, event: dict[str, Any]
) -> None:
    domain, service_name = (
        service.split(".", 1) if "." in service else ("notify", service)
    )
    geo = event.get("geo", {})
    message = (
        f"[{event.get('severity', '').upper()}] {event.get('event_type', '')} "
        f"from {event.get('ip', 'N/A')} "
        f"({geo.get('city', '?')}, {geo.get('country', '?')})"
    )
    await hass.services.async_call(
        domain,
        service_name,
        {"message": message, "title": "Security Sentinel Alert"},
        blocking=False,
    )


def _send_email(config: dict[str, Any], event: dict[str, Any]) -> None:
    """Send an HTML email alert (blocking — runs in executor)."""
    smtp_host = config.get(CONF_SMTP_HOST, "")
    smtp_port = config.get(CONF_SMTP_PORT, DEFAULT_SMTP_PORT)
    smtp_user = config.get(CONF_SMTP_USERNAME, "")
    smtp_pass = config.get(CONF_SMTP_PASSWORD, "")
    recipient = config.get(CONF_EMAIL_RECIPIENT, "")

    if not (smtp_host and recipient):
        return

    severity = event.get("severity", "low")
    color = SEVERITY_COLORS.get(severity, "#607D8B")
    geo = event.get("geo", {})

    html = f"""
    <html><body style="font-family:sans-serif;max-width:600px;margin:auto;">
    <h2 style="background:{color};color:white;padding:12px;border-radius:6px;">
      Security Sentinel Alert &mdash; {event.get('event_type', '')}
    </h2>
    <table style="width:100%;border-collapse:collapse;">
      <tr><td style="padding:8px;font-weight:bold;">Severity</td>
          <td style="padding:8px;"><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;">{severity.upper()}</span></td></tr>
      <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">Source IP</td>
          <td style="padding:8px;">{event.get('ip', 'N/A')}</td></tr>
      <tr><td style="padding:8px;font-weight:bold;">Country</td>
          <td style="padding:8px;">{geo.get('country', 'Unknown')}</td></tr>
      <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">City</td>
          <td style="padding:8px;">{geo.get('city', 'Unknown')}</td></tr>
      <tr><td style="padding:8px;font-weight:bold;">ISP / Org</td>
          <td style="padding:8px;">{geo.get('org', 'Unknown')}</td></tr>
      <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">Detail</td>
          <td style="padding:8px;">{event.get('detail', '')}</td></tr>
      <tr><td style="padding:8px;font-weight:bold;">Timestamp</td>
          <td style="padding:8px;">{event.get('timestamp', '')}</td></tr>
    </table>
    <p style="color:#888;font-size:12px;margin-top:16px;">
      Sent by Security Sentinel &mdash; Home Assistant Integration
    </p></body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = (
        f"[Security Sentinel] {severity.upper()}: "
        f"{event.get('event_type', '')} from {event.get('ip', 'N/A')}"
    )
    msg["From"] = smtp_user or "security-sentinel@homeassistant.local"
    msg["To"] = recipient
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(msg["From"], [recipient], msg.as_string())
            _LOGGER.info("Email alert sent to %s for event %s.", recipient, event.get("event_type"))
    except Exception as err:  # noqa: BLE001
        _LOGGER.error("Failed to send email alert: %s", err)
