"""Config flow for Security Sentinel."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    CONF_BRUTE_FORCE_WINDOW,
    CONF_EMAIL_RECIPIENT,
    CONF_FAILED_LOGIN_THRESHOLD,
    CONF_GEO_API_KEY,
    CONF_NOTIFY_SERVICE,
    CONF_SCAN_INTERVAL,
    CONF_SMTP_HOST,
    CONF_SMTP_PASSWORD,
    CONF_SMTP_PORT,
    CONF_SMTP_USERNAME,
    DEFAULT_BRUTE_FORCE_WINDOW,
    DEFAULT_FAILED_LOGIN_THRESHOLD,
    DEFAULT_NOTIFY_SERVICE,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SMTP_PORT,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            int, vol.Range(min=10, max=3600)
        ),
        vol.Required(
            CONF_FAILED_LOGIN_THRESHOLD, default=DEFAULT_FAILED_LOGIN_THRESHOLD
        ): vol.All(int, vol.Range(min=2, max=100)),
        vol.Required(
            CONF_BRUTE_FORCE_WINDOW, default=DEFAULT_BRUTE_FORCE_WINDOW
        ): vol.All(int, vol.Range(min=10, max=3600)),
        vol.Optional(CONF_NOTIFY_SERVICE, default=DEFAULT_NOTIFY_SERVICE): str,
        vol.Optional(CONF_GEO_API_KEY, default=""): str,
    }
)

STEP_EMAIL_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_EMAIL_RECIPIENT, default=""): str,
        vol.Optional(CONF_SMTP_HOST, default=""): str,
        vol.Optional(CONF_SMTP_PORT, default=DEFAULT_SMTP_PORT): vol.All(
            int, vol.Range(min=1, max=65535)
        ),
        vol.Optional(CONF_SMTP_USERNAME, default=""): str,
        vol.Optional(CONF_SMTP_PASSWORD, default=""): str,
    }
)


class SecuritySentinelConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Security Sentinel."""

    VERSION = 1
    _user_input: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        """Handle the initial step."""
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")
        if user_input is not None:
            self._user_input = user_input
            return await self.async_step_email()
        return self.async_show_form(step_id="user", data_schema=STEP_USER_SCHEMA)

    async def async_step_email(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        """Handle the email/SMTP step."""
        if user_input is not None:
            data = {**self._user_input, **user_input}
            return self.async_create_entry(title="Security Sentinel", data=data)
        return self.async_show_form(step_id="email", data_schema=STEP_EMAIL_SCHEMA)

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "SecuritySentinelOptionsFlow":
        """Return the options flow handler."""
        return SecuritySentinelOptionsFlow(config_entry)


class SecuritySentinelOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for Security Sentinel."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        c = self.config_entry.data
        schema = vol.Schema(
            {
                vol.Required(CONF_SCAN_INTERVAL, default=c.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): vol.All(int, vol.Range(min=10, max=3600)),
                vol.Required(CONF_FAILED_LOGIN_THRESHOLD, default=c.get(CONF_FAILED_LOGIN_THRESHOLD, DEFAULT_FAILED_LOGIN_THRESHOLD)): vol.All(int, vol.Range(min=2, max=100)),
                vol.Required(CONF_BRUTE_FORCE_WINDOW, default=c.get(CONF_BRUTE_FORCE_WINDOW, DEFAULT_BRUTE_FORCE_WINDOW)): vol.All(int, vol.Range(min=10, max=3600)),
                vol.Optional(CONF_NOTIFY_SERVICE, default=c.get(CONF_NOTIFY_SERVICE, DEFAULT_NOTIFY_SERVICE)): str,
                vol.Optional(CONF_GEO_API_KEY, default=c.get(CONF_GEO_API_KEY, "")): str,
                vol.Optional(CONF_EMAIL_RECIPIENT, default=c.get(CONF_EMAIL_RECIPIENT, "")): str,
                vol.Optional(CONF_SMTP_HOST, default=c.get(CONF_SMTP_HOST, "")): str,
                vol.Optional(CONF_SMTP_PORT, default=c.get(CONF_SMTP_PORT, DEFAULT_SMTP_PORT)): vol.All(int, vol.Range(min=1, max=65535)),
                vol.Optional(CONF_SMTP_USERNAME, default=c.get(CONF_SMTP_USERNAME, "")): str,
                vol.Optional(CONF_SMTP_PASSWORD, default=c.get(CONF_SMTP_PASSWORD, "")): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
