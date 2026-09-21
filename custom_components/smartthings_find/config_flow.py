"""Config, reauth and reconfigure flows for SmartThings Find."""

from typing import Any
import logging

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .auth import (
    PendingLogin,
    SmartThingsFindAuthError,
    async_finish_login,
    async_start_login,
)
from .const import (
    CONF_ACTIVE_MODE_OTHERS,
    CONF_ACTIVE_MODE_OTHERS_DEFAULT,
    CONF_ACTIVE_MODE_SMARTTAGS,
    CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT,
    CONF_JSESSIONID,
    CONF_UPDATE_INTERVAL,
    CONF_UPDATE_INTERVAL_DEFAULT,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class SmartThingsFindConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SmartThings Find."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    def __init__(self) -> None:
        self._login_url: str | None = None
        self._pending: PendingLogin | None = None

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        """Begin sign-in by handing the user a Samsung Account login URL."""
        session = async_get_clientsession(self.hass)
        try:
            self._login_url, self._pending = await async_start_login(
                session, self.hass.config.country
            )
        except SmartThingsFindAuthError as err:
            _LOGGER.error("Could not start Samsung Account sign-in: %s", err)
            return self.async_show_form(
                step_id="user",
                errors={"base": "login_error"},
                description_placeholders={"error_msg": str(err)},
            )
        return await self.async_step_auth_code()

    async def async_step_auth_code(self, user_input=None) -> ConfigFlowResult:
        """Take the pasted ms-app:// callback and store the credentials."""
        errors: dict[str, str] = {}
        error_msg = ""

        if user_input is not None and self._pending is not None:
            session = async_get_clientsession(self.hass)
            try:
                creds = await async_finish_login(
                    session, user_input["redirect_url"], self._pending
                )
            except SmartThingsFindAuthError as err:
                _LOGGER.error("Samsung Account sign-in failed: %s", err)
                errors["base"] = "auth_failed"
                error_msg = str(err)
            else:
                return self._async_finish(creds.to_entry_data())

        return self.async_show_form(
            step_id="auth_code",
            data_schema=vol.Schema({vol.Required("redirect_url"): str}),
            description_placeholders={
                "login_url": self._login_url or "",
                "error_msg": error_msg,
            },
            errors=errors,
        )

    @callback
    def _async_finish(self, data: dict[str, Any]) -> ConfigFlowResult:
        """Create the entry, or update the existing one when reauthenticating.

        Home Assistant 2025.11 turned calling async_create_entry inside a reauth
        or reconfigure flow into a hard error, so both of those paths have to
        update the entry they were started from and abort.
        """
        # Drop any cached cookie: it belongs to the previous session, and may
        # even belong to a different account if the user just switched.
        data_updates = {**data, CONF_JSESSIONID: None}

        if self.source == config_entries.SOURCE_REAUTH:
            return self.async_update_reload_and_abort(
                self._get_reauth_entry(), data_updates=data_updates
            )
        if self.source == config_entries.SOURCE_RECONFIGURE:
            return self.async_update_reload_and_abort(
                self._get_reconfigure_entry(), data_updates=data_updates
            )
        return self.async_create_entry(title="SmartThings Find", data=data)

    async def async_step_reauth(
        self, entry_data: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle re-authentication after the session could not be renewed."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None) -> ConfigFlowResult:
        """Confirm before restarting sign-in, so it isn't triggered silently."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm", data_schema=vol.Schema({})
            )
        return await self.async_step_user()

    async def async_step_reconfigure(self, user_input=None) -> ConfigFlowResult:
        """Handle the Reconfigure button on the integration entry."""
        return await self.async_step_user()

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> OptionsFlow:
        """Create the options flow."""
        return SmartThingsFindOptionsFlowHandler()


class SmartThingsFindOptionsFlowHandler(OptionsFlow):
    """Handle an options flow."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle options flow."""

        if user_input is not None:
            res = self.async_create_entry(title="", data=user_input)

            # Reload the integration entry to make sure the newly set options take effect
            self.hass.config_entries.async_schedule_reload(self.config_entry.entry_id)
            return res

        options = self.config_entry.options
        data_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_UPDATE_INTERVAL,
                    default=options.get(
                        CONF_UPDATE_INTERVAL, CONF_UPDATE_INTERVAL_DEFAULT
                    ),
                ): vol.All(vol.Coerce(int), vol.Clamp(min=30)),
                vol.Optional(
                    CONF_ACTIVE_MODE_SMARTTAGS,
                    default=options.get(
                        CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT
                    ),
                ): bool,
                vol.Optional(
                    CONF_ACTIVE_MODE_OTHERS,
                    default=options.get(
                        CONF_ACTIVE_MODE_OTHERS, CONF_ACTIVE_MODE_OTHERS_DEFAULT
                    ),
                ): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=data_schema)
