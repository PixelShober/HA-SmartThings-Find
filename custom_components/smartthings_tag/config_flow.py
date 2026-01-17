from typing import Any, Dict
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlowResult,
    OptionsFlowWithConfigEntry
)
from .const import (
    DOMAIN,
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_IOT_ACCESS_TOKEN,
    CONF_IOT_REFRESH_TOKEN,
    CONF_USER_ID,
    CONF_AUTH_SERVER_URL,
    CONF_DEVICE_ID,
    CONF_UPDATE_INTERVAL,
    CONF_UPDATE_INTERVAL_DEFAULT,
    CONF_ACTIVE_MODE_SMARTTAGS,
    CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT,
    CONF_ACTIVE_MODE_OTHERS,
    CONF_ACTIVE_MODE_OTHERS_DEFAULT
)
from .utils import do_login_stage_one, do_login_stage_two
import asyncio
import logging


_LOGGER = logging.getLogger(__name__)

class SmartThingsFindConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SmartThings Find."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    reauth_entry: ConfigEntry | None = None

    task_stage_one: asyncio.Task | None = None
    task_stage_two: asyncio.Task | None = None

    session = None

    jsessionid = None


    error = None

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
             # This is actually not reached usually if we return showing form immediately
             pass

        # Call stage one to get the URL
        login_url, err = await do_login_stage_one(self.hass)
        if not login_url:
            return self.async_show_form(
                step_id="user",
                errors={"base": "login_error"},
                description_placeholders={"error_msg": err}
            )
        
        # We store the state/verifier in hass.data in stage_one, so we are good.
        
        return await self.async_step_auth_code(login_url=login_url)

    async def async_step_auth_code(self, user_input=None, login_url=None):
        """Step where user enters the redirect URL."""
        errors = {}
        if user_input is not None:
            redirect_url_input = user_input.get("redirect_url")
            
            from .utils import do_login_stage_two
            
            token_data_find, token_data_iot, user_id, auth_server_url, err = await do_login_stage_two(
                self.hass,
                redirect_url_input
            )
            
            if not token_data_find or not token_data_iot:
                errors["base"] = "auth_failed"
                if err:
                    _LOGGER.error("Auth failed: %s", err)
                # We might want to restart flow or let user try again
            else:
                device_id = (
                    self.hass.data.get(DOMAIN, {})
                    .get("auth_data", {})
                    .get("device_id")
                )
                data = {
                    CONF_ACCESS_TOKEN: token_data_find.get('access_token'),
                    CONF_REFRESH_TOKEN: token_data_find.get('refresh_token'),
                    CONF_IOT_ACCESS_TOKEN: token_data_iot.get('access_token'),
                    CONF_IOT_REFRESH_TOKEN: token_data_iot.get('refresh_token'),
                    CONF_USER_ID: user_id,
                    CONF_AUTH_SERVER_URL: auth_server_url,
                    CONF_DEVICE_ID: device_id
                }
                
                if self.reauth_entry:
                     self.hass.config_entries.async_update_entry(self.reauth_entry, data=data)
                     self.hass.async_create_task(self.hass.config_entries.async_reload(self.reauth_entry.entry_id))
                     return self.async_abort(reason="reauth_successful")
                
                return self.async_create_entry(title="SmartThings Tag", data=data)

        # If we came from step_user, login_url is set. If we repost form with error, it is lost unless we store it?
        # But step_auth_code calls itself? 
        # Actually `async_step_user` called this.
        # Ideally we'd store login_url in self if we want to persist it across error re-renders.
        if login_url:
            self.login_url = login_url
        
        return self.async_show_form(
            step_id="auth_code",
            data_schema=vol.Schema({
                vol.Required("redirect_url"): str
            }),
            description_placeholders={
                "login_url": self.login_url
            },
            errors=errors
        )

    async def async_step_reauth(self, entry_data: dict[str, Any] | None = None):
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_user()

    
    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        return await self.async_step_user()
    
    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return SmartThingsFindOptionsFlowHandler(config_entry)
    
    
class SmartThingsFindOptionsFlowHandler(OptionsFlowWithConfigEntry):
    """Handle an options flow."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle options flow."""

        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        data_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_UPDATE_INTERVAL,
                    default=self.options.get(
                        CONF_UPDATE_INTERVAL, CONF_UPDATE_INTERVAL_DEFAULT
                    ),
                ): vol.All(vol.Coerce(int), vol.Clamp(min=30)),
                vol.Optional(
                    CONF_ACTIVE_MODE_SMARTTAGS,
                    default=self.options.get(
                        CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT
                    ),
                ): bool,
                vol.Optional(
                    CONF_ACTIVE_MODE_OTHERS,
                    default=self.options.get(
                        CONF_ACTIVE_MODE_OTHERS, CONF_ACTIVE_MODE_OTHERS_DEFAULT
                    ),
                ): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=data_schema)
