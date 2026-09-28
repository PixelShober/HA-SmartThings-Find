from datetime import timedelta
import logging
import aiohttp
from homeassistant.components import persistent_notification
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.const import Platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.config_entries import ConfigEntry

from .const import (
    DOMAIN,
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_IOT_ACCESS_TOKEN,
    CONF_IOT_REFRESH_TOKEN,
    CONF_USER_ID,
    CONF_AUTH_SERVER_URL,
    CONF_DEVICE_ID,
    CONF_ST_USER_UUID,
    CONF_INSTALLED_APP_ID,
    CONF_USER_AUTH_TOKEN,
    CONF_LOGIN_ID,
    CONF_WEB_JSESSIONID,
    CONF_ACTIVE_MODE_OTHERS,
    CONF_ACTIVE_MODE_OTHERS_DEFAULT,
    CONF_ACTIVE_MODE_SMARTTAGS,
    CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT,
    CONF_UPDATE_INTERVAL,
    CONF_UPDATE_INTERVAL_DEFAULT,
)
from .utils import get_devices, get_device_location, get_ring_status, _web_ensure_session

_LOGGER = logging.getLogger(__name__)

# Fixed id so automations can trigger on it (trigger platform: persistent_notification)
WEB_SESSION_NOTIFICATION = "smartthings_find_web_session"

PLATFORMS = [Platform.DEVICE_TRACKER, Platform.SENSOR, Platform.SWITCH]

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the SmartThings Find component."""
    hass.data[DOMAIN] = {}
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up SmartThings Find from a config entry."""
    
    hass.data[DOMAIN][entry.entry_id] = {}

    # Load the tokens from the config
    access_token = entry.data.get(CONF_ACCESS_TOKEN)
    refresh_token = entry.data.get(CONF_REFRESH_TOKEN)
    iot_access_token = entry.data.get(CONF_IOT_ACCESS_TOKEN)
    iot_refresh_token = entry.data.get(CONF_IOT_REFRESH_TOKEN)
    auth_server_url = entry.data.get(CONF_AUTH_SERVER_URL)
    user_id = entry.data.get(CONF_USER_ID)
    device_id = entry.data.get(CONF_DEVICE_ID)
    st_user_uuid = entry.data.get(CONF_ST_USER_UUID)
    installed_app_id = entry.data.get(CONF_INSTALLED_APP_ID)
    
    # Store in hass.data so utils can access it
    hass.data[DOMAIN][entry.entry_id].update({
        CONF_ACCESS_TOKEN: access_token,
        CONF_REFRESH_TOKEN: refresh_token,
        CONF_IOT_ACCESS_TOKEN: iot_access_token,
        CONF_IOT_REFRESH_TOKEN: iot_refresh_token,
        CONF_AUTH_SERVER_URL: auth_server_url,
        CONF_USER_ID: user_id,
        CONF_DEVICE_ID: device_id,
        CONF_ST_USER_UUID: st_user_uuid,
        CONF_INSTALLED_APP_ID: installed_app_id,
        CONF_USER_AUTH_TOKEN: entry.data.get(CONF_USER_AUTH_TOKEN),
        CONF_LOGIN_ID: entry.data.get(CONF_LOGIN_ID),
        # Set in the options flow - the one thing that cannot be automated.
        CONF_WEB_JSESSIONID: entry.options.get(CONF_WEB_JSESSIONID),
    })

    # Web authentication uses cookies, which must stay isolated to this account.
    session = async_create_clientsession(hass)
    active_smarttags = entry.options.get(CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT)
    active_others = entry.options.get(CONF_ACTIVE_MODE_OTHERS, CONF_ACTIVE_MODE_OTHERS_DEFAULT)
    hass.data[DOMAIN][entry.entry_id].update({
        CONF_ACTIVE_MODE_SMARTTAGS:  active_smarttags,
        CONF_ACTIVE_MODE_OTHERS: active_others,
    })

    # No CSRF fetch needed for OAuth
    # await fetch_csrf(hass, session, entry.entry_id)
    
    # Load all SmartThings-Find devices from the users account
    devices = await get_devices(hass, session, entry.entry_id)
    
    # Create an update coordinator. This is responsible to regularly
    # fetch data from STF and update the device_tracker and sensor
    # entities
    update_interval = entry.options.get(CONF_UPDATE_INTERVAL, CONF_UPDATE_INTERVAL_DEFAULT)
    coordinator = SmartThingsFindCoordinator(hass, session, devices, update_interval, entry.entry_id)

    # This is what makes the whole integration slow to load (around 10-15
    # seconds for my 15 devices) but it is the right way to do it. Only if
    # it succeeds, the integration will be marked as successfully loaded.
    await coordinator.async_config_entry_first_refresh()
    
    hass.data[DOMAIN][entry.entry_id].update({
        "session": session,
        "coordinator": coordinator,
        "devices": devices
    })

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    hass.async_create_task(
        hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    )
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_success = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_success:
        hass.data[DOMAIN].pop(entry.entry_id)
    else:
        _LOGGER.error(f"Unload failed: {unload_success}")
    return unload_success


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options updates."""
    await hass.config_entries.async_reload(entry.entry_id)


class SmartThingsFindCoordinator(DataUpdateCoordinator):
    """Class to manage fetching SmartThings Find data."""

    def __init__(
        self,
        hass: HomeAssistant,
        session: aiohttp.ClientSession,
        devices,
        update_interval: int,
        entry_id: str
    ):
        """Initialize the coordinator."""
        self.session = session
        self.devices = devices
        self.hass = hass
        self.entry_id = entry_id
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval)  # Update interval for all entities
        )

    def _notify_web_session(self, ok: bool) -> None:
        """Raise/clear a notification on state changes only, so it is not re-posted every poll.
        Starts as unknown: a reload after a fresh cookie must still clear an old notification."""
        if ok == getattr(self, "_web_ok", None):
            return
        self._web_ok = ok
        if ok:
            persistent_notification.async_dismiss(self.hass, WEB_SESSION_NOTIFICATION)
            return
        persistent_notification.async_create(
            self.hass,
            "Die Web-Session ist abgelaufen – Handy und Buds lassen sich gerade nicht "
            "klingeln (Tags schon). Normalerweise erneuert der Login-Bot sie innerhalb "
            "einer Stunde von selbst. Bleibt diese Meldung stehen, ist der Bot ausgefallen: "
            "dann auf smartthingsfind.samsung.com anmelden, das JSESSIONID-Cookie kopieren "
            "und unter Einstellungen → Geräte & Dienste → SmartThings Find → Konfigurieren "
            "einfügen.",
            title="SmartThings Find: Web-Session abgelaufen",
            notification_id=WEB_SESSION_NOTIFICATION,
        )

    async def _async_update_data(self):
        """Fetch data from SmartThings Find."""
        try:
            tags = {}
            _LOGGER.debug(f"Updating locations...")
            for device in self.devices:
                dev_data = device['data']
                tag_data = await get_device_location(self.hass, self.session, dev_data, self.entry_id)
                tags[dev_data['device_id']] = tag_data
            _LOGGER.debug(f"Fetched {len(tags)} locations")
            # Keep-alive: the web session idles out after 30 min and cannot be
            # re-minted, so touch it on every poll. Cheap, and never fatal -
            # tags ring through the tracker API regardless.
            if self.hass.data[DOMAIN][self.entry_id].get(CONF_WEB_JSESSIONID):
                web_ok = await _web_ensure_session(self.hass, self.session, self.entry_id)
                self._notify_web_session(web_ok)
                if not web_ok:
                    _LOGGER.warning(
                        "SmartThings Find web session is no longer valid - paste a "
                        "fresh JSESSIONID in the integration options to keep "
                        "ringing phones and earbuds"
                    )
                else:
                    # Live ring state, so rings started from the app show up too
                    for device in self.devices:
                        dev_data = device['data']
                        if not dev_data.get("is_tracker"):
                            tags[dev_data['device_id']]["ring"] = await get_ring_status(
                                self.hass, self.session, self.entry_id, dev_data)
            return tags
        except ConfigEntryAuthFailed as err:
            raise
        except Exception as err:
            raise UpdateFailed(f"Error fetching data: {err}")
