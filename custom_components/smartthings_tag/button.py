import logging
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .utils import ring_device, stop_ring_device, format_ring_error

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up SmartThings Find button entities."""
    devices = hass.data[DOMAIN][entry.entry_id]["devices"]
    entities = []
    for device in devices:
        if device["data"].get("is_tracker"):
            entities += [
                RingButton(hass, entry.entry_id, device),
                StopRingButton(hass, entry.entry_id, device),
            ]
    async_add_entities(entities)


class RingButton(ButtonEntity):
    """Representation a button entity to make a SmartThings Find device ring."""

    def __init__(self, hass: HomeAssistant, entry_id: str, device):
        """Initialize the button."""
        self.hass = hass
        self.entry_id = entry_id
        self.device = device['data']
        device_id = self.device.get("device_id")
        name = self.device.get("name") or device_id or "SmartThings Tag"
        self._attr_unique_id = f"stf_ring_button_{device_id}"
        self._attr_name = f"{name} Ring"

        icon_url = self.device.get("icon_url")
        if icon_url:
            self._attr_entity_picture = icon_url
        self._attr_icon = 'mdi:nfc-search-variant'
        self._attr_device_info = device['ha_dev_info']

    async def async_press(self):
        """Handle the button press."""
        session = self.hass.data[DOMAIN][self.entry_id]["session"]
        ok, err = await ring_device(self.hass, session, self.entry_id, self.device)
        if ok:
            _LOGGER.info("Successfully rang device %s", self.device.get("name") or self.device.get("device_id"))
            return

        message = format_ring_error(err)
        _LOGGER.error(
            "Failed to ring device %s: %s",
            self.device.get("name") or self.device.get("device_id"),
            message,
        )
        raise HomeAssistantError(message)


class StopRingButton(ButtonEntity):
    """Representation a button entity to stop a SmartThings Find device ring."""

    def __init__(self, hass: HomeAssistant, entry_id: str, device):
        """Initialize the button."""
        self.hass = hass
        self.entry_id = entry_id
        self.device = device['data']
        device_id = self.device.get("device_id")
        name = self.device.get("name") or device_id or "SmartThings Tag"
        self._attr_unique_id = f"stf_ring_stop_button_{device_id}"
        self._attr_name = f"{name} Stop Ring"

        icon_url = self.device.get("icon_url")
        if icon_url:
            self._attr_entity_picture = icon_url
        self._attr_icon = 'mdi:bell-off'
        self._attr_device_info = device['ha_dev_info']

    async def async_press(self):
        """Handle the button press."""
        session = self.hass.data[DOMAIN][self.entry_id]["session"]
        ok, err = await stop_ring_device(self.hass, session, self.entry_id, self.device)
        if ok:
            _LOGGER.info("Successfully stopped ringing for %s", self.device.get("name") or self.device.get("device_id"))
            return

        message = format_ring_error(err)
        _LOGGER.error(
            "Failed to stop ringing for %s: %s",
            self.device.get("name") or self.device.get("device_id"),
            message,
        )
        raise HomeAssistantError(message)
