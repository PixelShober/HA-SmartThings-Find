import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN, RING_TIMEOUT_SECONDS
from .utils import ring_device, stop_ring_device, format_ring_error

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SmartThings Find switch entities."""
    devices = hass.data[DOMAIN][entry.entry_id]["devices"]
    entities = []
    for device in devices:
        if device["data"].get("is_tracker"):
            entities.append(RingSwitch(hass, entry.entry_id, device))
    async_add_entities(entities)


class RingSwitch(SwitchEntity):
    """Optimistic switch for starting/stopping a tracker ring."""

    _attr_assumed_state = True

    def __init__(self, hass: HomeAssistant, entry_id: str, device: dict) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self.device = device["data"]
        device_id = self.device.get("device_id")
        name = self.device.get("name") or device_id or "SmartThings Find"

        self._attr_unique_id = f"stf_ring_switch_{device_id}"
        self._attr_name = f"{name} Ring"
        self._attr_icon = "mdi:bell-ring"
        self._attr_device_info = device["ha_dev_info"]

        icon_url = self.device.get("icon_url")
        if icon_url:
            self._attr_entity_picture = icon_url

        self._is_on = False
        self._auto_off_cancel = None

    @property
    def is_on(self) -> bool:
        return self._is_on

    def _cancel_auto_off(self) -> None:
        if self._auto_off_cancel:
            self._auto_off_cancel()
            self._auto_off_cancel = None

    def _schedule_auto_off(self) -> None:
        self._cancel_auto_off()
        self._auto_off_cancel = async_call_later(
            self.hass,
            RING_TIMEOUT_SECONDS,
            self._handle_auto_off,
        )

    def _handle_auto_off(self, _now) -> None:
        self._auto_off_cancel = None
        if not self._is_on:
            return
        self.hass.async_create_task(self._async_auto_off())

    async def _async_auto_off(self) -> None:
        session = self.hass.data[DOMAIN][self.entry_id]["session"]
        ok, err = await stop_ring_device(self.hass, session, self.entry_id, self.device)
        if not ok:
            _LOGGER.error(
                "Auto ring stop failed for %s: %s",
                self.device.get("name") or self.device.get("device_id"),
                err,
            )
        self._is_on = False
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs) -> None:
        session = self.hass.data[DOMAIN][self.entry_id]["session"]
        ok, err = await ring_device(self.hass, session, self.entry_id, self.device)
        if ok:
            self._is_on = True
            self.async_write_ha_state()
            self._schedule_auto_off()
            return

        message = format_ring_error(err)
        _LOGGER.error(
            "Failed to ring device %s: %s",
            self.device.get("name") or self.device.get("device_id"),
            message,
        )
        raise HomeAssistantError(message)

    async def async_turn_off(self, **kwargs) -> None:
        self._cancel_auto_off()
        session = self.hass.data[DOMAIN][self.entry_id]["session"]
        ok, err = await stop_ring_device(self.hass, session, self.entry_id, self.device)
        if not ok:
            message = format_ring_error(err)
            _LOGGER.error(
                "Failed to stop ringing for %s: %s",
                self.device.get("name") or self.device.get("device_id"),
                message,
            )
            raise HomeAssistantError(message)
        self._is_on = False
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        self._cancel_auto_off()
