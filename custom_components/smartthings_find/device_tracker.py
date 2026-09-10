import logging
from homeassistant.components.device_tracker.config_entry import TrackerEntity as DeviceTrackerEntity
from homeassistant.components.device_tracker.const import SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up SmartThings Find device tracker entities."""
    devices = hass.data[DOMAIN][entry.entry_id]["devices"]
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []
    for device in devices:
        entities += [SmartThingsDeviceTracker(hass, coordinator, device)]
    async_add_entities(entities)

class SmartThingsDeviceTracker(DeviceTrackerEntity):
    """Representation of a SmartTag device tracker."""

    def __init__(self, hass: HomeAssistant, coordinator, device):
        """Initialize the device tracker."""

        self.coordinator = coordinator
        self.hass = hass
        self.device = device['data']
        self.device_id = self.device.get("device_id")

        name = self.device.get("name") or self.device_id or "SmartThings Find"
        self._attr_unique_id = f"stf_device_tracker_{self.device_id}"
        self._attr_name = name
        self._attr_device_info = device['ha_dev_info']
        self._attr_latitude = None
        self._attr_longitude = None

        icon_url = self.device.get("icon_url")
        if icon_url:
            self._attr_entity_picture = icon_url
        self._last_fix_key = None
        self.async_update = coordinator.async_add_listener(
            self._handle_coordinator_update
        )

    def _fix_key(self):
        """Identity of the current fix. Excludes volatile API telemetry."""
        data = self.coordinator.data.get(self.device_id) or {}
        used_loc = data.get('used_loc') or {}
        return (
            bool(data) and bool(data.get('update_success')),
            bool(data.get('location_found')),
            used_loc.get('gps_date'),
            used_loc.get('latitude'),
            used_loc.get('longitude'),
            used_loc.get('gps_accuracy'),
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Write state only when the fix or availability actually changed.

        TrackerEntity sets force_update=True, so every write bumps
        last_updated and re-promotes this entity to 'most recently updated
        GPS tracker' in the person integration, regardless of fix age.
        Suppressing no-op writes is the only way to stop that.
        """
        key = self._fix_key()
        if key == self._last_fix_key:
            return
        self._last_fix_key = key
        self.async_write_ha_state()

    def async_write_ha_state(self):
        if not self.enabled:
            _LOGGER.debug(f"Ignoring state write request for disabled entity '{self.entity_id}'")
            return
        return super().async_write_ha_state()

    @property
    def available(self) -> bool:
        """Return true if the device is available."""
        tag_data = self.coordinator.data.get(self.device_id, {})
        if not tag_data:
            _LOGGER.info(f"tag_data none for '{self.name}'; rendering state unavailable")
            return False
        if not tag_data.get('update_success'):
            _LOGGER.info(f"Last update for '{self.name}' failed; rendering state unavailable")
            return False
        return True
    
    @property
    def source_type(self) -> str:
        return SourceType.GPS
    
    @property
    def latitude(self):
        """Return the latitude of the device."""
        data = self.coordinator.data.get(self.device_id, {})
        if data.get('location_found'):
            return data.get('used_loc', {}).get('latitude', None)
        return None

    @property
    def longitude(self):
        """Return the longitude of the device."""
        data = self.coordinator.data.get(self.device_id, {})
        if data.get('location_found'):
            return data.get('used_loc', {}).get('longitude', None)
        return None
    
    @property
    def location_accuracy(self):
        """Return the location accuracy of the device."""
        data = self.coordinator.data.get(self.device_id, {})
        if data.get('location_found'):
            return data.get('used_loc', {}).get('gps_accuracy', None)
        return None

    @property
    def battery_level(self):
        """Return the battery level of the device."""
        data = self.coordinator.data.get(self.device_id, {})
        return data.get('battery_level')
    
    @property
    def extra_state_attributes(self):
        tag_data = self.coordinator.data.get(self.device_id, {}) or {}
        device_data = self.device or {}
        used_loc = tag_data.get('used_loc') or {}
        attrs = {}
        attrs.update(device_data)
        attrs.update(tag_data)
        attrs['last_seen'] = used_loc.get('gps_date')
        return attrs
