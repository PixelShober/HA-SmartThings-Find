import logging
from datetime import timedelta

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, RING_TIMEOUT_SECONDS
from .utils import ring_device, stop_ring_device, format_ring_error, get_ring_status

_LOGGER = logging.getLogger(__name__)

# Device answers ~2 s after a command (measured), so 3 s shows changes promptly
FAST_POLL = timedelta(seconds=3)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SmartThings Find switch entities."""
    data = hass.data[DOMAIN][entry.entry_id]
    # Every device type can be rung via the web API, not just trackers
    async_add_entities(
        RingSwitch(data["coordinator"], hass, entry.entry_id, device)
        for device in data["devices"]
    )


class RingSwitch(CoordinatorEntity, SwitchEntity):
    """Ring switch. Phones/buds report their real ring state; tags are optimistic
    (on = request accepted, auto-stop after RING_TIMEOUT_SECONDS)."""

    def __init__(self, coordinator, hass: HomeAssistant, entry_id: str, device: dict) -> None:
        super().__init__(coordinator)
        self.hass = hass
        self.entry_id = entry_id
        self.device = device["data"]
        device_id = self.device.get("device_id")
        name = self.device.get("name") or device_id or "SmartThings Find"

        self._attr_unique_id = f"stf_ring_switch_{device_id}"
        self._attr_name = f"{name} Ring"
        self._attr_icon = "mdi:bell-ring"
        self._attr_device_info = device["ha_dev_info"]
        self._name = name
        # Tags only get a server-side flag and never report back. No assumed_state on
        # purpose: that would render two buttons instead of a toggle.
        self._optimistic = bool(self.device.get("is_tracker"))

        icon_url = self.device.get("icon_url")
        if icon_url:
            self._attr_entity_picture = icon_url

        self._is_on = False
        self._ring_state = "idle" if self._optimistic else "unknown"
        self._op = None
        self._auto_off_cancel = None
        self._poll_cancel = None
        self._poll_ticks = 0

    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def extra_state_attributes(self) -> dict:
        op = self._op or {}
        return {
            "ring_status": self._ring_state,
            "ring_message": self._message(),
            "operation_status_code": op.get("oprnStsCd"),
            "operation_result_code": op.get("oprnResultCode"),
            "operation_done": op.get("oprnDoneDate"),
        }

    def _message(self) -> str:
        """What the STF web page's ring dialog says (its success_/error_ring_* strings, in German)."""
        s, name = self._ring_state, self._name
        if self._optimistic:
            # The page only knows whether the request was accepted - a tag rings once a
            # Galaxy device gets near it, and it never reports back.
            return {
                "requested": f"Dein {name} hat geklingelt.",
                "error": "Keine Verbindung zum Tag – Klingeln nicht möglich.",
            }.get(s, f"{name} klingelt, wenn du auf Start klickst.")
        buds = "left" in ((self._op or {}).get("extra") or {})
        return {
            "pending": f"Verbinde mit {name} …",
            "ringing": f"Klicke auf Stopp, wenn du {name} gefunden hast." if buds
                       else f"{name} hat geklingelt.",
            "error_fmm_off": f"{name} kann nicht geortet oder gesteuert werden, "
                             "weil „Mein Gerät finden“ in den Einstellungen deaktiviert ist.",
            "error_on_call": "„Meine Ohrhörer finden“ geht nicht während eines Anrufs.",
            "error_wearing": "Du scheinst die Ohrhörer bereits zu tragen.",
        }.get(s, (f"Keine Verbindung zu {name} – Klingeln nicht möglich."
                  if s.startswith("error_") else f"{name} klingelt, wenn du auf Start klickst."))

    def _session(self):
        return self.hass.data[DOMAIN][self.entry_id]["session"]

    def _apply(self, state: str, op: dict | None) -> None:
        self._ring_state, self._op = state, op
        if state == "ringing":
            self._is_on = True
        elif state == "idle" or state.startswith("error_"):
            if self._is_on and state.startswith("error_"):
                _LOGGER.warning("Ring for %s failed: %s", self._attr_name, state)
            self._is_on = False
        # pending / unknown: keep the current state

    @callback
    def _handle_coordinator_update(self) -> None:
        ring = (self.coordinator.data or {}).get(self.device.get("device_id"), {}).get("ring")
        if ring and not self._optimistic:
            self._apply(*ring)
            if self._is_on:
                self._start_fast_poll()  # rung from the app/web -> follow it closely
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._handle_coordinator_update()  # first refresh ran before we existed

    # --- fast polling while a ring is in flight (phones/buds) ---

    def _start_fast_poll(self) -> None:
        self._poll_ticks = 0
        if not self._poll_cancel:
            self._poll_cancel = async_track_time_interval(self.hass, self._async_poll, FAST_POLL)

    def _stop_fast_poll(self) -> None:
        if self._poll_cancel:
            self._poll_cancel()
            self._poll_cancel = None

    async def _async_poll(self, _now=None) -> None:
        self._poll_ticks += 1
        state, op = await get_ring_status(self.hass, self._session(), self.entry_id, self.device)
        self._apply(state, op)
        # Stop once settled; cap it in case the device never answers
        capped = self._poll_ticks * FAST_POLL.total_seconds() > RING_TIMEOUT_SECONDS
        if capped and state != "ringing":
            self._is_on = False
        if capped or (not self._is_on and state != "pending"):
            self._stop_fast_poll()
        self.async_write_ha_state()

    # --- optimistic auto-off for tags ---

    def _cancel_auto_off(self) -> None:
        if self._auto_off_cancel:
            self._auto_off_cancel()
            self._auto_off_cancel = None

    def _handle_auto_off(self, _now) -> None:
        self._auto_off_cancel = None
        if self._is_on:
            self.hass.async_create_task(self._async_auto_off())

    async def _async_auto_off(self) -> None:
        ok, err = await stop_ring_device(self.hass, self._session(), self.entry_id, self.device)
        if not ok:
            _LOGGER.error("Auto ring stop failed for %s: %s", self._attr_name, err)
        self._is_on = False
        self._ring_state = "idle"
        self.async_write_ha_state()

    # --- commands ---

    async def _send(self, start: bool) -> None:
        fn = ring_device if start else stop_ring_device
        ok, err = await fn(self.hass, self._session(), self.entry_id, self.device)
        if not ok:
            message = format_ring_error(err)
            _LOGGER.error("Ring %s failed for %s: %s",
                          "start" if start else "stop", self._attr_name, message)
            if self._optimistic and start:
                self._ring_state = "error"
                self.async_write_ha_state()
            raise HomeAssistantError(message)
        self._is_on = start
        if self._optimistic:
            self._ring_state = "requested" if start else "idle"
        else:
            self._ring_state = "pending"
        self.async_write_ha_state()
        if self._optimistic:
            self._cancel_auto_off()
            if start:
                self._auto_off_cancel = async_call_later(
                    self.hass, RING_TIMEOUT_SECONDS, self._handle_auto_off)
        else:
            self._start_fast_poll()

    async def async_turn_on(self, **kwargs) -> None:
        await self._send(True)

    async def async_turn_off(self, **kwargs) -> None:
        await self._send(False)

    async def async_will_remove_from_hass(self) -> None:
        self._cancel_auto_off()
        self._stop_fast_poll()
        await super().async_will_remove_from_hass()
