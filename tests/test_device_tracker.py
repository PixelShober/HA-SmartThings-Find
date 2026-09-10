"""Tests for the coordinator-update write gating in SmartThingsDeviceTracker.

TrackerEntity forces every async_write_ha_state() call to bump the entity's
last_updated, even when the state and attributes are unchanged. Since
homeassistant.components.person picks a GPS source by last_updated alone,
an unfiltered write on every poll let a stale cached fix keep outranking a
freshly-reporting phone. _handle_coordinator_update must write only when the
identity of the fix itself (availability, location_found, gps_date,
latitude, longitude, gps_accuracy) actually changes.
"""
from unittest import mock

import pytest
from homeassistant.components.device_tracker.config_entry import TrackerEntity

from custom_components.smartthings_find.device_tracker import SmartThingsDeviceTracker


class FakeCoordinator:
    """Stand-in for the DataUpdateCoordinator used by the tracker."""

    def __init__(self):
        self.data = {}
        self._listeners = []

    def async_add_listener(self, listener):
        self._listeners.append(listener)
        return lambda: None

    def push(self, data):
        """Simulate a coordinator refresh delivering new data."""
        self.data = data
        for listener in self._listeners:
            listener()


@pytest.fixture
def write_spy(monkeypatch):
    """Count actual state writes at the base-entity level.

    SmartThingsDeviceTracker.async_write_ha_state() always delegates to
    super().async_write_ha_state() (resolved fresh on every call via super()),
    so patching it here observes real writes regardless of how or when the
    coordinator captured its listener reference.
    """
    spy = mock.Mock()
    monkeypatch.setattr(TrackerEntity, "async_write_ha_state", spy)
    return spy


def make_tracker(coordinator, device_id="dev1"):
    device = {
        "data": {"device_id": device_id, "name": "My Tag"},
        "ha_dev_info": {},
    }
    return SmartThingsDeviceTracker(hass=None, coordinator=coordinator, device=device)


def make_fix(gps_date="t1", lat=1.0, lon=2.0, acc=5, location_found=True,
             update_success=True, battery_level=80, **extra_telemetry):
    """Build one device's coordinator payload for a given GPS fix."""
    data = {
        "update_success": update_success,
        "location_found": location_found,
        "used_loc": {
            "gps_date": gps_date,
            "latitude": lat,
            "longitude": lon,
            "gps_accuracy": acc,
        },
        "battery_level": battery_level,
    }
    data.update(extra_telemetry)
    return data


def test_first_update_writes_state(write_spy):
    coordinator = FakeCoordinator()
    make_tracker(coordinator)

    coordinator.push({"dev1": make_fix()})

    assert write_spy.call_count == 1


def test_identical_fix_is_not_rewritten(write_spy):
    coordinator = FakeCoordinator()
    make_tracker(coordinator)
    coordinator.push({"dev1": make_fix()})

    coordinator.push({"dev1": make_fix()})

    assert write_spy.call_count == 1


def test_battery_only_change_does_not_rewrite(write_spy):
    """Regression: a battery-only refresh must not re-promote the tracker."""
    coordinator = FakeCoordinator()
    make_tracker(coordinator)
    coordinator.push({"dev1": make_fix(battery_level=80)})

    coordinator.push({"dev1": make_fix(battery_level=42)})

    assert write_spy.call_count == 1


def test_volatile_telemetry_only_change_does_not_rewrite(write_spy):
    """Regression: raw_item noise (rssi, scanCnt, ...) must not re-promote it."""
    coordinator = FakeCoordinator()
    make_tracker(coordinator)
    coordinator.push({"dev1": make_fix()})

    coordinator.push({"dev1": make_fix(
        timeGap=99, scanCnt=3, rssi=-70, d2dStatus="A", connectedDevice="phone-x",
    )})

    assert write_spy.call_count == 1


def test_new_gps_fix_rewrites(write_spy):
    coordinator = FakeCoordinator()
    make_tracker(coordinator)
    coordinator.push({"dev1": make_fix(gps_date="t1")})

    coordinator.push({"dev1": make_fix(gps_date="t2", lat=1.1)})

    assert write_spy.call_count == 2


def test_availability_change_rewrites(write_spy):
    coordinator = FakeCoordinator()
    make_tracker(coordinator)
    coordinator.push({"dev1": make_fix(update_success=True)})

    coordinator.push({"dev1": make_fix(update_success=False)})

    assert write_spy.call_count == 2


def test_missing_device_data_is_not_rewritten_repeatedly(write_spy):
    coordinator = FakeCoordinator()
    make_tracker(coordinator)

    coordinator.push({})
    coordinator.push({})

    assert write_spy.call_count == 1
