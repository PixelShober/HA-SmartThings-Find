"""Shared test fixtures.

This repository has no dependency on the real ``homeassistant`` package (it
only ships as a HACS custom component, installed into a live HA instance).
To keep the test suite hermetic and fast, this stubs the exact
``homeassistant`` symbols that
``custom_components/smartthings_find/device_tracker.py`` imports. If a real
``homeassistant`` install is present (e.g. via
pytest-homeassistant-custom-component), it is used instead and this stub is
skipped.
"""
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _register_namespace_package(name: str, path: Path) -> None:
    """Register `name` as an already-imported package pointing at `path`.

    custom_components/smartthings_find/__init__.py pulls in aiohttp and other
    runtime-only dependencies that this test suite has no need for (it only
    exercises device_tracker.py). Pre-populating sys.modules with a bare
    package object lets `import custom_components.smartthings_find.device_tracker`
    resolve submodules from disk without ever executing that __init__.py.
    """
    if name in sys.modules:
        return
    module = types.ModuleType(name)
    module.__path__ = [str(path)]
    sys.modules[name] = module


def _install_homeassistant_stub() -> None:
    if "homeassistant" in sys.modules:
        return
    try:
        import homeassistant  # noqa: F401
        return
    except ImportError:
        pass

    def callback(func):
        """Stand-in for homeassistant.core.callback (a plain marker decorator)."""
        return func

    class HomeAssistant:
        pass

    class ConfigEntry:
        pass

    class Entity:
        """Minimal stand-in for homeassistant.helpers.entity.Entity."""

        enabled = True
        entity_id = None

        def async_write_ha_state(self):
            pass

    class TrackerEntity(Entity):
        """Minimal stand-in for the real TrackerEntity."""

    class SourceType:
        GPS = "gps"

    class AddEntitiesCallback:
        pass

    modules = {}

    ha = types.ModuleType("homeassistant")
    modules["homeassistant"] = ha

    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = HomeAssistant
    core.callback = callback
    modules["homeassistant.core"] = core

    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = ConfigEntry
    modules["homeassistant.config_entries"] = config_entries

    modules["homeassistant.components"] = types.ModuleType("homeassistant.components")
    modules["homeassistant.components.device_tracker"] = types.ModuleType(
        "homeassistant.components.device_tracker"
    )

    device_tracker_config_entry = types.ModuleType(
        "homeassistant.components.device_tracker.config_entry"
    )
    device_tracker_config_entry.TrackerEntity = TrackerEntity
    modules["homeassistant.components.device_tracker.config_entry"] = device_tracker_config_entry

    device_tracker_const = types.ModuleType("homeassistant.components.device_tracker.const")
    device_tracker_const.SourceType = SourceType
    modules["homeassistant.components.device_tracker.const"] = device_tracker_const

    modules["homeassistant.helpers"] = types.ModuleType("homeassistant.helpers")

    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
    entity_platform.AddEntitiesCallback = AddEntitiesCallback
    modules["homeassistant.helpers.entity_platform"] = entity_platform

    sys.modules.update(modules)


_install_homeassistant_stub()
_register_namespace_package("custom_components", REPO_ROOT / "custom_components")
_register_namespace_package(
    "custom_components.smartthings_find", REPO_ROOT / "custom_components" / "smartthings_find"
)
