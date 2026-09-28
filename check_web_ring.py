#!/usr/bin/env python3
"""
Self-check for the web-API ring path (run directly: python3 check_web_ring.py).

Fixtures are live Samsung API responses from 2026-09-16 (ids and names anonymized),
including the double HTML escaping the web frontend applies to device names.
This guards the riskiest assumption in the implementation: that devices from the
SmartThings device list can be matched to the web API's own numeric device ids.
"""
import html

# --- fixtures: real response shapes, anonymized and trimmed to the fields the integration reads ----

SMARTTHINGS_DEVICES = [
    {"stDid": "00000000-0000-4000-8000-000000000001", "stDevName": "Rucksack", "locationType": "TRACKER"},
    {"stDid": "00000000-0000-4000-8000-000000000002", "stDevName": "Koffer", "locationType": "TRACKER"},
    {"stDid": "00000000-0000-4000-8000-000000000003", "stDevName": "Schlüssel", "locationType": "TRACKER"},
    {"fmmDevId": "00:00:00:00:00:01", "fmmDevName": "Alex's Buds3 Pro", "locationType": "FMM"},
    {"fmmDevId": "00:00:00:00:00:02", "fmmDevName": "Galaxy Buds+", "locationType": "FMM"},
    {"fmmDevId": "IMEI:000000000000000", "fmmDevName": "Alex's S22 Ultra", "locationType": "FMM"},
]

WEB_DEVICE_LIST = {"deviceList": [
    {"dvceID": "100000001", "modelName": "Alex&amp;#39;s Buds3 Pro", "deviceTypeCode": "HEARABLE"},
    {"dvceID": "100000002", "modelName": "Koffer", "deviceTypeCode": "TAG"},
    {"dvceID": "100000003", "modelName": "Rucksack", "deviceTypeCode": "TAG"},
    {"dvceID": "100000004", "modelName": "Schlüssel", "deviceTypeCode": "TAG"},
    {"dvceID": "100000005", "modelName": "Alex&amp;#39;s S22 Ultra", "deviceTypeCode": "PHONE DEVICE"},
    {"dvceID": "100000006", "modelName": "Galaxy Buds+", "deviceTypeCode": "HEARABLE"},
]}


# --- logic mirrored from utils.py -------------------------------------------

def html_unescape(value):
    """utils._html_unescape - loops because the web API escapes twice."""
    if not isinstance(value, str):
        return ""
    current = value
    for _ in range(3):
        decoded = html.unescape(current)
        if decoded == current:
            break
        current = decoded
    return current


def device_name(device):
    """utils.get_devices name resolution."""
    return html_unescape(
        device.get("stDevName")
        or device.get("fmmDevName")
        or device.get("deviceName")
        or device.get("name")
    )


def web_device_ids(payload):
    """utils._web_device_ids"""
    return {
        html_unescape(d.get("modelName")): d.get("dvceID")
        for d in payload.get("deviceList", [])
        if d.get("modelName") and d.get("dvceID")
    }


def ring_payload(dvce_id, user_id, start):
    """utils._web_ring payload - must match what the site's own JS sends."""
    return {
        "dvceId": dvce_id,
        "operation": "RING",
        "usrId": user_id,
        "status": "start" if start else "stop",
    }


def check_web_session_is_borrowed_not_minted():
    """
    Minting a web session headlessly is impossible (verified 2026-09-18): the
    browser's code is bound to redirect_uri=<base>/login.do, login.do redeems
    only such codes, and authorize rejects redirect_uri with 400
    unauthorized_client. The old _web_login *looked* like it worked - authorize
    returned a code, login.do answered 302 - but chkLogin.do then said "fail".
    Re-adding that path would burn another debugging session.
    ponytail: source-level check because the real flow needs a live Samsung
    session; promote to a recorded-HTTP test if this ever gains more steps.
    """
    import pathlib
    root = pathlib.Path(__file__).with_name("custom_components") / "smartthings_find"
    utils = (root / "utils.py").read_text(encoding="utf-8")
    init = (root / "__init__.py").read_text(encoding="utf-8")

    assert "async def _web_login" not in utils, \
        "the headless mint is dead - authorize rejects redirect_uri (400)"
    assert "getState.do" not in utils and "login.do" not in utils, \
        "leftovers of the mint flow must go, they cannot work"

    apply = utils.split("def _web_apply_cookie", 1)[1].split("\nasync def ", 1)[0]
    assert "update_cookies" in apply, "the cookie must reach the aiohttp jar"
    assert "URL(URL_STF)" in apply, "the cookie is scoped to the STF host"
    # The value carries a Tomcat jvmRoute (".fmm-prd-cns-1") pinning it to a
    # cluster node. Splitting on "." would silently break node affinity.
    assert ".split(" not in apply, "the JSESSIONID must be passed verbatim"

    # The 30 min idle timeout is only survivable if something touches the
    # session regularly - that is the coordinator's poll.
    assert "_web_ensure_session" in init, \
        "coordinator must keep the web session alive, it cannot be re-minted"


# --- checks ------------------------------------------------------------------

def main():
    mapping = web_device_ids(WEB_DEVICE_LIST)
    assert len(mapping) == 6, mapping

    # Double-escaped names must resolve, or earbuds/phone can never be rung.
    assert "Alex's Buds3 Pro" in mapping, sorted(mapping)
    assert mapping["Alex's Buds3 Pro"] == "100000001"

    # Every device the integration creates must map to a web id.
    unmatched = []
    for device in SMARTTHINGS_DEVICES:
        name = device_name(device)
        assert name, device
        if name not in mapping:
            unmatched.append(name)
    assert not unmatched, f"no web id for: {unmatched}"

    # Non-ASCII names must survive untouched.
    assert mapping["Schlüssel"] == "100000004"

    # Payload shape: exactly the four fields the web frontend sends for a tag or
    # earbuds (it only adds lockMessage for phone/tablet/watch).
    payload = ring_payload("100000001", "abcde12345", True)
    assert set(payload) == {"dvceId", "operation", "usrId", "status"}, payload
    assert payload["operation"] == "RING"
    assert payload["status"] == "start"
    assert ring_payload("1", "u", False)["status"] == "stop"

    check_web_session_is_borrowed_not_minted()

    print(f"OK - {len(SMARTTHINGS_DEVICES)}/{len(SMARTTHINGS_DEVICES)} devices mapped to web ids")
    for device in SMARTTHINGS_DEVICES:
        name = device_name(device)
        print(f"   {name:22} [{device['locationType']:7}] -> {mapping[name]}")


if __name__ == "__main__":
    main()
