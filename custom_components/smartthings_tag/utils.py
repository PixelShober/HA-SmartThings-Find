import logging
import json
import pytz
import base64
import aiohttp
import random
import string
import html
import hashlib
import os
import secrets
import urllib.parse
import uuid
from io import BytesIO
from datetime import datetime, timedelta
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry, entity_registry

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from .const import (
    DOMAIN, BATTERY_LEVELS, CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_OTHERS,
    CLIENT_ID_AUTH, CLIENT_ID_FIND, CLIENT_ID_ONECONNECT, SCOPE_AUTH, SCOPE_FIND,
    CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN, CONF_AUTH_SERVER_URL, CONF_USER_ID,
    CONF_IOT_ACCESS_TOKEN, CONF_IOT_REFRESH_TOKEN, CONF_DEVICE_ID,
    CONF_INSTALLED_APP_ID, CONF_ST_USER_UUID
)

_LOGGER = logging.getLogger(__name__)

URL_ENTRY_POINT = 'https://account.samsung.com/accounts/ANDROIDSDK/getEntryPoint'
SMARTTHINGS_APP_VERSION = "1.8.21.28"
SMARTTHINGS_DEVICE_MODEL = "Google Pixel 8 Pro"
SMARTTHINGS_OS = "Android 14"
SMARTTHINGS_USER_AGENT = (
    f"Android/OneApp/{SMARTTHINGS_APP_VERSION}/Main "
    f"({SMARTTHINGS_DEVICE_MODEL}; Android 14/14) SmartKit/4.423.1"
)


def get_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def _html_unescape(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    current = value
    for _ in range(3):
        decoded = html.unescape(current)
        if decoded == current:
            break
        current = decoded
    return current


def format_ring_error(err: str | None) -> str:
    if not err:
        return "Ring failed"
    if err == "unsupported_device":
        return "Ring not supported for this device."
    if err.startswith("app_error_"):
        return f"Ring failed: {err}"
    if err.startswith("http_"):
        return f"Ring failed: {err}"
    return f"Ring failed: {err}"

def _sync_entity_names(hass: HomeAssistant, device_id: str, name: str) -> None:
    if not device_id or not name:
        return
    registry = entity_registry.async_get(hass)
    unique_ids = (
        ("device_tracker", f"stf_device_tracker_{device_id}"),
        ("sensor", f"stf_device_battery_{device_id}"),
        ("switch", f"stf_ring_switch_{device_id}"),
        ("button", f"stf_ring_button_{device_id}"),
        ("button", f"stf_ring_stop_button_{device_id}"),
    )
    for domain, unique_id in unique_ids:
        entity_id = registry.async_get_entity_id(domain, DOMAIN, unique_id)
        if not entity_id:
            continue
        entry = registry.async_get(entity_id)
        if not entry or entry.name:
            continue
        original = entry.original_name or ""
        if not original or original == name:
            continue
        if _html_unescape(original) != name:
            continue
        registry.async_update_entity(entity_id, original_name=name)


def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')


def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')


def _get_auth_data(hass: HomeAssistant) -> dict:
    return hass.data.setdefault(DOMAIN, {}).setdefault("auth_data", {})


def _get_or_create_device_id(hass: HomeAssistant) -> str:
    auth_data = _get_auth_data(hass)
    device_id = auth_data.get("device_id")
    if not device_id:
        device_id = secrets.token_hex(16)
        auth_data["device_id"] = device_id
    return device_id


def _decrypt_auth_value(value: str, key: str) -> str | None:
    try:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b"\0")
        else:
            key_bytes = key_bytes[:16]
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(bytes.fromhex(value)) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode("utf-8")
    except Exception as exc:
        _LOGGER.debug("Failed to decrypt auth value: %s", exc)
        return None


def _country_to_iso3(country: str | None) -> str:
    if not country:
        return "USA"
    country = country.upper()
    if len(country) == 3:
        return country
    if len(country) != 2:
        return country
    try:
        import pycountry  # type: ignore
        entry = pycountry.countries.get(alpha_2=country)
        if entry and entry.alpha_3:
            return entry.alpha_3
    except Exception:
        pass
    fallback = {
        "US": "USA",
        "DE": "DEU",
        "GB": "GBR",
        "UK": "GBR",
        "AT": "AUT",
        "CH": "CHE",
        "NL": "NLD",
        "FR": "FRA",
        "ES": "ESP",
        "IT": "ITA",
        "PL": "POL",
    }
    return fallback.get(country, country)


def _get_find_headers(hass: HomeAssistant, entry_id: str) -> dict[str, str]:
    data_store = hass.data[DOMAIN][entry_id]
    auth_server_url = str(data_store.get(CONF_AUTH_SERVER_URL, ""))
    if auth_server_url.startswith("https://"):
        auth_server_url = auth_server_url[len("https://"):]
    elif auth_server_url.startswith("http://"):
        auth_server_url = auth_server_url[len("http://"):]
    return {
        "X-Sec-Sa-Userid": str(data_store.get(CONF_USER_ID, "")),
        "X-Sec-Sa-Countrycode": _country_to_iso3(hass.config.country),
        "X-Sec-Sa-Authserverurl": auth_server_url,
        "X-Sec-Sa-Authtoken": str(data_store.get(CONF_ACCESS_TOKEN, "")),
        "Accept": "application/json",
    }


def _get_timezone_offset() -> str:
    offset = datetime.now().astimezone().utcoffset()
    if offset is None:
        return "UTC+00:00"
    total_minutes = int(offset.total_seconds() / 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    hours, minutes = divmod(total_minutes, 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def _get_accept_language(hass: HomeAssistant) -> str:
    language = getattr(hass.config, "language", None) or "en"
    country = getattr(hass.config, "country", None)
    if country:
        return f"{language}-{country}"
    return language


def _get_smartthings_headers(hass: HomeAssistant, entry_id: str) -> dict[str, str]:
    data_store = hass.data[DOMAIN][entry_id]
    token = data_store.get(CONF_IOT_ACCESS_TOKEN)
    correlation_id = data_store.get("correlation_id")
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
        data_store["correlation_id"] = correlation_id
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.smartthings+json;v=1",
        "Accept-Language": _get_accept_language(hass),
        "User-Agent": SMARTTHINGS_USER_AGENT,
        "X-St-Client-Appversion": SMARTTHINGS_APP_VERSION,
        "X-St-Client-Devicemodel": SMARTTHINGS_DEVICE_MODEL,
        "X-St-Client-Os": SMARTTHINGS_OS,
        "X-St-Correlation": correlation_id,
    }
    return headers


async def _smartthings_get_json(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    url: str
) -> tuple[int, dict | None]:
    headers = _get_smartthings_headers(hass, entry_id)
    async with session.get(url, headers=headers) as res:
        if res.status in [401, 403]:
            await refresh_iot_token(hass, session, entry_id)
            headers = _get_smartthings_headers(hass, entry_id)
            async with session.get(url, headers=headers) as retry_res:
                return retry_res.status, await retry_res.json()
        return res.status, await res.json()


async def _ensure_smartthings_user_info(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str
) -> tuple[str | None, str | None]:
    data_store = hass.data[DOMAIN][entry_id]
    if data_store.get(CONF_ST_USER_UUID):
        return data_store.get(CONF_ST_USER_UUID), data_store.get("st_country_code")

    status, data = await _smartthings_get_json(
        hass,
        session,
        entry_id,
        "https://auth.api.smartthings.com/users/me"
    )
    if status != 200 or not data:
        _LOGGER.error("Failed to fetch SmartThings user info: %s", data)
        return None, None

    user_uuid = data.get("uuid")
    country_code = data.get("countryCode")
    data_store[CONF_ST_USER_UUID] = user_uuid
    if country_code:
        data_store["st_country_code"] = country_code

    entry = hass.config_entries.async_get_entry(entry_id)
    if entry:
        new_data = entry.data.copy()
        new_data[CONF_ST_USER_UUID] = user_uuid
        hass.config_entries.async_update_entry(entry, data=new_data)

    return user_uuid, country_code


async def _get_installed_app_id(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str
) -> str | None:
    data_store = hass.data[DOMAIN][entry_id]
    cached = data_store.get(CONF_INSTALLED_APP_ID)
    if cached:
        return cached

    user_uuid, _ = await _ensure_smartthings_user_info(hass, session, entry_id)
    if not user_uuid:
        return None

    url = "https://api.smartthings.com/installedapps?allowed=true"
    all_items = []
    while url:
        status, data = await _smartthings_get_json(hass, session, entry_id, url)
        if status != 200 or not data:
            _LOGGER.error("Failed to fetch installed apps: %s", data)
            return None
        items = data.get("items", [])
        all_items.extend(items)
        url = (data.get("_links", {}) or {}).get("next", {}) or {}
        url = url.get("href")

    plugin_id = "com.samsung.android.plugin.fme"
    app_id = None
    for item in all_items:
        ui = item.get("ui", {})
        owner = item.get("owner", {})
        if ui.get("pluginId") == plugin_id and owner.get("ownerId") == user_uuid:
            app_id = item.get("installedAppId")
            break
    if not app_id:
        for item in all_items:
            ui = item.get("ui", {})
            if ui.get("pluginId") == plugin_id:
                app_id = item.get("installedAppId")
                break

    if app_id:
        data_store[CONF_INSTALLED_APP_ID] = app_id
        entry = hass.config_entries.async_get_entry(entry_id)
        if entry:
            new_data = entry.data.copy()
            new_data[CONF_INSTALLED_APP_ID] = app_id
            hass.config_entries.async_update_entry(entry, data=new_data)

    return app_id


def _encode_base64_json(payload: dict | list | str | None) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


async def _build_installed_apps_request(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    method: str,
    uri: str,
    extra_uri: str | None = None,
    extra_params: dict | None = None,
    headers: dict | None = None,
    body: dict | None = None
) -> dict | None:
    data_store = hass.data[DOMAIN][entry_id]
    device_id = data_store.get(CONF_DEVICE_ID) or _get_or_create_device_id(hass)
    data_store[CONF_DEVICE_ID] = device_id
    token = data_store.get(CONF_IOT_ACCESS_TOKEN)
    user_id = data_store.get(CONF_USER_ID)
    if not user_id:
        return None

    request_body = {
        "client": {
            "displayMode": "LIGHT",
            "language": _get_accept_language(hass),
            "mobileDeviceId": device_id,
            "os": "Android",
            "samsungAccountId": data_store.get(CONF_USER_ID),
            "supportedTemplates": [
                "BASIC_V1", "BASIC_V2", "BASIC_V3", "BASIC_V4",
                "BASIC_V5", "BASIC_V6", "BASIC_V7"
            ],
            "timeZoneOffset": _get_timezone_offset(),
            "version": SMARTTHINGS_APP_VERSION
        },
        "parameters": {
            "requester": user_id,
            "requesterToken": token,
            "clientType": "aPlugin",
            "clientVersion": "1",
            "method": method,
            "uri": uri,
            "extraUri": extra_uri,
            "encodedHeaders": _encode_base64_json(headers),
            "encodedBody": _encode_base64_json(body),
        }
    }

    if extra_params:
        request_body["parameters"].update(extra_params)

    return request_body


async def _execute_installed_app(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    method: str,
    uri: str,
    extra_uri: str | None = None,
    extra_params: dict | None = None,
    headers: dict | None = None,
    body: dict | None = None
) -> tuple[int, dict | None]:
    app_id = await _get_installed_app_id(hass, session, entry_id)
    if not app_id:
        return 500, {"error": "missing_installed_app_id"}

    request_body = await _build_installed_apps_request(
        hass,
        session,
        entry_id,
        method,
        uri,
        extra_uri=extra_uri,
        extra_params=extra_params,
        headers=headers,
        body=body
    )
    if request_body is None:
        return 500, {"error": "missing_user_info"}

    exec_url = f"https://api.smartthings.com/installedapps/{app_id}/execute"

    st_headers = _get_smartthings_headers(hass, entry_id)
    st_headers["Content-Type"] = "application/json"

    async with session.post(exec_url, json=request_body, headers=st_headers) as res:
        if res.status in [401, 403]:
            await refresh_iot_token(hass, session, entry_id)
            request_body = await _build_installed_apps_request(
                hass,
                session,
                entry_id,
                method,
                uri,
                extra_uri=extra_uri,
                extra_params=extra_params,
                headers=headers,
                body=body
            )
            st_headers = _get_smartthings_headers(hass, entry_id)
            st_headers["Content-Type"] = "application/json"
            async with session.post(exec_url, json=request_body, headers=st_headers) as retry_res:
                return retry_res.status, await retry_res.json()
        return res.status, await res.json()


def _parse_installed_apps_response(response: dict | None) -> tuple[int | None, dict | None, str | None]:
    if not response:
        return None, None, "empty_response"
    status_code = response.get("statusCode")
    message = response.get("message")
    error_code = response.get("errorCode")
    return status_code, message, error_code


def encrypt_svc_param(svc_param_json, chk_do_num, public_key):
    chk_do_num_str = str(chk_do_num)
    chk_do_num_hash = hashlib.sha256(chk_do_num_str.encode('utf-8')).digest()

    key = os.urandom(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        base64.b64encode(chk_do_num_hash),
        key,
        chk_do_num,
        dklen=16,
    )

    svc_enc_ky = public_key.encrypt(
        base64.b64encode(derived_key),
        asym_padding.PKCS1v15()
    )
    svc_enc_ky_b64 = base64.b64encode(svc_enc_ky).decode('utf-8')

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(svc_param_json.encode('utf-8')) + padder.finalize()
    
    svc_enc_param = encryptor.update(padded_data) + encryptor.finalize()
    svc_enc_param_b64 = base64.b64encode(svc_enc_param).decode('utf-8')

    payload_dict = {
        "chkDoNum": chk_do_num_str,
        "svcEncParam": svc_enc_param_b64,
        "svcEncKY": svc_enc_ky_b64,
        "svcEncIV": iv.hex(),
    }
    payload_json = json.dumps(payload_dict)
    payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
    return urllib.parse.quote(payload_b64)


async def do_login_stage_one(hass: HomeAssistant) -> tuple:
    session = async_get_clientsession(hass)
    
    # 1. Get Entry Point
    async with session.get(URL_ENTRY_POINT) as res:
        if res.status != 200:
            return None, "Failed to get entry point"
        data = await res.json()
        
    sign_in_uri = data['signInURI']
    pki_public_key = data['pkiPublicKey']
    chk_do_num = int(data['chkDoNum'])

    # 2. Generate SVC Param
    state = get_random_string(20)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    auth_data = _get_auth_data(hass)
    device_id = _get_or_create_device_id(hass)
    auth_data.update({
        "state": state,
        "code_verifier": code_verifier
    })
    if _LOGGER.isEnabledFor(logging.DEBUG):
        _LOGGER.debug(
            "Auth debug: state=%s code_verifier=%s device_id=%s",
            state,
            code_verifier,
            device_id
        )

    svc_param = {
        "clientId": CLIENT_ID_AUTH,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "competitorDeviceYNFlag": "Y",
        "countryCode": (hass.config.country or "us").lower(),
        "deviceInfo": "Google|com.android.chrome",
        "deviceModelID": "Pixel 8 Pro",
        "deviceName": "Google Pixel 8 Pro",
        "deviceOSVersion": "35",
        "devicePhysicalAddressText": f"ANID:{device_id}",
        "deviceType": "APP",
        "deviceUniqueID": device_id,
        "redirect_uri": "ms-app://s-1-15-2-4027708247-2189610-1983755848-2937435718-1578786913-2158692839-1974417358",
        "replaceableClientConnectYN": "N",
        "replaceableClientId": "",
        "replaceableDevicePhysicalAddressText": "",
        "responseEncryptionType": "1",
        "responseEncryptionYNFlag": "Y",
        "scope": "",
        "state": state,
        "svcIptLgnID": "",
        "iosYNFlag": "Y",
    }
    
    svc_param_json = json.dumps(svc_param)
    
    # 3. Encrypt Payload
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        pub_key_bytes = base64.b64decode(pki_public_key)
        try:
            public_key = load_der_public_key(pub_key_bytes, backend=default_backend())
        except:
             # Fallback usually not needed if standard DER
             from cryptography.hazmat.primitives.serialization import load_pem_public_key
             pass
        
        if 'public_key' not in locals():
             raise Exception("Failed to load public key")
        
        svc_param_value = encrypt_svc_param(svc_param_json, chk_do_num, public_key)

    except Exception as e:
        _LOGGER.error(f"Encryption failed: {e}")
        return None, f"Encryption failed: {e}"

    login_url = f"{sign_in_uri}?locale=en&svcParam={svc_param_value}&mode=C"

    _LOGGER.info(f"Generated Login URL: {login_url}")
    
    return login_url, None



async def do_login_stage_two(
    hass: HomeAssistant,
    redirect_url: str
) -> tuple[dict | None, dict | None, str | None, str | None, str | None]:
    session = async_get_clientsession(hass)
    auth_data = hass.data.get(DOMAIN, {}).get('auth_data')
    if not auth_data:
        return None, None, None, None, "Auth data missing. Please restart flow."
    
    state_orig = auth_data['state']
    code_verifier = auth_data['code_verifier']
    device_id = auth_data.get("device_id") or _get_or_create_device_id(hass)

    # Parse parameters from redirect URL
    import urllib.parse
    parsed = urllib.parse.urlparse(redirect_url)
    params = urllib.parse.parse_qs(parsed.query)
    if parsed.fragment:
        params.update(urllib.parse.parse_qs(parsed.fragment))
    
    # Parameters needed: code, auth_server_url
    auth_server_url = params.get('auth_server_url', [''])[0]
    code = params.get('code', [''])[0]
    state_param = params.get('state', [''])[0]
    ret_value = params.get('retValue', [''])[0]
    
    if state_param:
        decrypted_state = _decrypt_auth_value(state_param, state_orig)
        if decrypted_state:
            auth_server_url = _decrypt_auth_value(auth_server_url, decrypted_state) or auth_server_url
            code = _decrypt_auth_value(code, decrypted_state) or code
            ret_value = _decrypt_auth_value(ret_value, decrypted_state) or ret_value

    if auth_server_url and not auth_server_url.startswith("http"):
        auth_server_url = f"https://{auth_server_url}"

    if not auth_server_url or not code:
        return None, None, None, None, "Missing auth_server_url or code in redirect URL"

    if not ret_value:
        return None, None, None, None, "Missing username in redirect URL"
    
    async with session.post(
        f"{auth_server_url}/auth/oauth2/authenticate",
        data={
            "grant_type": "authorization_code",
            "serviceType": "M",
            "client_id": CLIENT_ID_AUTH,
            "code": code,
            "code_verifier": code_verifier,
            "username": ret_value,
            "physical_address_text": device_id,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    ) as res:
        if res.status != 200:
             return None, None, None, None, f"Token exchange failed: {await res.text()}"
        data = await res.json()
    
    user_auth_token = data.get('userauth_token') or data.get('userAuthToken')
    user_id = data.get('userId') or data.get('user_id')
    login_id = data.get('loginId') or data.get('login_id') or ret_value
    if not user_auth_token or not user_id:
        return None, None, None, None, "Authenticate response missing user token or user id"

    async def _authorize_and_token(
        client_id: str,
        scope: str
    ) -> tuple[dict | None, str | None]:
        new_verifier = generate_code_verifier()
        new_challenge = generate_code_challenge(new_verifier)

        params_auth = {
            "response_type": "code",
            "client_id": client_id,
            "scope": scope,
            "code_challenge": new_challenge,
            "code_challenge_method": "S256",
            "userauth_token": user_auth_token,
            "serviceType": "M",
            "childAccountSupported": "Y",
            "physical_address_text": device_id,
            "login_id": login_id,
        }

        async with session.get(
            f"{auth_server_url}/auth/oauth2/v2/authorize",
            params=params_auth
        ) as res:
            if res.status != 200:
                 return None, f"Authorize failed: {await res.text()}"
            auth_data = await res.json()

        auth_code = auth_data.get('code')
        if not auth_code and auth_data.get('privacyAccepted') == "N" and params_auth.get("login_id"):
            params_auth.pop("login_id", None)
            async with session.get(
                f"{auth_server_url}/auth/oauth2/v2/authorize",
                params=params_auth
            ) as res:
                if res.status != 200:
                     return None, f"Authorize failed: {await res.text()}"
                auth_data = await res.json()
            auth_code = auth_data.get('code')

        if not auth_code:
            return None, "Authorize response missing code"

        async with session.post(
            f"{auth_server_url}/auth/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code,
                "code_verifier": new_verifier,
                "physical_address_text": device_id,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ) as res:
            if res.status != 200:
                 return None, f"Token exchange failed: {await res.text()}"
            token_data = await res.json()

        return token_data, None
    
    find_token, err = await _authorize_and_token(CLIENT_ID_FIND, SCOPE_FIND)
    if not find_token:
        return None, None, None, None, f"Find authorization failed: {err}"

    iot_token, err = await _authorize_and_token(CLIENT_ID_ONECONNECT, "iot.client")
    if not iot_token:
        return None, None, None, None, f"SmartThings authorization failed: {err}"

    return find_token, iot_token, user_id, auth_server_url, None




async def _refresh_token(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    refresh_token_key: str,
    access_token_key: str,
    client_id: str
) -> str:
    """Refreshes the access token using the given refresh token key."""
    data_store = hass.data[DOMAIN][entry_id]
    refresh_token = data_store.get(refresh_token_key)
    auth_server_url = data_store.get(CONF_AUTH_SERVER_URL)

    if not refresh_token or not auth_server_url:
        raise ConfigEntryAuthFailed("Refresh token or Auth URL missing")

    try:
        url = f"{auth_server_url}/auth/oauth2/token"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        async with session.post(url, data=payload, headers=headers) as res:
            if res.status != 200:
                _LOGGER.error(f"Token refresh failed: {res.status} - {await res.text()}")
                raise ConfigEntryAuthFailed("Token refresh failed")

            data = await res.json()

        new_access_token = data.get('access_token')
        new_refresh_token = data.get('refresh_token')

        if not new_access_token or not new_refresh_token:
            raise ConfigEntryAuthFailed("Invalid refresh response")

        # Update hass.data
        data_store[access_token_key] = new_access_token
        data_store[refresh_token_key] = new_refresh_token

        # Update Config Entry
        entry = hass.config_entries.async_get_entry(entry_id)
        if entry:
            new_data = entry.data.copy()
            new_data[access_token_key] = new_access_token
            new_data[refresh_token_key] = new_refresh_token
            hass.config_entries.async_update_entry(entry, data=new_data)
            _LOGGER.info("Successfully refreshed token for %s", access_token_key)
        return new_access_token

    except Exception as e:
        _LOGGER.error(f"Error refreshing token: {e}")
        raise ConfigEntryAuthFailed(f"Error refreshing token: {e}")


async def refresh_find_token(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str
) -> str:
    return await _refresh_token(
        hass,
        session,
        entry_id,
        CONF_REFRESH_TOKEN,
        CONF_ACCESS_TOKEN,
        CLIENT_ID_FIND
    )


async def refresh_iot_token(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str
) -> str:
    return await _refresh_token(
        hass,
        session,
        entry_id,
        CONF_IOT_REFRESH_TOKEN,
        CONF_IOT_ACCESS_TOKEN,
        CLIENT_ID_ONECONNECT
    )


async def authenticated_request(hass: HomeAssistant, session: aiohttp.ClientSession, entry_id: str, url: str, json_data: dict = None, data: dict = None) -> tuple[int, str]:
    """
    Helper to perform an authenticated request with automatic token refresh.
    
    Returns:
        tuple: (status_code, response_text)
    """
    headers = _get_find_headers(hass, entry_id)
    
    async def _do_req(auth_headers: dict[str, str]):
        # We prefer JSON if provided, else data (which might be empty dict for get_devices)
        if json_data is not None:
             async with session.post(url, json=json_data, headers=auth_headers) as resp:
                 return resp.status, await resp.text()
        else:
             async with session.post(url, data=data or {}, headers=auth_headers) as resp:
                 return resp.status, await resp.text()

    status, text = await _do_req(headers)
    
    if status in [401, 403]:
        _LOGGER.info(f"Request to {url.split('/')[-1]} returned {status}, refreshing token...")
        try:
            new_token = await refresh_find_token(hass, session, entry_id)
        except Exception as e:
            _LOGGER.error(f"Failed to refresh token: {e}")
            raise ConfigEntryAuthFailed("Token refresh failed")
            
        headers["X-Sec-Sa-Authtoken"] = f"{new_token}"
        status, text = await _do_req(headers)
        
        if status in [401, 403]:
             raise ConfigEntryAuthFailed(f"Auth failed after refresh: {status}")
             
    return status, text


def extract_best_location(operations: list, dev_name: str) -> tuple[dict, dict]:
    """
    Extracts the best/newest location from the list of operations.
    Returns (used_op, used_loc).
    """
    used_op = None
    used_loc = {
        "latitude": None,
        "longitude": None,
        "gps_accuracy": None,
        "gps_date": None
    }
    
    for op in operations:
        if op['oprnType'] not in ['LOCATION', 'LASTLOC', 'OFFLINE_LOC']:
            continue
            
        op_data = None
        utc_date = None
        
        # Check standard location
        if 'latitude' in op:
            if 'extra' in op and 'gpsUtcDt' in op['extra']:
                utc_date = parse_stf_date(op['extra']['gpsUtcDt'])
            else:
                 _LOGGER.warning(f"[{dev_name}] No UTC date in operation {op['oprnType']}")
                 continue
            op_data = op

        # Check encrypted/nested location
        elif 'encLocation' in op:
            loc = op['encLocation']
            if loc.get('encrypted'):
                _LOGGER.debug(f"[{dev_name}] Ignoring encrypted location")
                continue
            if 'gpsUtcDt' not in loc:
                 continue
            utc_date = parse_stf_date(loc['gpsUtcDt'])
            op_data = loc
        
        if not op_data or not utc_date:
            continue
            
        # Check if newer
        if used_loc['gps_date'] and used_loc['gps_date'] >= utc_date:
            _LOGGER.debug(f"[{dev_name}] Ignoring older location ({op['oprnType']})")
            continue
            
        # Extract coordinates
        lat = float(op_data['latitude']) if 'latitude' in op_data else None
        lon = float(op_data['longitude']) if 'longitude' in op_data else None
        
        if lat is None or lon is None:
             _LOGGER.warning(f"[{dev_name}] Missing coordinates in {op['oprnType']}")
             # If we have no coords, we preserve 'location_found'=False (implicit by None result)
             # But we might want to track accuracy/date still? 
             # The original code only set location_found=True if lat/lon existed.
             # But it accepted the OP as 'used_op' anyway?
             # "if not locFound: warn ... used_loc['gps_accuracy'] = ... used_op = op"
             # Yes, it updates date/accuracy even if lat/lon missing.
             pass
        
        used_loc['latitude'] = lat
        used_loc['longitude'] = lon
        used_loc['gps_accuracy'] = calc_gps_accuracy(
            op_data.get('horizontalUncertainty'), op_data.get('verticalUncertainty'))
        used_loc['gps_date'] = utc_date
        used_op = op

    if used_op:
        return used_op, used_loc
    return None, None
async def get_devices(hass: HomeAssistant, session: aiohttp.ClientSession, entry_id: str) -> list:
    """
    Retrieves a list of SmartThings Find devices via the SmartThings installed app API.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        session (aiohttp.ClientSession): The current session.

    Returns:
        list: A list of devices if successful, empty list otherwise.
    """
    try:
        status, response = await _execute_installed_app(
            hass,
            session,
            entry_id,
            "GET",
            "/devices"
        )
        if status != 200:
            _LOGGER.error("Failed to retrieve devices [%s]: %s", status, response)
            return []

        status_code, message, error_code = _parse_installed_apps_response(response)
        if status_code == 401 or error_code == "UnauthorizedError":
            await refresh_iot_token(hass, session, entry_id)
            status, response = await _execute_installed_app(
                hass,
                session,
                entry_id,
                "GET",
                "/devices"
            )
            if status != 200:
                _LOGGER.error("Failed to retrieve devices after refresh [%s]: %s", status, response)
                return []
            status_code, message, error_code = _parse_installed_apps_response(response)
        if status_code != 200 or message is None:
            _LOGGER.error("Device list error [%s/%s]: %s", status_code, error_code, response)
            return []

        devices_data = message.get("devices", [])

    except ConfigEntryAuthFailed:
        raise
    except Exception as e:
        _LOGGER.error(f"Error listing devices: {e}")
        return []
    devices = []
    for device in devices_data:
        device_id = (
            device.get("stDid")
            or device.get("deviceId")
            or device.get("fmmDevId")
            or device.get("id")
        )
        if not device_id:
            continue
        location_type = device.get("locationType") or device.get("deviceType") or ""
        location_type_norm = str(location_type).upper()
        is_tracker = location_type_norm == "TRACKER"
        if not is_tracker:
            continue
        name = (
            device.get("stDevName")
            or device.get("deviceName")
            or device.get("name")
            or device.get("label")
        )
        if isinstance(name, str):
            name = _html_unescape(name)
        if not name:
            if location_type:
                name = f"{location_type} {device_id}"
            else:
                name = device_id or "SmartThings Tag"
        icon_url = (
            device.get("iconUrl")
            or device.get("iconURL")
            or device.get("imageUrl")
            or device.get("imgUrl")
        )
        identifier = (DOMAIN, device_id)
        registry = device_registry.async_get(hass)
        ha_dev = registry.async_get_device({identifier})
        if ha_dev and ha_dev.disabled:
             _LOGGER.debug(
                f"Ignoring disabled device: '{name}' (disabled by {ha_dev.disabled_by})")
             continue
        if ha_dev and not ha_dev.name_by_user:
            current_name = ha_dev.name or ""
            if current_name != name and _html_unescape(current_name) == name:
                registry.async_update_device(ha_dev.id, name=name)
        _sync_entity_names(hass, device_id, name)
        name_original = name

        ha_dev_info = DeviceInfo(
            identifiers={identifier},
            manufacturer="Samsung",
            name=name,
            model=location_type or "SmartThings Tag",
            configuration_url="https://smartthingsfind.samsung.com/"
        )
        devices += [{
            "data": {
                "device_id": device_id,
                "name": name,
                "original_name": name_original,
                "icon_url": icon_url,
                "location_type": location_type,
                "is_tracker": is_tracker,
                "owner_id": device.get("stOwnerId") or device.get("ownerId"),
                "sa_guid": device.get("saGuid"),
                "fmm_device_id": device.get("fmmDevId"),
                "st_device_id": device.get("stDid") or device.get("deviceId"),
                "share_geolocation": device.get("shareGeolocation"),
                "mutual_agreement": device.get("mutualAgreement"),
                "raw_device": device,
            },
            "ha_dev_info": ha_dev_info
        }]
        _LOGGER.debug(f"Adding device: {name}")
    return devices


async def get_device_location(hass: HomeAssistant, session: aiohttp.ClientSession, dev_data: dict, entry_id: str) -> dict:
    """
    Retrieves the current location data for the specified device via the SmartThings API.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        session (aiohttp.ClientSession): The current session.
        dev_data (dict): The device information obtained from get_devices.

    Returns:
        dict: The device location data.
    """
    dev_id = dev_data.get('device_id')
    dev_name = dev_data.get('name') or dev_id or "SmartThings Tag"
    st_device_id = dev_data.get("st_device_id") or dev_id
    if not dev_data.get("is_tracker"):
        return {
            "dev_name": dev_name,
            "dev_id": dev_id,
            "update_success": True,
            "location_found": False
        }
    if not st_device_id:
        _LOGGER.error("[%s] Missing device id for location fetch", dev_name)
        return {
            "dev_name": dev_name,
            "dev_id": dev_id,
            "update_success": False,
            "location_found": False
        }

    try:
        status, response = await _execute_installed_app(
            hass,
            session,
            entry_id,
            "GET",
            "/trackers/geolocation",
            extra_params={"stDids": st_device_id}
        )

        if status != 200:
            _LOGGER.error("[%s] Failed to fetch location data: %s", dev_name, response)
            return {
                "dev_name": dev_name,
                "dev_id": dev_id,
                "update_success": False,
                "location_found": False
            }

        status_code, message, error_code = _parse_installed_apps_response(response)
        if status_code == 401 or error_code == "UnauthorizedError":
            await refresh_iot_token(hass, session, entry_id)
            status, response = await _execute_installed_app(
                hass,
                session,
                entry_id,
                "GET",
                "/trackers/geolocation",
                extra_params={"stDids": st_device_id}
            )
            if status != 200:
                _LOGGER.error("[%s] Failed to fetch location data after refresh: %s", dev_name, response)
                return {
                    "dev_name": dev_name,
                    "dev_id": dev_id,
                    "update_success": False,
                    "location_found": False
                }
            status_code, message, error_code = _parse_installed_apps_response(response)
        if status_code != 200 or message is None:
            _LOGGER.error("[%s] Location response error [%s/%s]: %s", dev_name, status_code, error_code, response)
            return {
                "dev_name": dev_name,
                "dev_id": dev_id,
                "update_success": False,
                "location_found": False
            }

        items = message.get("items", [])
        item = next(
            (
                entry for entry in items
                if entry.get("deviceId") == st_device_id
                or entry.get("stDid") == st_device_id
                or entry.get("fmmDevId") == st_device_id
            ),
            None
        )
        if not item and items:
            item = items[0]
        if not item:
            _LOGGER.warning("[%s] No location item found", dev_name)
            return {
                "dev_name": dev_name,
                "dev_id": dev_id,
                "update_success": False,
                "location_found": False
            }

        if item.get("resultCode") == 403:
            _LOGGER.warning("[%s] Location access not allowed", dev_name)
            return {
                "dev_name": dev_name,
                "dev_id": dev_id,
                "update_success": False,
                "location_found": False
            }

        geo_locations = item.get("geolocations") or item.get("geoLocations") or item.get("geoLocation") or []
        if isinstance(geo_locations, dict):
            geo_locations = [geo_locations]
        used_loc = {
            "latitude": None,
            "longitude": None,
            "gps_accuracy": None,
            "gps_date": None
        }
        battery_level = None
        if geo_locations:
            geo = geo_locations[0]
            try:
                used_loc["latitude"] = float(geo.get("latitude")) if geo.get("latitude") else None
                used_loc["longitude"] = float(geo.get("longitude")) if geo.get("longitude") else None
            except (TypeError, ValueError):
                pass
            try:
                used_loc["gps_accuracy"] = float(geo.get("accuracy")) if geo.get("accuracy") else None
            except (TypeError, ValueError):
                pass
            last_update = geo.get("lastUpdateTime") or geo.get("lastUpdateAt")
            if last_update:
                try:
                    last_update_value = int(last_update)
                except (TypeError, ValueError):
                    last_update_value = None
                if last_update_value:
                    used_loc["gps_date"] = datetime.fromtimestamp(
                        last_update_value / 1000, tz=pytz.UTC
                    )
            battery_raw = geo.get("battery")
            if battery_raw is None:
                battery_raw = geo.get("batteryLevel")
            if battery_raw is not None:
                if isinstance(battery_raw, str):
                    battery_level = BATTERY_LEVELS.get(battery_raw, None)
                    if battery_level is None:
                        try:
                            battery_level = int(battery_raw)
                        except ValueError:
                            battery_level = None
                else:
                    try:
                        battery_level = int(battery_raw)
                    except (TypeError, ValueError):
                        battery_level = None

        return {
            "dev_name": dev_name,
            "dev_id": st_device_id,
            "update_success": True,
            "location_found": used_loc["latitude"] is not None and used_loc["longitude"] is not None,
            "used_loc": used_loc,
            "battery_level": battery_level,
            "raw_item": item
        }

    except ConfigEntryAuthFailed as e:
        raise
    except Exception as e:
        _LOGGER.error(
            f"[{dev_name}] Exception occurred while fetching location data for tag '{dev_name}': {e}", exc_info=True)
    return {
        "dev_name": dev_name,
        "dev_id": dev_id,
        "update_success": False,
        "location_found": False
    }


async def _ring_command(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    device_id: str,
    command: str
) -> tuple[bool, str | None]:
    if not device_id:
        return False, "missing_device_id"

    command = (command or "").lower()
    if command not in ("start", "stop"):
        return False, "invalid_command"

    status, response = await _execute_installed_app(
        hass,
        session,
        entry_id,
        "PUT",
        "/trackerapi",
        extra_uri=f"/trackers/{device_id}/ring",
        body={"command": command}
    )

    if status != 200:
        return False, f"http_{status}: {response}"

    status_code, message, error_code = _parse_installed_apps_response(response)
    if status_code != 200:
        return False, f"app_error_{status_code}/{error_code}: {message or response}"

    return True, None


async def ring_device(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    dev_data: dict
) -> tuple[bool, str | None]:
    if dev_data.get("is_tracker"):
        device_id = dev_data.get("st_device_id") or dev_data.get("device_id")
        return await _ring_command(hass, session, entry_id, device_id, "start")
    return False, "unsupported_device"


async def stop_ring_device(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    dev_data: dict
) -> tuple[bool, str | None]:
    if dev_data.get("is_tracker"):
        device_id = dev_data.get("st_device_id") or dev_data.get("device_id")
        return await _ring_command(hass, session, entry_id, device_id, "stop")
    return False, "unsupported_device"


def calc_gps_accuracy(hu: float, vu: float) -> float:
    """
    Calculate the GPS accuracy using the Pythagorean theorem.
    Returns the combined GPS accuracy based on the horizontal
    and vertical uncertainties provided by the API

    Args:
        hu (float): Horizontal uncertainty.
        vu (float): Vertical uncertainty.

    Returns:
        float: Calculated GPS accuracy.
    """
    try:
        return round((float(hu)**2 + float(vu)**2) ** 0.5, 1)
    except ValueError:
        return None


def get_sub_location(ops: list, subDeviceName: str) -> tuple:
    """
    Extracts sub-location data for devices that contain multiple
    sub-locations (e.g., left and right earbuds).

    Args:
        ops (list): List of operations from the API.
        subDeviceName (str): Name of the sub-device.

    Returns:
        tuple: The operation and sub-location data.
    """
    if not ops or not subDeviceName or len(ops) < 1:
        return {}, {}
    for op in ops:
        if subDeviceName in op.get('encLocation', {}):
            loc = op['encLocation'][subDeviceName]
            sub_loc = {
                "latitude": float(loc['latitude']),
                "longitude": float(loc['longitude']),
                "gps_accuracy": calc_gps_accuracy(loc.get('horizontalUncertainty'), loc.get('verticalUncertainty')),
                "gps_date": parse_stf_date(loc['gpsUtcDt'])
            }
            return op, sub_loc
    return {}, {}


def parse_stf_date(datestr: str) -> datetime:
    """
    Parses a date string in the format "%Y%m%d%H%M%S" to a datetime object.
    This is the format, the SmartThings Find API uses.

    Args:
        datestr (str): The date string in the format "%Y%m%d%H%M%S".

    Returns:
        datetime: A datetime object representing the input date string.
    """
    return datetime.strptime(datestr, "%Y%m%d%H%M%S").replace(tzinfo=pytz.UTC)


def get_battery_level(dev_name: str, ops: list) -> int:
    """
    Try to extract the device battery level from the received operation

    Args:
        dev_name (str): The name of the device.
        ops (list): List of operations from the API.

    Returns:
        int: The battery level if found, None otherwise.
    """
    for op in ops:
        if op['oprnType'] == 'CHECK_CONNECTION' and 'battery' in op:
            batt_raw = op['battery']
            batt = BATTERY_LEVELS.get(batt_raw, None)
            if batt is None:
                try:
                    batt = int(batt_raw)
                except ValueError:
                    _LOGGER.warn(
                        f"[{dev_name}]: Received invalid battery level: {batt_raw}")
            return batt
    return None



