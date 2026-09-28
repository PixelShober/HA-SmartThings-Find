# SmartThings Find Integration for Home Assistant (OAuth Fork)

This is a fork of the original repository by [tomskra](https://github.com/tomskra/HA-SmartThings-Find) (and [Vedeneb](https://github.com/Vedeneb/HA-SmartThings-Find)). This version replaces the unstable JSESSIONID authentication with a robust OAuth 2.0 flow using PKCE, ensuring persistent connections and automatic token refreshing.

# SmartThings Find Integration for Home Assistant

This integration adds support for devices from Samsung SmartThings Find. While intended mainly for Samsung SmartTags, it also works with other devices, such as phones, tablets, watches and earbuds.

Currently the integration creates these entities:
* `device_tracker`: Shows the location of the tag (trackers only).
* `sensor`: Represents the battery level of the tag (trackers only).
* `switch` (`… Ring`): Ring on / off for **all** device types — SmartTags, phones,
  tablets, watches and earbuds.
  * Phones and earbuds report their **real** ring state (on while ringing, off once
    they stop, also when rung from the app or the website).
  * Tags cannot report back, so their switch means "ring request accepted" and turns
    itself off (with a stop command) after 200 s. Switching it off stops the tag.
  * Attributes: `ring_status` (`idle`, `pending`, `ringing`, `requested`, `error_*`),
    `ring_message` (the text the SmartThings Find website shows, in German) and the
    raw operation codes.

### How ringing works

| Device | Path | Setup |
|---|---|---|
| SmartTags | SmartThings installed-app proxy, `PUT /trackerapi` `/trackers/<id>/ring` (same as the SmartThings app) | none |
| Phones, tablets, watches, earbuds | `smartthingsfind.samsung.com` web frontend, `dm/addOperation.do` | a web session cookie (see below) |

The tracker API cannot ring anything but tags, and the web session it would take to
ring phones cannot be created from the OAuth login (Samsung's server-side policy for
the web client forbids it). Tags deliberately use the tracker API: a tag rung via
the website **cannot be stopped again**, one rung via the tracker API can. The web
API is only a fallback for tags.

All details, measurements and dead ends are documented (in German) in [RING.md](RING.md).

This integration does **not** allow you to perform actions based on button presses on the SmartTag! There are other ways to do that.


## ⚠️ Warning/Disclaimer ⚠️

- **API Limitations**: Created by reverse engineering the SmartThings Find API, this integration might stop working at any time if changes occur on the SmartThings side.
- **Limited Testing**: The integration hasn't been thoroughly tested. If you encounter issues, please report them by creating an issue.
- **Feature Constraints**: The integration can only support features available on the [SmartThings Find website](https://smartthingsfind.samsung.com/) and the SmartThings tracker API. Tags never report whether they are ringing, so their switch shows the accepted request, not the actual sound.

## Notes on authentication
This integration now uses a standard OAuth 2.0 flow with PKCE to authenticate with Samsung servers. This mirrors the authentication used by official Samsung apps, providing a persistent session that automatically refreshes. You no longer need to worry about manually re-authenticating or sessions expiring unexpectedly.

## Notes on connection to the devices
Being able to let a SmartTag ring depends on a Galaxy phone/tablet nearby which forwards your request via Bluetooth. If no such device is near your tag, the request is accepted but nothing rings until one comes close. The location should still update if any Galaxy device is nearby.

If ringing your tag does not work, try it from the SmartThings **app** — Home Assistant uses the same tracker API for tags. The website uses a different path that cannot stop a ringing tag again.

## Web session for phones and earbuds

Ringing phones, tablets, watches and earbuds needs a session of the SmartThings Find website. It cannot be created automatically, so it is handed over once:

1. Log in at <https://smartthingsfind.samsung.com> in a browser.
2. F12 → **Application** → **Cookies** → `https://smartthingsfind.samsung.com` → copy the value of `JSESSIONID`.
   If there are two, take the one **with** a suffix like `….fmm-prd-cns-1` and keep the value unchanged.
3. Home Assistant: **Settings → Devices & services → SmartThings Find → Configure**, paste it into the *JSESSIONID* field.

The integration keeps the session alive on every poll. Samsung still ends it eventually (password change, logout, server side limits). When that happens, a notification `smartthings_find_web_session` appears (usable as an automation trigger) and disappears once a valid session is back. Tags keep ringing without it.

### Optional: login bot

[`bot/`](bot/) contains a small bot that logs in with a real browser (patchright/Chromium on a virtual display, since headless triggers reCAPTCHA) and pushes a fresh session into Home Assistant through the options flow. It runs hourly via systemd and only logs in when the last session is dead.

- Credentials: `~/.config/stf-bot/credentials` of the bot user, `chmod 600` (the bot refuses otherwise), with `STF_EMAIL`, `STF_PASSWORD`, `HA_URL`, `HA_TOKEN` (a long-lived access token of an admin user).
- Several Home Assistant instances: comma-separated `HA_URL` and `HA_TOKEN` in the same order.
- Failures show up as notification `smartthings_find_login_bot`. After a failed login it waits 6 h to avoid locking the Samsung account.
- Wrong tokens make Home Assistant ban the bot's IP (`ip_ban`, then every request gets 403). Remove the entry from `ip_bans.yaml` and restart.

Setup notes (in German) are in [RING.md](RING.md#automatisch-erneuern-login-bot-seit-2026-09-25).

## Notes on active/passive mode

Starting with version 0.2.0, it is possible to configure whether to use the integration in an active or passive mode. In passive mode the integration only fetches the location from the server which was last reported to STF. In active mode the integration sends an actual "request location update" request. This will make the STF server try to connect to e.g. your phone, get the current location and send it back to the STF server from where the integration can then read it. This has quite a big impact on the devices battery and in some cases might also wake up the screen of the phone or tablet.

By default active mode is enabled for SmartTags but disabled for any other devices. You can change this behaviour on the integrations page by clicking on `Configure`. Here you can also set the update interval, which is set to 120 seconds by default.


## Installation Instructions

### Using HACS

1. Add this repository as a custom repository in HACS. Either by manually adding `https://github.com/PixelShober/HA-SmartThings-Find` with category `integration` or simply click the following button:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=PixelShober&repository=HA-SmartThings-Find&category=integration)

2. Search for "SmartThings Find" in HACS and install the integration
3. Restart Home Assistant
4. Proceed to [Setup instructions](#setup-instructions)

### Manual install

1. Download the `custom_components/smartthings_find` directory to your Home Assistant configuration directory
2. Restart Home Assistant
3. Proceed to [Setup instructions](#setup-instructions)

## Setup Instructions

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=smartthings_find)

1. Go to the Integrations page  
2. Search for "SmartThings Find" (**do not confuse this with the built-in SmartThings integration!**)  
3. Follow the on-screen configuration wizard:
   - **Login**: Click the provided link to log in to your Samsung account.
   - **Redirect**: After logging in, the browser will try to open a `ms-app://...` link. Cancel the external app prompt if it appears.
   - **Copy URL**: Use Developer Tools (F12) and copy the full `ms-app://...` URL from Network or Console (not the visible error page URL).
   - **Paste**: Paste the copied URL back into the Home Assistant dialog.
4. The integration will verify the token and load your devices.

## Debugging

To enable debugging, you need to set the log level in `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.smartthings_find: debug
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests to help improve this integration.

## Support

For support, please create an issue on the GitHub repository.

## Roadmap

- No roadmap, unfortunately, I don't have time for adding features

## Disclaimer

This is a third-party integration and is not affiliated with or endorsed by Samsung or SmartThings.

## Credits

- **[tomskra](https://github.com/tomskra)** and **[Vedeneb](https://github.com/Vedeneb)** for the original integration work.
- **[KieronQuinn](https://github.com/KieronQuinn)** for the [uTag](https://github.com/KieronQuinn/uTag) project and documenting the authentication protocol.
