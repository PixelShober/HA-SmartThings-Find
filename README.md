# SmartThings Find Integration for Home Assistant (OAuth Fork)

This is a fork of the original repository by [tomskra](https://github.com/tomskra/HA-SmartThings-Find) (and [Vedeneb](https://github.com/Vedeneb/HA-SmartThings-Find)). This version replaces the unstable JSESSIONID authentication with a robust OAuth 2.0 flow using PKCE, ensuring persistent connections and automatic token refreshing.

# SmartThings Find Integration for Home Assistant

This integration adds support for devices from Samsung SmartThings Find. While intended mainly for Samsung SmartTags, it also works with other devices, such as phones, tablets, watches and earbuds.

Currently the integration creates these entities (trackers only):
* `device_tracker`: Shows the location of the tag/device.
* `sensor`: Represents the battery level of the tag/device (not supported for earbuds!)
* `switch`: Optimistic ring toggle (auto turns off after 120s).

This integration does **not** allow you to perform actions based on button presses on the SmartTag! There are other ways to do that.


## ⚠️ Warning/Disclaimer ⚠️

- **API Limitations**: Created by reverse engineering the SmartThings Find API, this integration might stop working at any time if changes occur on the SmartThings side.
- **Limited Testing**: The integration hasn't been thoroughly tested. If you encounter issues, please report them by creating an issue.
- **Feature Constraints**: The integration can only support features available on the [SmartThings Find website](https://smartthingsfind.samsung.com/). Ring stop is exposed for trackers, but support depends on the backend; if it fails the API will reject the command. The ring switch is optimistic because the ring status cannot be read from the OAuth API.

## Notes on authentication
This integration now uses a standard OAuth 2.0 flow with PKCE to authenticate with Samsung servers. This mirrors the authentication used by official Samsung apps, providing a persistent session that automatically refreshes. You no longer need to worry about manually re-authenticating or sessions expiring unexpectedly.

## Notes on connection to the devices
Being able to let a SmartTag ring depends on a phone/tablet nearby which forwards your request via Bluetooth. If your phone is not near your tag, you can't make it ring. The location should still update if any Galaxy device is nearby. 

If ringing your tag does not work, first try to let it ring from the [SmartThings Find website](https://smartthingsfind.samsung.com/). If it does not work from there, it can not work from Home Assistant too! Note that letting it ring with the SmartThings Mobile App is not the same as the website. Just because it does work in the App, does not mean it works on the web. So always use the web version to do your tests.

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
