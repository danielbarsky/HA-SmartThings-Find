# ⚠️ Fork: persistent authentication ⚠️

This fork removes the recurring "paste a new JSESSIONID every few days" chore and
fixes the reauth/reconfigure flows. See [Notes on authentication](#notes-on-authentication).

> Upstream note from the original author, who archived the project: *"Unfortunately,
> I no longer have the time to maintain this repository. I underestimated how much
> work it would be. Additionally, my focus recently has shifted away from HA (and
> programming in general) towards other things. I sincerely hope someone else can
> take over and build a solid, reliable integration from what's already here."*

# SmartThings Find Integration for Home Assistant

This integration adds support for devices from Samsung SmartThings Find. While intended mainly for Samsung SmartTags, it also works with other devices, such as phones, tablets, watches and earbuds.

Currently the integration creates three entities for each device:
* `device_tracker`: Shows the location of the tag/device.
* `sensor`: Represents the battery level of the tag/device (not supported for earbuds!)
* `button`: Allows you to ring the tag/device.

![screenshot](media/screenshot_1.png)

This integration does **not** allow you to perform actions based on button presses on the SmartTag! There are other ways to do that.


## ⚠️ Warning/Disclaimer ⚠️

- **API Limitations**: Created by reverse engineering the SmartThings Find API, this integration might stop working at any time if changes occur on the SmartThings side.
- **Limited Testing**: The integration hasn't been thoroughly tested. If you encounter issues, please report them by creating an issue.
- **Feature Constraints**: The integration can only support features available on the [SmartThings Find website](https://smartthingsfind.samsung.com/). For instance, stopping a SmartTag from ringing is not possible due to API limitations (while other devices do support this; not yet implemented)

## Notes on authentication

Earlier versions stored only the `JSESSIONID` cookie from the SmartThings Find
website. That cookie is the bottom layer of Samsung's authentication chain and
expires after a few days, and because nothing else was stored there was no way
to recover - so you had to open a browser and paste a new cookie by hand.

This fork signs in to your Samsung Account once and stores the master token that
the sign-in produces. When the web session expires, the integration mints a new
one from that token by itself:

1. interactive Samsung Account sign-in &rarr; master `userauth_token`
2. master token &rarr; short-lived web-Find authorization code
3. `getState.do` &rarr; server-issued login state
4. `login.do` &rarr; a fresh `JSESSIONID`

The renewal happens in the background, so an expired cookie is no longer
something you see. Home Assistant only asks you to sign in again if the master
token itself stops working - after an account sign-out, a password change, or a
server-side revocation.

Two other authentication bugs are fixed here:

- **Reauth and reconfigure used to fail.** Both called `async_create_entry`,
  which Home Assistant 2025.11 turned into a hard error inside those flows, so
  the only way to recover was to delete the integration and add it again. They
  now update the existing entry.
- **The session cookie was sent to every host.** It was registered without a
  URL, which files it in aiohttp's domain-less "shared cookie" bucket, on the
  Home Assistant-wide shared session. The integration now uses its own session
  and scopes the cookie to `smartthingsfind.samsung.com`.

### A note on the master token

The master token is a primary credential: it can mint new sessions for your
Samsung Account. It is stored in Home Assistant's config entry storage
(`.storage/core.config_entries`, the same place every other integration keeps
its credentials) and is never written to the log. Treat a backup of that file as
you would your Samsung password.

Protocol details follow the reverse engineering published by
[KieronQuinn/uTag](https://github.com/KieronQuinn/uTag/wiki/Authentication) and
[charlesbel/samsung-re-find](https://github.com/charlesbel/samsung-re-find) (MIT),
and the OAuth login rework in
[PixelShober/HA-SmartThings-Find](https://github.com/PixelShober/HA-SmartThings-Find).

## Notes on connection to the devices
Being able to let a SmartTag ring depends on a phone/tablet nearby which forwards your request via Bluetooth. If your phone is not near your tag, you can't make it ring. The location should still update if any Galaxy device is nearby. 

If ringing your tag does not work, first try to let it ring from the [SmartThings Find website](https://smartthingsfind.samsung.com/). If it does not work from there, it can not work from Home Assistant too! Note that letting it ring with the SmartThings Mobile App is not the same as the website. Just because it does work in the App, does not mean it works on the web. So always use the web version to do your tests.

## Notes on active/passive mode

Starting with version 0.2.0, it is possible to configure whether to use the integration in an active or passive mode. In passive mode the integration only fetches the location from the server which was last reported to STF. In active mode the integration sends an actual "request location update" request. This will make the STF server try to connect to e.g. your phone, get the current location and send it back to the STF server from where the integration can then read it. This has quite a big impact on the devices battery and in some cases might also wake up the screen of the phone or tablet.

By default active mode is enabled for SmartTags but disabled for any other devices. You can change this behaviour on the integrations page by clicking on `Configure`. Here you can also set the update interval, which is set to 120 seconds by default.


## Installation Instructions

### Using HACS

1. Add this repository as a custom repository in HACS. Either by manually adding `https://github.com/tomskra/HA-SmartThings-Find` with category `integration` or simply click the following button:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=tomskra&repository=HA-SmartThings-Find&category=integration)

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
2. Search for "SmartThings *Find*" (**do not confuse this with the built-in SmartThings integration!**)
3. Open the sign-in link the dialog gives you and log in to your Samsung Account.
4. Your browser will then try to open an `ms-app://...` address. It will show an
   error page, or ask to open an external app - that is expected, because the
   address belongs to Samsung's own app. Cancel any app prompt and leave the tab
   open.
5. Open your browser's developer tools (F12), go to **Network** or **Console**,
   and copy the full address starting with `ms-app://`. Copy that address itself,
   not the address of the visible error page.
6. Paste it back into the Home Assistant dialog.
7. Wait a few seconds for the integration to be ready.

You only do this once. From then on the integration renews its own sessions.

### Upgrading from an older version

Existing entries keep working on their current cookie and log a warning that
they cannot renew it yet. To enable automatic renewal, press **Reconfigure** on
the integration and complete the sign-in above. Your devices, entity IDs and
history are preserved.

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
