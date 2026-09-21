from datetime import timedelta
import logging
import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.const import Platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.config_entries import ConfigEntry

from .const import (
    DOMAIN,
    CONF_ACTIVE_MODE_OTHERS,
    CONF_ACTIVE_MODE_OTHERS_DEFAULT,
    CONF_ACTIVE_MODE_SMARTTAGS,
    CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT,
    CONF_UPDATE_INTERVAL,
    CONF_UPDATE_INTERVAL_DEFAULT
)
from .auth import WebSessionManager
from .utils import get_devices, get_device_location

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.DEVICE_TRACKER, Platform.BUTTON, Platform.SENSOR]

# Samsung rejects requests without a browser-ish User-Agent on some paths.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )
}


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the SmartThings Find component."""
    hass.data[DOMAIN] = {}
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up SmartThings Find from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {}

    # A session of our own, so the Samsung cookie can never ride along on
    # requests made by other integrations. Detached automatically on unload.
    session = async_create_clientsession(hass, headers=BROWSER_HEADERS)

    auth = WebSessionManager(hass, entry, session)

    active_smarttags = entry.options.get(CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT)
    active_others = entry.options.get(CONF_ACTIVE_MODE_OTHERS, CONF_ACTIVE_MODE_OTHERS_DEFAULT)

    hass.data[DOMAIN][entry.entry_id].update({
        CONF_ACTIVE_MODE_SMARTTAGS:  active_smarttags,
        CONF_ACTIVE_MODE_OTHERS: active_others,
        "auth": auth,
        "session": session,
    })

    # Raises ConfigEntryAuthFailed only if the session is dead AND cannot be
    # renewed from stored credentials, so a merely expired cookie is invisible.
    await auth.async_ensure_session()

    if not auth.can_self_renew:
        _LOGGER.warning(
            "This SmartThings Find entry predates automatic session renewal and "
            "will still expire. Reconfigure it once to sign in and enable renewal"
        )

    # Load all SmartThings-Find devices from the users account
    devices = await get_devices(hass, session, entry.entry_id)

    # Create an update coordinator. This is responsible to regularly
    # fetch data from STF and update the device_tracker and sensor
    # entities
    update_interval = entry.options.get(CONF_UPDATE_INTERVAL, CONF_UPDATE_INTERVAL_DEFAULT)
    coordinator = SmartThingsFindCoordinator(hass, session, devices, update_interval)

    # This is what makes the whole integration slow to load (around 10-15
    # seconds for my 15 devices) but it is the right way to do it. Only if
    # it succeeds, the integration will be marked as successfully loaded.
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id].update({
        "coordinator": coordinator,
        "devices": devices
    })

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_success = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_success:
        hass.data[DOMAIN].pop(entry.entry_id)
    else:
        _LOGGER.error(f"Unload failed: {unload_success}")
    return unload_success


class SmartThingsFindCoordinator(DataUpdateCoordinator):
    """Class to manage fetching SmartThings Find data."""

    def __init__(self, hass: HomeAssistant, session: aiohttp.ClientSession, devices, update_interval : int):
        """Initialize the coordinator."""
        self.session = session
        self.devices = devices
        self.hass = hass
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval)  # Update interval for all entities
        )

    async def _async_update_data(self):
        """Fetch data from SmartThings Find."""
        try:
            tags = {}
            _LOGGER.debug(f"Updating locations...")
            for device in self.devices:
                dev_data = device['data']
                tag_data = await get_device_location(self.hass, self.session, dev_data, self.config_entry.entry_id)
                tags[dev_data['dvceID']] = tag_data
            _LOGGER.debug(f"Fetched {len(tags)} locations")

            # Samsung may have handed us a new cookie along the way; keep the
            # stored one in step so a restart does not fall back to a dead value.
            self.hass.data[DOMAIN][self.config_entry.entry_id]["auth"].note_rotated_cookie()
            return tags
        except ConfigEntryAuthFailed as err:
            raise
        except Exception as err:
            raise UpdateFailed(f"Error fetching data: {err}")
