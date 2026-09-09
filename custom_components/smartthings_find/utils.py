import logging
import json
import aiohttp
import html
from datetime import datetime, timezone
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry

from .auth import WebSessionManager
from .const import (
    DOMAIN,
    BATTERY_LEVELS,
    CONF_ACTIVE_MODE_SMARTTAGS,
    CONF_ACTIVE_MODE_OTHERS,
    URL_DEVICE_LIST,
    URL_REQUEST_LOC_UPDATE,
    URL_SET_LAST_DEVICE,
)

_LOGGER = logging.getLogger(__name__)


def _get_auth(hass: HomeAssistant, entry_id: str) -> WebSessionManager:
    return hass.data[DOMAIN][entry_id]["auth"]


def _is_auth_failure(status: int, text: str) -> bool:
    """Whether a response means the web session is no longer accepted."""
    return status in (401, 403, 404) or text.strip() == "Logout"


async def stf_post(
    hass: HomeAssistant,
    session: aiohttp.ClientSession,
    entry_id: str,
    url: str,
    *,
    json_body: dict | None = None,
    data: dict | None = None,
    headers: dict | None = None,
) -> tuple[int, str]:
    """POST to SmartThings Find, renewing the session once if it is rejected.

    Renewal is silent when the stored master credentials still work, so an
    expired cookie no longer surfaces to the user as a reauth prompt.
    """
    auth = _get_auth(hass, entry_id)

    async def _attempt() -> tuple[int, str]:
        async with session.post(
            f"{url}?_csrf={auth.csrf}",
            json=json_body,
            data=data,
            headers=headers,
        ) as response:
            return response.status, await response.text()

    status, text = await _attempt()
    if _is_auth_failure(status, text):
        _LOGGER.info(
            "SmartThings Find rejected the session (HTTP %s); renewing", status
        )
        await auth.async_ensure_session(force_renew=True)
        status, text = await _attempt()
        if _is_auth_failure(status, text):
            raise ConfigEntryAuthFailed(
                f"SmartThings Find still rejects the session after renewal "
                f"(HTTP {status})"
            )
    return status, text


async def get_devices(hass: HomeAssistant, session: aiohttp.ClientSession, entry_id: str) -> list:
    """
    Sends a request to the SmartThings Find API to retrieve a list of devices associated with the user's account.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        session (aiohttp.ClientSession): The current session.

    Returns:
        list: A list of devices if successful, empty list otherwise.
    """
    # stf_post renews an expired session and only raises once renewal itself
    # fails, so a 404 here no longer means "ask the user to log in again".
    status, text = await stf_post(
        hass,
        session,
        entry_id,
        URL_DEVICE_LIST,
        data={},
        headers={'Accept': 'application/json'},
    )
    if status != 200:
        _LOGGER.error(f"Failed to retrieve devices [{status}]: {text}")
        return []

    devices_data = json.loads(text)["deviceList"]
    devices = []
    for device in devices_data:
        # Double unescaping required. Example:
        # "Benedev&amp;#39;s S22" first becomes "Benedev&#39;s S22" and then "Benedev's S22"
        device['modelName'] = html.unescape(
            html.unescape(device['modelName']))
        identifier = (DOMAIN, device['dvceID'])
        ha_dev = device_registry.async_get(
            hass).async_get_device({identifier})
        if ha_dev and ha_dev.disabled:
            _LOGGER.debug(
                f"Ignoring disabled device: '{device['modelName']}' (disabled by {ha_dev.disabled_by})")
            continue
        ha_dev_info = DeviceInfo(
            identifiers={identifier},
            manufacturer="Samsung",
            name=device['modelName'],
            model=device['modelID'],
            configuration_url="https://smartthingsfind.samsung.com/"
        )
        devices += [{"data": device, "ha_dev_info": ha_dev_info}]
        _LOGGER.debug(f"Adding device: {device['modelName']}")
    return devices


async def get_device_location(hass: HomeAssistant, session: aiohttp.ClientSession, dev_data: dict, entry_id: str) -> dict:
    """
    Sends requests to update the device's location and retrieves the current location data for the specified device.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        session (aiohttp.ClientSession): The current session.
        dev_data (dict): The device information obtained from get_devices.

    Returns:
        dict: The device location data.
    """
    dev_id = dev_data['dvceID']
    dev_name = dev_data['modelName']

    set_last_payload = {
        "dvceId": dev_id,
        "removeDevice": []
    }

    update_payload = {
        "dvceId": dev_id,
        "operation": "CHECK_CONNECTION_WITH_LOCATION",
        "usrId": dev_data['usrId']
    }

    try:
        active = (
            (dev_data['deviceTypeCode'] == 'TAG' and hass.data[DOMAIN][entry_id][CONF_ACTIVE_MODE_SMARTTAGS]) or
            (dev_data['deviceTypeCode'] != 'TAG' and hass.data[DOMAIN]
             [entry_id][CONF_ACTIVE_MODE_OTHERS])
        )

        if active:
            _LOGGER.debug("Active mode; requesting location update now")
            await stf_post(
                hass, session, entry_id, URL_REQUEST_LOC_UPDATE,
                json_body=update_payload,
            )
        else:
            _LOGGER.debug("Passive mode; not requesting location update")

        status, res_text = await stf_post(
            hass, session, entry_id, URL_SET_LAST_DEVICE,
            json_body=set_last_payload,
            headers={'Accept': 'application/json'},
        )
        _LOGGER.debug(f"[{dev_name}] Location response ({status})")
        if status == 200:
            data = json.loads(res_text)
            res = {
                "dev_name": dev_name,
                "dev_id": dev_id,
                "update_success": True,
                "location_found": False,
                "used_op": None,
                "used_loc": None,
                "ops": []
            }
            used_loc = None
            if 'operation' in data and len(data['operation']) > 0:
                res['ops'] = data['operation']

                used_op = None
                used_loc = {
                    "latitude": None,
                    "longitude": None,
                    "gps_accuracy": None,
                    "gps_date": None
                }
                # Find and extract the latest location from the response. Often the response
                # contains multiple locations (especially for non-SmartTag devices such as phones).
                # We go through all of them and find the "most usable" one. Sometimes locations
                # are encrypted (usually OFFLINE_LOC), we ignore these. They could probably also
                # be encrypted; there is a special getEncToken-Endpoint which returns some sort of
                # key. Since the only encrypted locations I encountered were even older than the
                # non encrypted ones, I didn't try anything to encrypt them yet.
                for op in data['operation']:
                    if op['oprnType'] in ['LOCATION', 'LASTLOC', 'OFFLINE_LOC']:
                        if 'latitude' in op:
                            utcDate = None

                            if 'extra' in op and 'gpsUtcDt' in op['extra']:
                                utcDate = parse_stf_date(
                                    op['extra']['gpsUtcDt'])
                            else:
                                _LOGGER.error(
                                    f"[{dev_name}] No UTC date found for operation '{op['oprnType']}', this should not happen! OP: {json.dumps(op)}")
                                continue

                            if used_loc['gps_date'] and used_loc['gps_date'] >= utcDate:
                                _LOGGER.debug(
                                    f"[{dev_name}] Ignoring location older than the previous ({op['oprnType']})")
                                continue

                            locFound = False
                            if 'latitude' in op:
                                used_loc['latitude'] = float(
                                    op['latitude'])
                                locFound = True
                            if 'longitude' in op:
                                used_loc['longitude'] = float(
                                    op['longitude'])
                                locFound = True

                            if not locFound:
                                _LOGGER.warn(
                                    f"[{dev_name}] Found no coordinates in operation '{op['oprnType']}'")
                            else:
                                res['location_found'] = True

                            used_loc['gps_accuracy'] = calc_gps_accuracy(
                                op.get('horizontalUncertainty'), op.get('verticalUncertainty'))
                            used_loc['gps_date'] = utcDate
                            used_op = op

                        elif 'encLocation' in op:
                            loc = op['encLocation']
                            if 'encrypted' in loc and loc['encrypted']:
                                _LOGGER.info(
                                    f"[{dev_name}] Ignoring encrypted location ({op['oprnType']})")
                                continue
                            elif 'gpsUtcDt' not in loc:
                                _LOGGER.info(
                                    f"[{dev_name}] Ignoring location with missing date ({op['oprnType']})")
                                continue
                            else:
                                utcDate = parse_stf_date(loc['gpsUtcDt'])
                                if used_loc['gps_date'] and used_loc['gps_date'] >= utcDate:
                                    _LOGGER.debug(
                                        f"[{dev_name}] Ignoring location older than the previous ({op['oprnType']})")
                                    continue
                                else:
                                    locFound = False
                                    if 'latitude' in loc:
                                        used_loc['latitude'] = float(
                                            loc['latitude'])
                                        locFound = True
                                    if 'longitude' in loc:
                                        used_loc['longitude'] = float(
                                            loc['longitude'])
                                        locFound = True
                                    else:
                                        res['location_found'] = True

                                    if not locFound:
                                        _LOGGER.warn(
                                            f"[{dev_name}] Found no coordinates in operation '{op['oprnType']}'")

                                    used_loc['gps_accuracy'] = calc_gps_accuracy(
                                        loc.get('horizontalUncertainty'), loc.get('verticalUncertainty'))
                                    used_loc['gps_date'] = utcDate
                                    used_op = op
                                continue

                if used_op:
                    res['used_op'] = used_op
                    res['used_loc'] = used_loc
                else:
                    _LOGGER.warn(
                        f"[{dev_name}] No useable location-operation found")

                _LOGGER.debug(
                    f"    --> {dev_name} used operation: {'NONE' if not used_op else used_op['oprnType']}")

            else:
                _LOGGER.warn(
                    f"[{dev_name}] No operation found in response; marking update failed")
                res['update_success'] = False
            return res
        else:
            _LOGGER.error(
                f"[{dev_name}] Failed to fetch device data ({status})")
            _LOGGER.debug(f"[{dev_name}] Full response: '{res_text}'")

    except ConfigEntryAuthFailed as e:
        raise
    except Exception as e:
        _LOGGER.error(
            f"[{dev_name}] Exception occurred while fetching location data for tag '{dev_name}': {e}", exc_info=True)

    return None


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
    return datetime.strptime(datestr, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


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
