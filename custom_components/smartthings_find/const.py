DOMAIN = "smartthings_find"

# Cached SmartThings Find web-bridge session cookie. Kept for backwards
# compatibility with entries created before persistent auth existed.
CONF_JSESSIONID = "jsessionid"

# Master Samsung Account credentials. These let the integration mint a fresh
# JSESSIONID on its own, which is what makes the session survive longer than a
# few days. See auth.py for the flow these feed into.
CONF_USERAUTH_TOKEN = "userauth_token"
CONF_LOGIN_ID = "login_id"
CONF_USER_ID = "user_id"
CONF_AUTH_SERVER_URL = "auth_server_url"
CONF_DEVICE_ID = "device_id"

CONF_ACTIVE_MODE_SMARTTAGS = "active_mode_smarttags"
CONF_ACTIVE_MODE_OTHERS = "active_mode_others"

CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT = True
CONF_ACTIVE_MODE_OTHERS_DEFAULT = False

CONF_UPDATE_INTERVAL = "update_interval"
CONF_UPDATE_INTERVAL_DEFAULT = 120

# Samsung Account OAuth client ids, as used by the official apps.
# CLIENT_ID_AUTH mints the master token; CLIENT_ID_WEB_FIND authorizes the
# legacy smartthingsfind.samsung.com web bridge that this integration reads.
CLIENT_ID_AUTH = "yfrtglt53o"
CLIENT_ID_WEB_FIND = "ntly6zvfpn"
SCOPE_WEB_FIND = "iot.client"

# Redirect target registered by the Samsung app. The browser cannot follow it,
# which is why the user copies the resulting ms-app:// URL back into the flow.
REDIRECT_URI = (
    "ms-app://s-1-15-2-4027708247-2189610-1983755848-2937435718"
    "-1578786913-2158692839-1974417358"
)

URL_ENTRY_POINT = "https://account.samsung.com/accounts/ANDROIDSDK/getEntryPoint"
URL_STF_BASE = "https://smartthingsfind.samsung.com"
URL_GET_STATE = f"{URL_STF_BASE}/getState.do"
URL_LOGIN = f"{URL_STF_BASE}/login.do"
URL_GET_CSRF = f"{URL_STF_BASE}/chkLogin.do"
URL_DEVICE_LIST = f"{URL_STF_BASE}/device/getDeviceList.do"
URL_REQUEST_LOC_UPDATE = f"{URL_STF_BASE}/dm/addOperation.do"
URL_SET_LAST_DEVICE = f"{URL_STF_BASE}/device/setLastSelect.do"

BATTERY_LEVELS = {
    'FULL': 100,
    'MEDIUM': 50,
    'LOW': 15,
    'VERY_LOW': 5
}
