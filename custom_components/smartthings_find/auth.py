"""Persistent Samsung Account authentication for SmartThings Find.

The SmartThings Find web bridge is authenticated by a JSESSIONID cookie which
Samsung expires after a few days. That cookie is only the bottom layer of a
four-layer chain, so an integration that stores nothing else has no way to
recover and has to ask the user to paste a new cookie from their browser.

This module stores the top of the chain instead - the master `userauth_token` -
and mints web sessions from it on demand:

    1. interactive Samsung Account sign-in -> master `userauth_token`
    2. master token                        -> short-lived web-Find auth code
    3. getState.do                         -> server-issued opaque login state
    4. login.do(code, state)               -> a fresh JSESSIONID

Two details here are load-bearing and were established by live testing upstream:
the web-Find authorization must omit PKCE (including a challenge yields a cookie
that exists but fails chkLogin.do), and the login state must be the opaque value
from getState.do (a self-generated random state yields a cookie that chkLogin.do
rejects).

The master token is a primary credential: it can mint new scoped tokens and new
web sessions for the account, so it is never logged and only ever masked.

Protocol details follow the reverse engineering published by KieronQuinn/uTag
and charlesbel/samsung-re-find (MIT licensed).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Any

import aiohttp
from yarl import URL

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .const import (
    CLIENT_ID_AUTH,
    CLIENT_ID_WEB_FIND,
    CONF_AUTH_SERVER_URL,
    CONF_DEVICE_ID,
    CONF_JSESSIONID,
    CONF_LOGIN_ID,
    CONF_USER_ID,
    CONF_USERAUTH_TOKEN,
    REDIRECT_URI,
    SCOPE_WEB_FIND,
    URL_ENTRY_POINT,
    URL_GET_CSRF,
    URL_GET_STATE,
    URL_LOGIN,
    URL_STF_BASE,
)

_LOGGER = logging.getLogger(__name__)


class SmartThingsFindAuthError(Exception):
    """Raised when authentication cannot be completed."""


def mask(value: str | None, keep: int = 4) -> str:
    """Render a secret safe to log, keeping only a short prefix."""
    if not value:
        return "<unset>"
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}...<{len(value)} chars>"


@dataclass
class MasterCredentials:
    """The durable half of the auth chain, persisted in the config entry."""

    userauth_token: str
    login_id: str
    user_id: str
    auth_server_url: str
    device_id: str

    @property
    def auth_host(self) -> str:
        """Bare host of the auth server, as login.do expects it."""
        return urllib.parse.urlparse(self.auth_server_url).netloc

    def to_entry_data(self) -> dict[str, str]:
        return {
            CONF_USERAUTH_TOKEN: self.userauth_token,
            CONF_LOGIN_ID: self.login_id,
            CONF_USER_ID: self.user_id,
            CONF_AUTH_SERVER_URL: self.auth_server_url,
            CONF_DEVICE_ID: self.device_id,
        }

    @classmethod
    def from_entry_data(cls, data: dict[str, Any]) -> MasterCredentials | None:
        """Build credentials from a config entry, or None for legacy entries.

        Entries created before persistent auth only hold a JSESSIONID. Those
        keep working until the cookie dies, at which point reauth collects the
        master token and upgrades them.
        """
        token = data.get(CONF_USERAUTH_TOKEN)
        auth_server_url = data.get(CONF_AUTH_SERVER_URL)
        if not token or not auth_server_url:
            return None
        return cls(
            userauth_token=token,
            login_id=data.get(CONF_LOGIN_ID, ""),
            user_id=data.get(CONF_USER_ID, ""),
            auth_server_url=auth_server_url,
            device_id=data.get(CONF_DEVICE_ID, ""),
        )


def generate_code_verifier() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("utf-8")


def generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def _encrypt_svc_param(svc_param_json: str, chk_do_num: int, public_key) -> str:
    """Encrypt the sign-in payload the way the Samsung Account SDK does.

    PBKDF2-HMAC-SHA256 derives an AES key (iterated chk_do_num times), RSA
    PKCS#1 v1.5 wraps that key, and AES-CBC encrypts the payload itself.
    """
    chk_do_num_hash = hashlib.sha256(str(chk_do_num).encode("utf-8")).digest()
    salt = os.urandom(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        base64.b64encode(chk_do_num_hash),
        salt,
        chk_do_num,
        dklen=16,
    )

    wrapped_key = public_key.encrypt(
        base64.b64encode(derived_key), asym_padding.PKCS1v15()
    )

    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
    ).encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(svc_param_json.encode("utf-8")) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    payload = {
        "chkDoNum": str(chk_do_num),
        "svcEncParam": base64.b64encode(encrypted).decode("utf-8"),
        "svcEncKY": base64.b64encode(wrapped_key).decode("utf-8"),
        "svcEncIV": iv.hex(),
    }
    payload_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return urllib.parse.quote(payload_b64)


def _decrypt_callback_value(value: str, key: str) -> str | None:
    """Decrypt one AES-ECB encrypted field from the ms-app:// callback."""
    try:
        key_bytes = key.encode("utf-8")
        key_bytes = key_bytes[:16] if len(key_bytes) >= 16 else key_bytes.ljust(16, b"\0")
        decryptor = Cipher(
            algorithms.AES(key_bytes), modes.ECB(), backend=default_backend()
        ).decryptor()
        padded = decryptor.update(bytes.fromhex(value)) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    except Exception as err:
        _LOGGER.debug("Could not decrypt callback value: %s", err)
        return None


@dataclass
class PendingLogin:
    """State carried between the two halves of the interactive sign-in."""

    state: str
    code_verifier: str
    device_id: str


async def async_start_login(
    session: aiohttp.ClientSession,
    country: str | None,
) -> tuple[str, PendingLogin]:
    """Build the Samsung Account sign-in URL the user has to open."""
    async with session.get(URL_ENTRY_POINT) as res:
        if res.status != 200:
            raise SmartThingsFindAuthError(
                f"Could not reach the Samsung Account entry point (HTTP {res.status})"
            )
        # content_type=None throughout this module: Samsung labels some JSON
        # responses text/plain (getState.do does), and aiohttp would otherwise
        # refuse to parse a perfectly good body.
        entry = await res.json(content_type=None)

    try:
        sign_in_uri = entry["signInURI"]
        public_key = load_der_public_key(
            base64.b64decode(entry["pkiPublicKey"]), backend=default_backend()
        )
        chk_do_num = int(entry["chkDoNum"])
    except (KeyError, ValueError, TypeError) as err:
        raise SmartThingsFindAuthError(
            f"Unexpected Samsung Account entry point response: {err}"
        ) from err

    pending = PendingLogin(
        state=secrets.token_urlsafe(15),
        code_verifier=generate_code_verifier(),
        device_id=secrets.token_hex(16),
    )

    svc_param = {
        "clientId": CLIENT_ID_AUTH,
        "code_challenge": generate_code_challenge(pending.code_verifier),
        "code_challenge_method": "S256",
        "competitorDeviceYNFlag": "Y",
        "countryCode": (country or "us").lower(),
        "deviceInfo": "Google|com.android.chrome",
        "deviceModelID": "Pixel 8 Pro",
        "deviceName": "Google Pixel 8 Pro",
        "deviceOSVersion": "35",
        "devicePhysicalAddressText": f"ANID:{pending.device_id}",
        "deviceType": "APP",
        "deviceUniqueID": pending.device_id,
        "redirect_uri": REDIRECT_URI,
        "replaceableClientConnectYN": "N",
        "replaceableClientId": "",
        "replaceableDevicePhysicalAddressText": "",
        "responseEncryptionType": "1",
        "responseEncryptionYNFlag": "Y",
        "scope": "",
        "state": pending.state,
        "svcIptLgnID": "",
        "iosYNFlag": "Y",
    }

    svc_param_value = _encrypt_svc_param(
        json.dumps(svc_param), chk_do_num, public_key
    )
    login_url = f"{sign_in_uri}?locale=en&svcParam={svc_param_value}&mode=C"
    _LOGGER.debug("Built sign-in URL for device %s", mask(pending.device_id))
    return login_url, pending


async def async_finish_login(
    session: aiohttp.ClientSession,
    redirect_url: str,
    pending: PendingLogin,
) -> MasterCredentials:
    """Exchange the pasted ms-app:// callback for master credentials."""
    parsed = urllib.parse.urlparse(redirect_url.strip())
    params = urllib.parse.parse_qs(parsed.query)
    if parsed.fragment:
        params.update(urllib.parse.parse_qs(parsed.fragment))

    auth_server_url = params.get("auth_server_url", [""])[0]
    code = params.get("code", [""])[0]
    state_param = params.get("state", [""])[0]
    username = params.get("retValue", [""])[0]

    # Samsung encrypts the callback fields, keyed by the state we sent.
    if state_param:
        inner_key = _decrypt_callback_value(state_param, pending.state)
        if inner_key:
            auth_server_url = (
                _decrypt_callback_value(auth_server_url, inner_key) or auth_server_url
            )
            code = _decrypt_callback_value(code, inner_key) or code
            username = _decrypt_callback_value(username, inner_key) or username

    if auth_server_url and not auth_server_url.startswith("http"):
        auth_server_url = f"https://{auth_server_url}"

    if not auth_server_url or not code:
        raise SmartThingsFindAuthError(
            "That URL is missing the authorization code. Make sure you copied the "
            "full ms-app:// URL and not the visible error page URL."
        )
    if not username:
        raise SmartThingsFindAuthError("That URL is missing the account identifier.")

    _assert_samsung_host(auth_server_url)

    async with session.post(
        f"{auth_server_url}/auth/oauth2/authenticate",
        data={
            "grant_type": "authorization_code",
            "serviceType": "M",
            "client_id": CLIENT_ID_AUTH,
            "code": code,
            "code_verifier": pending.code_verifier,
            "username": username,
            "physical_address_text": pending.device_id,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    ) as res:
        if res.status != 200:
            raise SmartThingsFindAuthError(
                f"Samsung rejected the authorization code (HTTP {res.status})"
            )
        data = await res.json(content_type=None)

    userauth_token = data.get("userauth_token") or data.get("userAuthToken")
    user_id = data.get("userId") or data.get("user_id")
    if not userauth_token or not user_id:
        raise SmartThingsFindAuthError(
            "Samsung's response did not include a master token"
        )

    creds = MasterCredentials(
        userauth_token=userauth_token,
        login_id=data.get("loginId") or data.get("login_id") or username,
        user_id=user_id,
        auth_server_url=auth_server_url,
        device_id=pending.device_id,
    )
    _LOGGER.debug("Obtained master token %s", mask(creds.userauth_token))
    return creds


def _assert_samsung_host(url: str) -> None:
    """Refuse to send the master token anywhere but Samsung over HTTPS."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (
        host == "account.samsung.com"
        or host.endswith(".samsungosp.com")
        or host.endswith(".samsung.com")
    ):
        raise SmartThingsFindAuthError(
            f"Refusing to authenticate against untrusted host '{host}'"
        )


async def async_validate_jsessionid(
    session: aiohttp.ClientSession, jsessionid: str
) -> str | None:
    """Return the CSRF token if this cookie is still a live session.

    chkLogin.do answers HTTP 200 even for a dead cookie, so the presence of the
    `_csrf` response header is the only reliable signal.
    """
    if not jsessionid or not jsessionid.strip():
        return None
    try:
        async with session.get(
            URL_GET_CSRF, cookies={"JSESSIONID": jsessionid.strip()}
        ) as res:
            if res.status != 200:
                return None
            return res.headers.get("_csrf")
    except aiohttp.ClientError as err:
        _LOGGER.debug("Session validation request failed: %s", err)
        return None


async def async_mint_jsessionid(
    session: aiohttp.ClientSession, creds: MasterCredentials
) -> tuple[str, str]:
    """Mint a new SmartThings Find web session from the master token.

    Returns the JSESSIONID and the CSRF token that proves it is live.
    """
    params = {
        "response_type": "code",
        "serviceType": "M",
        "client_id": CLIENT_ID_WEB_FIND,
        "childAccountSupported": "Y",
        "userauth_token": creds.userauth_token,
        "physical_address_text": creds.device_id,
        "scope": SCOPE_WEB_FIND,
        "login_id": creds.login_id,
    }
    _assert_samsung_host(creds.auth_server_url)
    authorize_url = f"{creds.auth_server_url}/auth/oauth2/v2/authorize"

    # No PKCE here on purpose: a challenge produces a cookie that fails
    # chkLogin.do. See the module docstring.
    async def _authorize(request_params: dict[str, str]) -> dict[str, Any]:
        async with session.get(authorize_url, params=request_params) as res:
            if res.status != 200:
                raise SmartThingsFindAuthError(
                    f"Web session authorization failed (HTTP {res.status})"
                )
            return await res.json(content_type=None)

    auth_data = await _authorize(params)
    code = auth_data.get("code")
    if not code and auth_data.get("privacyAccepted") == "N":
        # Some accounts only issue a code when login_id is left out.
        retry_params = {k: v for k, v in params.items() if k != "login_id"}
        auth_data = await _authorize(retry_params)
        code = auth_data.get("code")
    if not code:
        raise SmartThingsFindAuthError(
            "Samsung did not issue a web session authorization code"
        )

    # login.do only accepts the opaque state issued by getState.do, and needs
    # the bootstrap cookie from that same call, so both run on one jar. Drop any
    # dead cookie first so the bootstrap starts clean - it is about to be
    # replaced regardless. Reusing the caller's session rather than building a
    # throwaway one keeps Home Assistant's connector and avoids the blocking
    # SSL-context setup that creating a ClientSession performs.
    session.cookie_jar.clear_domain("smartthingsfind.samsung.com")

    async with session.get(URL_GET_STATE, params={"payload": "hound"}) as res:
        if res.status != 200:
            raise SmartThingsFindAuthError(
                f"Could not bootstrap the web session (HTTP {res.status})"
            )
        login_state = (await res.json(content_type=None)).get("state")
    if not login_state:
        raise SmartThingsFindAuthError("SmartThings Find omitted the login state")

    async with session.get(
        URL_LOGIN,
        params={
            "auth_server_url": creds.auth_host,
            "api_server_url": creds.auth_host,
            "code": code,
            "code_expires_in": str(auth_data.get("code_expires_in", 300)),
            "state": login_state,
        },
        allow_redirects=False,
    ) as res:
        if res.status not in (200, 302):
            raise SmartThingsFindAuthError(
                f"Web session exchange failed (HTTP {res.status})"
            )

    cookie = session.cookie_jar.filter_cookies(URL(URL_STF_BASE)).get("JSESSIONID")
    if not cookie or not cookie.value:
        raise SmartThingsFindAuthError(
            "SmartThings Find did not issue a session cookie"
        )
    jsessionid = cookie.value

    csrf = await async_validate_jsessionid(session, jsessionid)
    if not csrf:
        raise SmartThingsFindAuthError(
            "SmartThings Find issued a session cookie that failed validation"
        )

    _LOGGER.info("Minted a fresh SmartThings Find session")
    return jsessionid, csrf


class WebSessionManager:
    """Owns the SmartThings Find web session for one config entry.

    Callers ask for a CSRF token; this class makes sure a live session backs it,
    reusing the cached cookie when it still works and silently minting a new one
    when it does not. Only a dead master token surfaces as a reauth prompt.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        session: aiohttp.ClientSession,
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._session = session
        self._csrf: str | None = None
        self._jsessionid: str | None = None
        self._lock = asyncio.Lock()
        self._generation = 0

    @property
    def csrf(self) -> str:
        """CSRF token for the current session."""
        if not self._csrf:
            raise SmartThingsFindAuthError("No active SmartThings Find session")
        return self._csrf

    @property
    def can_self_renew(self) -> bool:
        """Whether this entry holds credentials that can mint a new session."""
        return MasterCredentials.from_entry_data(self._entry.data) is not None

    async def async_ensure_session(self, *, force_renew: bool = False) -> str:
        """Return a CSRF token backed by a live session, renewing if needed."""
        seen_generation = self._generation
        async with self._lock:
            # Somebody else renewed while we waited for the lock, so the token we
            # would have replaced is already gone. Use theirs instead of minting
            # another session for every device in the same update cycle.
            if self._generation != seen_generation and self._csrf:
                return self._csrf
            if not force_renew and self._csrf:
                return self._csrf

            cached = self._jsessionid or self._entry.data.get(CONF_JSESSIONID)
            if not force_renew and cached:
                if csrf := await async_validate_jsessionid(self._session, cached):
                    self._adopt(cached, csrf)
                    return csrf
                _LOGGER.debug("Cached SmartThings Find session is no longer valid")

            creds = MasterCredentials.from_entry_data(self._entry.data)
            if creds is None:
                # A pre-persistent-auth entry: nothing to renew from, so the
                # user has to sign in once to upgrade it.
                raise ConfigEntryAuthFailed(
                    "The SmartThings Find session expired. Reauthenticate once to "
                    "let the integration renew sessions on its own from now on."
                )

            try:
                jsessionid, csrf = await async_mint_jsessionid(self._session, creds)
            except SmartThingsFindAuthError as err:
                # The master token itself is gone; only the user can fix this.
                raise ConfigEntryAuthFailed(str(err)) from err

            self._adopt(jsessionid, csrf)
            self._persist(jsessionid)
            return csrf

    def _adopt(self, jsessionid: str, csrf: str) -> None:
        """Install a session cookie, scoped to SmartThings Find only."""
        self._jsessionid = jsessionid
        self._csrf = csrf
        self._generation += 1
        jar = self._session.cookie_jar
        jar.clear_domain("smartthingsfind.samsung.com")
        # The response URL matters: without it aiohttp files the cookie as a
        # domain-less "shared" cookie and sends it to every host.
        jar.update_cookies({"JSESSIONID": jsessionid}, URL(f"{URL_STF_BASE}/"))

    def _persist(self, jsessionid: str) -> None:
        """Cache the cookie so a restart does not need to mint another one."""
        if self._entry.data.get(CONF_JSESSIONID) == jsessionid:
            return
        self._hass.config_entries.async_update_entry(
            self._entry, data={**self._entry.data, CONF_JSESSIONID: jsessionid}
        )

    def note_rotated_cookie(self) -> None:
        """Persist a cookie that Samsung rotated underneath us.

        Samsung reissues the cookie periodically. aiohttp picks that up in the
        jar automatically, but unless it is written back to the config entry the
        next restart would start again from a stale value.
        """
        cookie = self._session.cookie_jar.filter_cookies(URL(URL_STF_BASE)).get(
            "JSESSIONID"
        )
        if cookie and cookie.value and cookie.value != self._jsessionid:
            _LOGGER.debug("SmartThings Find rotated the session cookie")
            self._jsessionid = cookie.value
            self._persist(cookie.value)
