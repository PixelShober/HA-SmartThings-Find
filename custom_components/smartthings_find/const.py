DOMAIN = "smartthings_find"

CONF_ACCESS_TOKEN = "access_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_IOT_ACCESS_TOKEN = "iot_access_token"
CONF_IOT_REFRESH_TOKEN = "iot_refresh_token"
CONF_USER_ID = "user_id"
CONF_USER_EMAIL = "user_email"
CONF_AUTH_SERVER_URL = "auth_server_url"
CONF_DEVICE_ID = "device_id"
CONF_ST_USER_UUID = "st_user_uuid"
CONF_INSTALLED_APP_ID = "installed_app_id"
CONF_ACTIVE_MODE_SMARTTAGS = "active_mode_smarttags"
CONF_ACTIVE_MODE_OTHERS = "active_mode_others"

CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT = True
CONF_ACTIVE_MODE_OTHERS_DEFAULT = False

CONF_UPDATE_INTERVAL = "update_interval"
CONF_UPDATE_INTERVAL_DEFAULT = 120

# Measured 2026-09-24: phones stop by themselves after 60 s, buds after ~188 s.
# Caps fast status polling, and is the optimistic auto-off for tags.
RING_TIMEOUT_SECONDS = 200

CLIENT_ID_FIND = "27zmg0v1oo"
CLIENT_ID_AUTH = "yfrtglt53o"
CLIENT_ID_ONECONNECT = "6iado3s6jc"
SCOPE_FIND = "offline.access"
SCOPE_AUTH = "serviceType"

# The SmartThings installed-app proxy only exposes /trackerapi, so it can ring
# SmartTags but not phones, tablets or earbuds. The classic web frontend rings
# every device type through a single endpoint, so we borrow a session from it.
#
# Minting that session headlessly from the master token is NOT possible (verified
# 2026-09-18): the browser obtains its code via samsung.account.signIn with
# redirect_uri=<base>/login.do, and login.do only redeems codes bound to that
# redirect_uri - while /auth/oauth2/v2/authorize rejects redirect_uri outright
# with 400 unauthorized_client. So the cookie is pasted in once by the user and
# then kept alive: the idle timeout is 30 min and we poll far more often.
CONF_USER_AUTH_TOKEN = "user_auth_token"
CONF_LOGIN_ID = "login_id"
CONF_WEB_JSESSIONID = "web_jsessionid"
URL_STF = "https://smartthingsfind.samsung.com"

BATTERY_LEVELS = {
    'FULL': 100,
    'MEDIUM': 50,
    'LOW': 15,
    'VERY_LOW': 5
}
