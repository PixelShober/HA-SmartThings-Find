"""Mint a SmartThings Find web session in a real browser with a persistent profile.

Samsung disables SSO for the STF client (ssoDisabled/bypassable/extendable = false), so every
new session needs a password. The profile keeps the "trusted device" mark, so 2FA should only
be needed on the very first run.

usage: venv/bin/python stf_login.py [--headless] [--fresh] [--out FILE] [--ha]
  --ha      unattended mode (run hourly under xvfb-run): if the last pushed session still works do
            nothing, else log in and push the new cookie to HA (HA_URL/HA_TOKEN in the credentials,
            several instances comma-separated in the same order)
  NOTE: headless triggers reCAPTCHA - run headed, on a virtual display (xvfb-run) when unattended
  --fresh   drop only the smartthingsfind cookies (keeps account.samsung.com trust)
  --out     write the authenticated JSESSIONID there (chmod 600), never printed
"""
import argparse, json, os, sys, time, traceback, urllib.request
from urllib.parse import urlsplit
from patchright.sync_api import sync_playwright

STF = "https://smartthingsfind.samsung.com"
PROFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profile")
# ponytail: patchright's own Chromium; Vivaldi's web-based UI breaks CDP target handling.
# If bot checks persist, point executable_path at a real Google Chrome.

ap = argparse.ArgumentParser()
ap.add_argument("--headless", action="store_true")
ap.add_argument("--fresh", action="store_true")
ap.add_argument("--out")
ap.add_argument("--timeout", type=int, default=300)
ap.add_argument("--ha", action="store_true",
                help="keep HA supplied: skip if the last pushed session still works, else log in and push")
a = ap.parse_args()


CREDS = os.path.expanduser("~/.config/stf-bot/credentials")


def load_creds() -> dict:
    """KEY=VALUE file, chmod 600. Missing file -> manual login in the window."""
    if not os.path.exists(CREDS):
        return {}
    if os.stat(CREDS).st_mode & 0o077:
        sys.exit(f"{CREDS} must not be readable by others (chmod 600)")
    out = {}
    for line in open(CREDS):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def autofill(page, creds: dict, done: set) -> None:
    """Fill each step at most once per run - repeated failed logins can lock the account."""
    if urlsplit(page.url).netloc != "account.samsung.com":
        return
    email = page.locator('input[name="account"]:visible, input[type="email"]:visible').first
    if "email" not in done and email.count() and not email.input_value():
        email.fill(creds["STF_EMAIL"]); email.press("Enter"); done.add("email"); print("filled email")
        return
    pw = page.locator('input[type="password"]:visible').first
    if "password" not in done and pw.count():
        pw.fill(creds["STF_PASSWORD"]); pw.press("Enter"); done.add("password"); print("filled password")


STATE_DIR = os.path.expanduser("~/.local/state/stf-bot")
STATE = os.path.join(STATE_DIR, "jsid")          # last session the bot minted
PUSHED = os.path.join(STATE_DIR, "jsid.pushed")  # last session HA accepted
FAILED = os.path.join(STATE_DIR, "login_failed") # backoff marker
BACKOFF = 6 * 3600  # failed logins retried at most every 6 h - repeated failures can lock the account
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"


def write_secret(path: str, value: str) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, value.encode()); os.close(fd)


def jsid_alive(jsid: str) -> bool:
    """Plain-HTTP chkLogin - an expired session answers 200 'fail' without _csrf."""
    req = urllib.request.Request(f"{STF}/chkLogin.do", headers={"User-Agent": UA, "Cookie": "JSESSIONID=" + jsid})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return bool(r.headers.get("_csrf"))
    except Exception:
        return False


BOT_NOTIFICATION = "smartthings_find_login_bot"


def ha_targets(creds: dict) -> list[tuple[str, str]]:
    """HA_URL / HA_TOKEN may list several instances, comma-separated in the same order."""
    urls = [u.strip().rstrip("/") for u in creds["HA_URL"].split(",")]
    tokens = [t.strip() for t in creds["HA_TOKEN"].split(",")]
    if len(urls) != len(tokens):
        sys.exit("HA_URL and HA_TOKEN need the same number of comma-separated entries")
    return list(zip(urls, tokens))


def ha_service(creds: dict, service: str, data: dict) -> None:
    for url, token in ha_targets(creds):
        req = urllib.request.Request(
            url + "/api/services/persistent_notification/" + service,
            data=json.dumps(data).encode(), method="POST",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=30).close()
        except Exception as e:  # one HA down must not hide the notification on the others
            print(f"notification to {url} failed:", e)


def fail(msg: str) -> None:
    """Unattended failure: tell HA (best effort) so it does not go unnoticed, then exit non-zero."""
    print("FAILED:", msg)
    if a.ha and login_attempted:
        write_secret(FAILED, str(int(time.time())))
    if a.ha:
        try:
            ha_service(load_creds(), "create", {
                "notification_id": BOT_NOTIFICATION, "title": "SmartThings Find: Login-Bot fehlgeschlagen",
                "message": f"Der Bot konnte keine neue Web-Session holen: {msg}\n\n"
                           "Log: `journalctl -u stf-bot` auf dem Bot-Host. Screenshot der letzten Seite: "
                           "`/tmp/stf/login_timeout.png`."})
        except Exception as e:
            print("could not notify HA either:", e)
    sys.exit(1)


def push_to_ha(creds: dict, jsid: str) -> None:
    """Sets the cookie through the integration's options flow (other options keep their values).
    Tries every instance; any failure raises afterwards, so the next run pushes again (idempotent)."""
    errors = []
    for url, token in ha_targets(creds):
        base = url + "/api/config/config_entries"
        hdr = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}

        def call(u, body=None):
            req = urllib.request.Request(u, data=None if body is None else json.dumps(body).encode(), headers=hdr,
                                         method="GET" if body is None else "POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)

        try:
            entry = next(e for e in call(base + "/entry") if e["domain"] == "smartthings_find")
            flow = call(base + "/options/flow", {"handler": entry["entry_id"]})
            res = call(f"{base}/options/flow/{flow['flow_id']}", {"web_jsessionid": jsid})
            if res.get("type") != "create_entry":
                raise RuntimeError(f"rejected the cookie: {res.get('errors') or res.get('type')}")
            print("pushed to", url)
        except Exception as e:
            errors.append(f"{url}: {e}")
    if errors:
        raise RuntimeError("HA push failed - " + "; ".join(errors))


def session_ok(ctx) -> bool:
    r = ctx.request.get(f"{STF}/chkLogin.do")
    return r.ok and bool(r.headers.get("_csrf"))


def read(path: str) -> str:
    return open(path).read().strip() if os.path.exists(path) else ""


login_attempted = False
if a.ha:
    # any crash in unattended mode must reach HA, not just the journal
    sys.excepthook = lambda t, v, tb: (traceback.print_exception(t, v, tb), fail(f"{t.__name__}: {v}"))
    minted = read(STATE)
    if minted and jsid_alive(minted):
        if read(PUSHED) == minted:
            print("session still valid - nothing to do")
        else:
            creds = load_creds()  # HA was unreachable last time: push again, no new login needed
            push_to_ha(creds, minted); write_secret(PUSHED, minted)
            ha_service(creds, "dismiss", {"notification_id": BOT_NOTIFICATION})
        sys.exit(0)
    last_fail = read(FAILED)
    if last_fail and time.time() - int(last_fail) < BACKOFF:
        print(f"last login failed {int((time.time() - int(last_fail)) / 60)} min ago - waiting for the 6 h backoff")
        sys.exit(0)
    a.fresh = True  # stale STF cookies in the profile would only confuse the login
    login_attempted = True

with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(
        PROFILE, headless=a.headless, no_viewport=True)
    if a.fresh:
        keep = [c for c in ctx.cookies() if "smartthingsfind" not in c["domain"]]
        ctx.clear_cookies()
        ctx.add_cookies(keep)
    page = ctx.pages[0] if ctx.pages else ctx.new_page()
    seen = []
    page.on("framenavigated", lambda f: f == page.main_frame and seen.append(urlsplit(f.url).path))

    page.goto(STF, wait_until="domcontentloaded")
    if session_ok(ctx):
        print("already logged in")
    else:
        # Same as the STF frontend's own login button (function D("hound") in its bundle)
        # patchright evaluates in an isolated world by default; the SDK lives in the page's main world
        for _ in range(60):
            if page.evaluate("() => !!(window.samsung && window.samsung.account)", isolated_context=False):
                break
            time.sleep(0.5)
        page.evaluate("""async () => {
            const s = (await (await fetch('/getState.do?payload=hound', {credentials: 'include'})).json()).state;
            window.samsung.account.signIn({clientId: 'ntly6zvfpn',
                redirectUri: encodeURIComponent(location.origin + '/login.do'),
                responseType: 'code', scope: 'iot.client', state: s});
        }""", isolated_context=False)
        print("login started")
        creds, done = load_creds(), set()
        if creds and "hier-passwort" in creds.get("STF_PASSWORD", ""):
            creds = {}  # template not filled in yet
        deadline = time.time() + a.timeout
        while time.time() < deadline:
            time.sleep(2)
            path = urlsplit(page.url).path
            if not seen or seen[-1] != path:
                seen.append(path)  # SPA route changes don't fire framenavigated
            if creds:
                try:
                    autofill(page, creds, done)
                except Exception as e:  # page mid-navigation
                    print("autofill retry:", type(e).__name__)
            # page.url can lag behind the final redirect, so trust chkLogin only
            if session_ok(ctx):
                break
        else:
            os.makedirs("/tmp/stf", exist_ok=True)
            page.screenshot(path="/tmp/stf/login_timeout.png")
            pages, last = " -> ".join(dict.fromkeys(seen)), urlsplit(page.url).path
            ctx.close()
            fail(f"Login nach {a.timeout} s nicht abgeschlossen (letzte Seite {last}; "
                 f"Verlauf {pages}). Häufige Ursachen: reCAPTCHA, geändertes Passwort, neue 2FA-Abfrage.")

    print("IAM pages:", " -> ".join(x for x in dict.fromkeys(seen) if x.startswith("/iam")) or "-")
    js = next((c for c in ctx.cookies(STF) if c["name"] == "JSESSIONID" and "." in c["value"]), None)
    print("RESULT:", "OK" if js else "FAILED",
          ("node=" + js["value"].split(".", 1)[1]) if js else "")
    ok = bool(js) and session_ok(ctx)
    ctx.close()

if not ok:
    fail("Login lief durch, aber es gab keine gültige JSESSIONID")
if a.out:
    write_secret(a.out, js["value"])
if a.ha:
    write_secret(STATE, js["value"])  # before pushing: if HA is down, the next run only re-pushes
    if os.path.exists(FAILED):
        os.remove(FAILED)
    login_attempted = False  # from here on only HA can fail, no reason for a login backoff
    creds = load_creds()
    push_to_ha(creds, js["value"])
    write_secret(PUSHED, js["value"])
    ha_service(creds, "dismiss", {"notification_id": BOT_NOTIFICATION})
