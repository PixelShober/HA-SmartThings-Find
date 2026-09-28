# Klingeln: wie es funktioniert und warum so

Stand: 2026-09-28. Dieses Dokument hält fest, **welcher Weg für welches Gerät funktioniert**,
und vor allem **welche Wege nachweislich nicht funktionieren** — damit niemand (auch kein
zukünftiges Ich) sie ein zweites Mal durchprobiert.

## Kurzfassung

| Gerätetyp | Weg | Automatisch? |
|---|---|---|
| SmartTags | SmartThings-Proxy `PUT /trackerapi` + `/trackers/<id>/ring` (wie die SmartThings-App) | ja, vollautomatisch, an **und** aus |
| Handy, Tablet, Kopfhörer | Web-Frontend `POST /dm/addOperation.do` | ja — nach Einfügen eines Cookies, oder per Login-Bot |

SmartTags brauchen keine Konfiguration. Für alles andere muss einmalig ein `JSESSIONID`-Cookie
hinterlegt werden (siehe unten), weil sich die dafür nötige Web-Session **nicht** programmatisch
erzeugen lässt.

## Einrichtung für Handy / Tablet / Kopfhörer

1. In einem Browser auf <https://smartthingsfind.samsung.com> mit dem Samsung-Konto anmelden.
2. F12 → **Application** → **Cookies** → `https://smartthingsfind.samsung.com`.
3. Wert von **`JSESSIONID`** kopieren.
   ⚠️ Es können **zwei** Cookies dieses Namens existieren. Nur das **mit** Punkt-Suffix
   (Tomcat-`jvmRoute`, z.B. `…ACA.fmm-prd-cns-1`) ist authentifiziert; das ohne Suffix
   antwortet auf `chkLogin.do` mit `fail`. Den Wert **unverändert** übernehmen — das Suffix
   bindet die Session an einen Cluster-Node und darf nicht abgeschnitten werden.
4. In Home Assistant: **Einstellungen → Geräte & Dienste → SmartThings Find → Konfigurieren**,
   Wert in das Feld *JSESSIONID-Cookie* einfügen, speichern.

Die Integration hält die Session danach selbst am Leben.

## Automatisch erneuern: Login-Bot (seit 2026-09-25)

Die Session lässt sich nicht verlängern (`extendable:false`, siehe unten) und stirbt irgendwann. Ein
stiller Mint ist unmöglich, also loggt sich ein **echter Browser** mit E-Mail und Passwort neu ein:
[`bot/stf_login.py`](bot/stf_login.py), läuft als eigener Benutzer `stfbot` auf einem beliebigen Linux-Host
(z. B. einem LXC-Container).

- **Stündlicher Timer** ([`bot/stf-bot.timer`](bot/stf-bot.timer)): Zuerst ein `chkLogin` ohne Browser.
  Lebt die zuletzt erzeugte Session noch, passiert nichts. Nur wenn sie tot ist: Login (~12 s), dann
  neues Cookie über den Options-Flow in HA eintragen. Mit dem Keep-alive der Integration hielt eine
  Session bisher über 2 Tage (25.–28.09.2026), der Bot loggt sich also selten ein.
- **Browser:** [patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) (Playwright ohne Automatisierungsspuren) mit
  dauerhaftem Profil, in dem das Gerät als vertraut markiert ist → **keine 2FA**.
  **Headless löst reCAPTCHA aus**, deshalb sichtbar auf einem virtuellen Bildschirm (`xvfb-run`).
- **Zugangsdaten:** `~stfbot/.config/stf-bot/credentials` (chmod 600, sonst Abbruch) mit
  `STF_EMAIL`, `STF_PASSWORD`, `HA_URL`, `HA_TOKEN` (Long-Lived Access Token eines **Admin**-Benutzers,
  der Options-Flow braucht Admin-Rechte).
- **Mehrere HA-Instanzen** (z. B. Test und Produktiv): `HA_URL` und `HA_TOKEN` kommagetrennt in gleicher
  Reihenfolge. Jede Instanz wird einzeln versorgt. Schlägt eine fehl, pusht der nächste Lauf erneut.
  Beim Einfügen prüfen: Ein Token ist ein JWT mit genau zwei **Punkten** und ohne Komma.
- **Schutz vor Kontosperre:** E-Mail und Passwort werden pro Lauf höchstens einmal eingetippt.
  Nach einem fehlgeschlagenen Login pausiert der Bot 6 h. Ist nur HA nicht erreichbar, wird die schon
  erzeugte Session später nachgereicht, ohne neuen Login.
- **Rückmeldung bei Fehlern**, zweifach als HA-Benachrichtigung (feste IDs, geeignet als Automations-Auslöser
  `platform: persistent_notification`):
  - `smartthings_find_login_bot` – vom Bot: Login hängt, Passwort falsch, HA lehnt ab usw.
  - `smartthings_find_web_session` – von der Integration: Keep-alive findet eine tote Session.
    Greift auch, wenn der Bot gar nicht läuft. Verschwindet von selbst, sobald die Session wieder gilt.

Logs: `journalctl -u stf-bot`. Bei einem Login-Timeout liegt ein Screenshot der letzten Seite unter
`/tmp/stf/login_timeout.png`. Manuell auslösen: `systemctl start stf-bot`. Sofort erneut an HA schicken
(ohne Login): `~stfbot/.local/state/stf-bot/jsid.pushed` löschen, dann starten.

**Einrichtung (Debian):** Benutzer `stfbot` anlegen, `xvfb` installieren, Skript nach `/opt/stf-bot`,
dort `python3 -m venv venv && venv/bin/pip install patchright && venv/bin/patchright install --with-deps chromium`.
Den ersten Login einmal sichtbar (bzw. unter `xvfb-run`) laufen lassen, damit das Profil das Gerät als
vertraut speichert (evtl. einmal 2FA). Dann die Units aus `bot/` nach `/etc/systemd/system/` und
`systemctl enable --now stf-bot.timer`.

**Fallstrick IP-Sperre:** Schickt der Bot mehrfach einen falschen Token, sperrt HA (`ip_ban`) seine IP.
Danach antwortet HA auf **alles** mit 403, auch mit richtigem Token. Eintrag aus `/config/ip_bans.yaml`
entfernen und HA neu starten.

Nicht funktioniert haben (alle getestet): Vivaldi als Browser-Binary (Absturz, die Vivaldi-UI stört CDP),
Google-Login (Samsung nutzt `gapi.auth2` mit FedCM, der Klick bewirkt im Bot nichts), headless.

## Wie das Am-Leben-Halten funktioniert

Die Session hat ein **Idle-Timeout von 30 Minuten** (im Frontend-JS als `18e5` ms hinterlegt).
Jeder Aufruf setzt es zurück. Der Update-Coordinator der Integration pollt ohnehin regelmäßig
(Default **120 Sekunden**, einstellbar ab 30 s) und ruft dabei `chkLogin.do` mit auf. Das
Idle-Timeout kann damit nicht mehr zuschlagen — es braucht **keinen eigenen Timer**.

Wichtig: Das normale Standort-Polling läuft über die **SmartThings**-API, nicht über die
Web-API. Es hält die Web-Session also *nicht* von allein warm; genau deshalb ist der
`chkLogin.do`-Aufruf explizit im Coordinator eingebaut.

### Wie lange hält das Cookie?

- **Idle-Timeout (30 min):** kein Thema mehr, der Keep-alive deckt es ab.
- **Absolutes Limit:** Ein hartes Limit gibt es (`extendable:false`), aber es ist lang: Mit Keep-alive
  hielt eine Session über 2 Tage. Eine früher beobachtete Laufzeit von ~21 h fiel in die Zeit ohne
  zuverlässigen Keep-alive.
- **Sicher tödlich** sind: Passwortänderung, Abmelden im Browser, und vermutlich ein Neustart
  oder Redeploy des Cluster-Nodes, auf den das `jvmRoute`-Suffix zeigt (`fmm-prd-cns-1`).

Wenn die Session stirbt, erscheint die Benachrichtigung `smartthings_find_web_session` mit dem Weg
zum neuen Cookie, und ein Klingelversuch meldet den Grund direkt. SmartTags klingeln davon unberührt weiter.

## Was NICHT funktioniert (alles verifiziert, nicht vermutet)

### Web-Session aus Account-Cookies minten (Browser-SSO) — unmöglich (2026-09-25)

Zweiter Anlauf, diesmal über den **Browser-Login-Endpoint** (`account.samsung.com/iam`, nicht die
tote Token-API `/auth/oauth2/v2`). Idee: Die langlebigen Account-Cookies (`sa_id`/`sa_state`) aus
dem eingeloggten Browser leihen und damit still eine neue STF-`JSESSIONID` erzeugen.

Endgültig **serverseitig gesperrt** — es liegt nicht an den Cookies. `GET /api/v1/configurations/ntly6zvfpn`
(mit gültigen Account-Cookies, 200) liefert für den STF-Web-Client:
```
sessions: { ssoDisabled: true, bypassable: false, extendable: false }
```
Damit ist SSO/Session-Bypass für genau diesen OAuth-Client per Policy verboten. Folgerichtig:
`POST /api/auths` legt zwar einen Auth-Kontext an (201 + `key`), aber `GET /api/auths/{key}`
antwortet `{"page":"password"}` — **jede** neue Autorisierung erzwingt interaktiv Passwort (+ ggf. 2FA).
Das erklärt auch, warum die STF-Session nach ~24 h stirbt und sich nicht still erneuern lässt:
`extendable:false` = hartes Session-Limit ohne Verlängerung.

Getestet mit den echten, frisch aus dem Browser (Vivaldi/KWallet, Key = „Chrome Safe Storage")
entschlüsselten Account-Cookies. Der Browser-eigene STF-`JSESSIONID` war zu dem Zeitpunkt übrigens
**derselbe tote** wie in HA (gleicher Hash) — der Browser hatte die Session also auch nicht erneuert.

→ Kein still-automatisierbarer Weg. Bleibt nur: manuell Cookie einfügen, ODER ein echter Browser,
der **interaktiv mit Passwort** neu einloggt (Variante 2, hoher Aufwand, 2FA evtl. per Trusted Device
gecacht) und die frische `JSESSIONID` per HA-API einschiebt.

### Web-Session automatisch erzeugen (Token-API) — unmöglich

Der naheliegende Wunsch: Session aus dem gespeicherten Master-Token (`userauth_token`) minten,
dann braucht es kein manuelles Cookie. Das geht nicht, und zwar strukturell:

- Das Browser-Frontend holt seinen Code über
  `samsung.account.signIn({clientId:"ntly6zvfpn", redirectUri:"<base>/login.do", …})` —
  der Code ist also an `redirect_uri=<base>/login.do` **gebunden**.
- `login.do` löst **nur** so gebundene Codes ein.
- `/auth/oauth2/v2/authorize` lehnt `redirect_uri` seinerseits mit
  **HTTP 400 `unauthorized_client`** ab.

Browser- und Headless-Flow erzeugen damit **inkompatible Codes**, und die Lücke lässt sich
nicht schließen. Der Headless-Weg funktionierte bis ca. 17.09.2026 22:05 und wurde danach
serverseitig dichtgemacht.

Besonders tückisch: Der tote Weg **sieht aus wie Erfolg**. `authorize` liefert einen gültigen
Code, `login.do` antwortet **302** wie bei einer echten Anmeldung und rotiert sogar die
`JSESSIONID`. Erst `chkLogin.do` verrät mit Body `fail` und fehlendem `_csrf`-Header, dass die
Session nie authentifiziert wurde. Ein Statuscode-basierter Check läuft hier ins Leere.

`check_web_ring.py` erzwingt deshalb, dass dieser Pfad nicht zurückkehrt.

### Ausgeschlossene Ursachen

Diese wurden alle einzeln geprüft und sind **nicht** die Erklärung:

| Vermutung | Befund |
|---|---|
| Toter Master-Token (`AUT_1302`) | Nein — `authorize` liefert einen Code, der Token lebt |
| Fehlender Master-Token | Nein — alle Felder im Config-Entry vorhanden |
| `privacyAccepted=N` | Nein — steht genauso beim ONECONNECT-Client, über den Tags **erfolgreich** klingeln |
| Rate-Limit / Lockout auf `login.do` | Nein — Fehler ist nach >12 h deterministisch reproduzierbar; ein Limit wäre sprunghaft |
| HA-/aiohttp-Bug, Cookie-Jar | Nein — außerhalb von HA mit reiner `urllib` identisch reproduziert |
| Falsch durchgereichter `state` | Nein — Server gibt den `state` unverändert zurück |
| Fehlendes `redirect_uri` | Ja, ursächlich — aber nicht behebbar (siehe oben) |

### uTag löst es nicht

uTag (KieronQuinn) ist eine **SmartTag**-App und klingelt Handy/Kopfhörer überhaupt nicht.
Die einzige Ring-Operation im gesamten uTag-Wiki ist `Set Tag Ringing` → exakt der
`/trackerapi`-Endpoint, den diese Integration für Tags ohnehin benutzt. `Get Devices` liest
FMM-Infos nur aus.

Der dort erwähnte Direktweg `client.smartthings.com/chaser/...` hilft ebenfalls nicht: er
braucht ein Zertifikat aus `libfmm_ct.so`, erzeugbar nur auf einem Android-Gerät mit
umgangenen Integritätschecks (Paketname `com.samsung.android.fmm`, Shared-User-ID
`android.uid.system`). Aus Home Assistant heraus nicht machbar.

### SmartThings-Proxy kann keine Handys klingeln

`installedapps/{id}/execute` hat nur `/devices` (GET) und `/trackerapi` in der URI-Whitelist.
Alles andere → `invalid-uri-method`. Es gibt dort **keinen** FMM-Pfad.

## Eigenheiten der Web-API

- `chkLogin.do` liefert `_csrf` im **Response-Header**, nicht im Body. Der Body ist nur
  `success` bzw. `fail`.
- Eine abgelaufene Session antwortet mit **HTTP 200** und Body `fail` — *nicht* mit 401/403.
  Eine Retry-Logik, die auf Statuscodes schaut, löst niemals aus.
- `getDeviceList.do` ist **POST-only**; ein GET liefert 404.
- Die Web-API nutzt **eigene numerische Geräte-IDs**, nicht die SmartThings-UUIDs.
- `modelName` enthält den **benutzervergebenen Namen**, `nickName` das Modell — ja, andersherum
  als der Name vermuten lässt.
- Gerätenamen sind **doppelt HTML-escaped** (`Alex&amp;#39;s Buds3 Pro`), daher entschlüsselt
  `_html_unescape()` mehrfach.
- Antwort auf einen Ring: `{"oprnType":"RING","reqId":…,"resultCode":"00"}` — `00` = angenommen.

## Live-Ring-Status (seit 2026-09-24)

Der Ring-Schalter zeigt bei Handy und Buds den **echten** Zustand, nicht mehr einen optimistischen.
Quelle ist `POST /dm/getOperationResult.do?_csrf=X` mit
`{"dvceId":D,"operation":["RING"],"userId":U}` (derselbe Aufruf, den das Web-Frontend nach
`addOperation` macht). Die Antwort enthält die letzte RING-Operation:

| Feld | Wert | Bedeutung |
|---|---|---|
| `oprnStsCd` | `1000` | Befehl unterwegs, Gerät hat noch nicht geantwortet (~2 s) |
| | `2800` (+ `oprnResultCode` `1200`) | Gerät hat geantwortet |
| | `2900` / `1900` | Fehler: `1452` FMM aus, `507` Telefonat, `3009` Buds werden getragen, `3008` Stop, obwohl nichts klingelt |
| `extra.status` (Handy) | `4`/`5` = klingelt, `0` = Ruhe | |
| `extra.left/right.status` (Buds) | `4`/`5` = piept, `2` = Ruhe | eine Seite reicht für „klingelt" |

Gemessen am S22 Ultra und an den Buds3 Pro:

- Start → Gerät klingelt nach **~2,5 s**, Stop → Ruhe nach **~2 s**.
- Von selbst hört das **Handy nach 60 s** auf, die **Buds nach ~188 s**. Deshalb steht
  `RING_TIMEOUT_SECONDS` auf 200.
- Tags liefern hier `"operation": []`. Ihr Schalter bleibt optimistisch und hat ein Auto-Off.
- `_csrf` bleibt über mehrere Aufrufe gültig, es muss nicht bei jedem Aufruf neu geholt werden.

Ablauf in der Integration: Der Coordinator liest bei jedem Poll (120 s) den Status mit. So fällt
auch ein Klingeln auf, das über die App oder das Web gestartet wurde. Solange ein Ring läuft
(oder ein Befehl `pending` ist), pollt der Schalter selbst alle 3 s. Die Rohcodes stehen als
Attribute `ring_status`, `operation_status_code`, `operation_result_code` und `operation_done`
am Schalter. Die Code-Zuordnung prüft `check_ring_status.py`.

## Wichtig zum Tag-Ring

`PUT /trackerapi` + `/trackers/<id>/ring` setzt bei Tags nur ein **serverseitiges Flag**. Der Tag
klingelt erst, wenn ihm ein Galaxy-Gerät per BLE nahe kommt. Ohne ein solches Gerät in Reichweite
passiert nichts — fehlerfrei und still. Das ist der Grund für „geht in der App, aber nicht im Web".
Beim Web-Weg (`addOperation.do`) gilt das ebenso für Tags; Handys klingeln dagegen sofort.

**Was die Webseite für Tags zeigt (Bundle + Live-Test am 27.09.2026):** Sie meldet nur, ob
`addOperation.do` mit `resultCode 00` angenommen wurde. Danach zeigt sie „Your %s rang."
(`success_ring_tag`), sonst „Couldn't connect to your tag to start ringing." (`error_ring_tag`).
Einen Stopp-Knopf gibt es für Tags nicht. `status:"stop"` nimmt der Server zwar mit `00` an, ein
**über die Web-API gestartetes Tag-Klingeln lässt sich aber nicht mehr stoppen**, auch nicht über
die Tracker-API (Handy lag daneben, Tag piepte weiter bis zum Knopfdruck). Wird dagegen über die
Tracker-API gestartet, klingelt der Tag sofort, und der Tracker-Stopp beendet es (live getestet am
27.09.2026, Schlüssel). Deshalb laufen Tags jetzt zuerst über die Tracker-API, die Web-API ist nur
noch Ausweichweg. `getOperationResult.do` bleibt bei Tags leer. Der Schalter ist deshalb ein normaler Toggle
(ohne `assumed_state`, sonst zeigt HA zwei Knöpfe). Er hat die Zustände `idle`, `requested` und
`error`. Das Attribut `ring_message` enthält den Seitentext auf Deutsch, bei Handy/Buds passend
zum Live-Status.
