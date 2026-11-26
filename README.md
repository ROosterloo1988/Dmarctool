# DMARC-rapportagesysteem

Leest DMARC-aggregate reports (RUA) en forensic/failure reports (RUF) in, slaat ze op in
PostgreSQL en toont de resultaten in een webinterface. Het doel is veilig naar
`p=quarantine` / `p=reject` gaan voor tenazenergy.com.

> **Status: alle 5 fases zijn gebouwd** — parser, ophalen via Graph, DNS-controle en
> verrijking, webinterface met SSO en meldingen per mail.

## Installatie (Docker-host in Azure)

1. **App-registraties en Application Gateway:** volg
   [docs/app-registratie.md](docs/app-registratie.md). Je hebt de mailbox-app (§1), de
   portal-app (§2) en de Application Gateway (§2.1) nodig.
2. **Configuratie:**
   ```bash
   cp .env.example .env
   ```
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
   Vul in `.env` in:
   - `POSTGRES_PASSWORD`;
   - de Graph-gegevens: `DMARC_GRAPH_TENANT_ID`, `DMARC_GRAPH_CLIENT_ID` en het
     certificaat (in `./secrets/`) of het secret;
   - de portal: `DMARC_SECRET_KEY` (de uitvoer van het commando hierboven),
     `DMARC_OIDC_CLIENT_ID` en `DMARC_OIDC_CLIENT_SECRET`;
   - `FORWARDED_ALLOW_IPS`: het subnet van de Application Gateway.
3. **Starten:** dit voert de migraties uit en start `api` (poort 8080), `worker` en `backup`.
   ```bash
   docker compose up -d --build
   ```
4. **Noodaccount (aanbevolen):** zo kom je ook binnen als Entra ID of de gateway niet
   werkt. Dit account staat standaard uit.
   ```bash
   docker compose run --rm cli user add noodbeheer --role admin
   ```
   Zet het alleen aan als het nodig is, met `DMARC_LOCAL_LOGIN_ENABLED=true` in `.env`,
   gevolgd door `docker compose up -d api`.
5. **Inloggen:** open https://dmarcportal.tenazenergy.com en kies **Sign in with
   Microsoft**. Daarna, onder **Settings**:
   - domein `tenazenergy.com` toevoegen;
   - het mailboxadres instellen.
6. **Meldingen instellen:** ga in de UI naar **Settings → Notifications**, vul daar de
   ontvangers in en kies **Send test mail**.
7. **Mailbox testen:**
   ```bash
   docker compose run --rm cli graph-check --other-mailbox iemand@tenazenergy.com
   ```
   Daarna in de UI: **Mail processing → Fetch mail → Run now**.

## Webinterface (fase 4)

**Inloggen:**
- Via Microsoft Entra ID (OIDC, authorization code + PKCE, alleen jullie tenant).
- De rol komt uit de app role in het token, en wordt bij elke login opnieuw gelezen:
  - **DMARC.Admin**: alles;
  - **DMARC.Viewer**: alles lezen en exporteren, behalve RUF.
- Accounts zonder rol komen niet binnen.
- Lokale noodaccounts gebruiken argon2-hashes. Na 5 foute pogingen volgt een lockout van
  15 minuten, en er geldt een rate-limit per IP.

**Pagina's:**

| Pagina | Inhoud |
|---|---|
| Dashboard | Volume, % DMARC-pass, SPF/DKIM-alignment, trend per dag (grafiek of tabel), "Ready for p=reject?" met de volgende DNS-stap, top-aanbevelingen, top-bronnen |
| Sending sources | Per provider/ASN: volume, aandeel, pass- en alignment-%, IP's, bounce- en DKIM-domeinen, selectors. Admins markeren hier legitiem/onbekend/misbruik met een notitie. CSV-export |
| Recommendations | Alle aanbevelingen in gewone taal |
| DNS check | Het DMARC-record, de SPF-boom met lookup-telling, DKIM-selectors met sleutellengte, alle bevindingen met de oplossing, en "Check now" |
| Records | Filters op domein, periode, rapporteur, resultaat, disposition, IP en bron; detail per record met SPF/DKIM-resultaten; CSV-export (max. 200.000 rijen) |
| Reports | Rapporten per rapporteur, met detail en download van de originele XML |
| IP detail | PTR (met forward-confirmatie), ASN, land, herkende verzender, en of het IP in jullie huidige SPF staat |
| Failure reports | RUF, alleen voor admins. Elke keer dat iemand er een bekijkt, komt dat in het auditlog |
| Mail processing | Status van de worker-jobs met "Run now", en alle verwerkte mail met de problemen bovenaan |
| Settings | Domeinen beheren (ook "parked"), en mailboxadres, mappen en interval wijzigen |
| Users & audit | Gebruikers uitschakelen, rollen van lokale accounts, en het auditlog (logins, wijzigingen, exports) |

**Beveiliging:**
- Sessiecookie: HttpOnly, Secure, SameSite=Lax, 8 uur geldig.
- CSRF-token op alle wijzigende verzoeken.
- Strikte Content-Security-Policy, X-Frame-Options en HSTS.
- CSV-cellen worden beschermd tegen formula-injectie.
- XML-downloads gaan als bijlage met `nosniff`.
- Secrets staan alleen in de environment.

**Lokaal proberen zonder Entra ID:**

```bash
docker compose run --rm cli user add admin --role admin
```

Zet in `.env` `DMARC_LOCAL_LOGIN_ENABLED=true` en `DMARC_COOKIE_SECURE=false`. Daarna:

```bash
docker compose up -d
```

Open http://localhost:8080.

**Frontend ontwikkelen:** dit gebruikt een Vite-devserver die `/api` doorstuurt naar
poort 8080.

```bash
cd frontend && npm install && npm run dev
```

## Meldingen per mail (fase 5)

De job `alerts` draait elk kwartier en verstuurt de mail via Graph vanuit de DMARC-mailbox
(`Mail.Send`).

| Wat | Wanneer |
|---|---|
| Nieuwe DNS-**fout**, bijvoorbeeld een tweede DMARC-record, SPF met meer dan 10 lookups of een te korte DKIM-sleutel | **Direct** |
| Nieuwe DNS-waarschuwing | Dagelijkse samenvatting |
| Opgelost DNS-probleem | Dagelijkse samenvatting |
| Nieuwe onbekende verzender. Voorwaarden: eerste keer gezien in de laatste 7 dagen, niet herkend en niet geclassificeerd, en minimaal *N* berichten (standaard 50) | Dagelijkse samenvatting |
| Daling van het DMARC-pass-percentage: de laatste 7 dagen tegenover de 7 dagen ervoor, met ≥ *X* procentpunt (standaard 5). Bronnen die als misbruik zijn gemarkeerd tellen niet mee | Dagelijkse samenvatting, hooguit wekelijks |

**Instellen:** onder Settings → Notifications in de UI stel je in:
- de ontvangers;
- aan/uit;
- het uur van de samenvatting (standaard 06:00 UTC);
- de drempels.

Daar staat ook de knop **Send test mail** en de lijst met recent verstuurde meldingen.

**Hoe het werkt:**
- Elk probleem wordt één keer gemeld, tot het is opgelost (tabel `alert_state`).
- Mislukt het versturen, dan wordt het de volgende run opnieuw geprobeerd.
- Staan meldingen uit, dan wordt er wel gedetecteerd. Er gaat dus niets verloren als je ze
  later aanzet.

## Ophalen van mail (fase 2)

- **Worker:** de `worker`-container leest elke `mailbox.poll_minutes` minuten (standaard
  15) de map `mailbox.source_folder` (standaard `Inbox`). Hij verwerkt de oudste mail eerst,
  maximaal `mailbox.batch_size` berichten per run.
- **Verplaatsen:** na het opslaan (commit) gaat de mail naar **Verwerkt** (status
  processed/duplicate) of naar **Fout** (partial/failed). De mappen worden automatisch
  aangemaakt. Paden zoals `Inbox/DMARC/Verwerkt` kunnen ook. Mail wordt nooit verwijderd.
- **Mislukt verplaatsen:** dan staat het resultaat al in de database. De volgende run
  herkent de mail en probeert alleen het verplaatsen opnieuw, zonder hem opnieuw te
  verwerken.
- **Netwerk- of throttlingfout bij het downloaden:** de mail blijft staan en gaat de
  volgende run opnieuw mee. Graph-throttling (429/503) wordt opnieuw geprobeerd, met
  respect voor `Retry-After`.
- **Te grote mail** (`DMARC_MAX_MESSAGE_BYTES`) gaat naar **Fout** en wordt gelogd.
- **Één actieve worker:** er draait altijd maar één actieve worker, via een PostgreSQL
  advisory lock. Een tweede instantie wacht als standby.
- **Runs in `job_run`:** elke run wordt vastgelegd in `job_run`, met tellingen of een
  foutmelding, voor de UI. In de UI start je een job direct met "Run now" (Mail processing); op de CLI met `dmarc queue fetch`. Dat
  wordt straks de knop "Nu ophalen" in de UI.
- **Retentie:** dagelijks na `DMARC_PURGE_HOUR_UTC` (standaard 03:00 UTC) draait de purge
  volgens de bewaartermijnen.

## DNS-controle, verrijking en aanbevelingen (fase 3)

**DNS-controle** (job `dnscheck`, elk uur) voor elk domein in `dmarc domain list`:
- **DMARC:**
  - precies één geldig record; meerdere records is een fout, want dan wordt DMARC genegeerd;
  - syntax en waarden van `p`, `sp`, `np`, `pct`, `adkim`, `aspf`, `fo`, `rua` en `ruf`;
  - overerving van het organisatiedomein;
  - de *external destination verification* als `rua`/`ruf` naar een ander domein wijzen.
- **SPF:**
  - precies één record, en de syntax;
  - het aantal DNS-lookups (maximaal 10) en het aantal void lookups (maximaal 2);
  - waarschuwingen bij `+all`, `?all`, een ontbrekende `all`, `ptr` en include-loops;
  - de volledige include-boom wordt opgeslagen, zodat we offline kunnen bepalen of een IP
    geautoriseerd is.
- **DKIM:**
  - de selectors die in de rapporten van de laatste 30 dagen voorkomen, ook op subdomeinen;
  - de sleutellengte: een waarschuwing onder 2048 bit en een fout onder 1024 bit;
  - ingetrokken sleutels en `t=y`.
- **Geparkeerde domeinen** (`dmarc domain add x --parked`): advies voor `v=spf1 -all`,
  `p=reject` en een null-MX.

**Verrijking** (job `enrich`, elk kwartier):
- **Reverse DNS**, forward-confirmed. Een PTR telt alleen als de naam terug resolvet naar
  hetzelfde IP; zo kan een spoofer zich niet "Flowmailer" noemen.
- **ASN, provider en land** uit **DB-IP Lite**. Die database downloadt de worker zelf en
  houdt hij maandelijks actueel. De licentie is CC BY 4.0, dus de UI vermeldt "IP data by
  DB-IP". Liever MaxMind GeoLite2? Zet dan `DMARC_GEOIP_ASN_PATH` en
  `DMARC_GEOIP_COUNTRY_PATH` op die `.mmdb`-bestanden.
- **Herkenning van bekende verzenders** via `backend/dmarc/senders.yaml`: Microsoft 365,
  Google Workspace, Flowmailer, Mailchimp/Mandrill, SendGrid, Mailgun, Amazon SES,
  Postmark, Brevo, HubSpot, Salesforce MC, Zendesk en Mimecast. De herkenning gaat op
  PTR, DKIM-domein, bounce-domein en (alleen waar het eenduidig is) ASN.
- **Eigen verzenders toevoegen:** maak een eigen YAML-bestand en wijs het aan met
  `DMARC_SENDERS_CATALOG_PATH`. Draai daarna `dmarc enrich --reassign`.
- **Elke record krijgt een bron:** `sender:<naam>`, `asn:<nummer>` of `ip:<adres>`.
- **Dagtotalen per domein en bron** (`daily_stat`) voor de trendgrafieken. Die blijven ook
  na de purge van de details (2 jaar) bewaard.

**Analyse** (`dmarc analyze tenazenergy.com`, straks het dashboard):
- **Overzicht per bron:** volume, % DMARC-pass, SPF- en DKIM-pass, alignment, gebruikte
  bounce- en DKIM-domeinen en selectors.
- **Aanbevelingen in gewone taal.** Voorbeelden:
  - *"Flowmailer sends ~1,200 mails/week on behalf of tenazenergy.com; 100% fails DMARC —
    DKIM is signed with flowmailer.net instead of your own domain … → Set up DKIM with your
    own domain: …"*
  - *"Add include:spf.protection.outlook.com to the SPF record"*, met een waarschuwing als
    je al dicht bij de 10 lookups zit.
  - *"There are 2 DMARC records … Remove all but one"*
  - onbekende bronnen met veel falende mail, die je zelf als legitiem, onbekend of misbruik
    markeert.
- **"Klaar voor p=reject"-indicator** (`ready`, `almost` of `not_ready`). Dat is gebaseerd
  op zes criteria:
  - geldige DMARC;
  - `rua` aanwezig;
  - geldige SPF;
  - minimaal 14 dagen data;
  - ≥ 98% pass voor legitieme mail;
  - geen legitieme verzender met significante fouten.

  De indicator geeft ook de volgende stap als concrete DNS-waarde:
  `p=none` → `p=quarantine; pct=25` → `pct=100` → `p=reject`.
- **Wat telt als legitiem:** bronnen die je als legitiem hebt gemarkeerd, plus
  ongemarkeerde bronnen die herkend zijn of die meestal slagen. Bronnen die je als misbruik
  markeert tellen niet mee, en doorgestuurde of mailinglijst-mail ook niet.

Classificeren gaat straks in de UI; nu via de CLI:

```bash
docker compose run --rm cli classify tenazenergy.com sender:flowmailer legit --note "Facturen"
```

**Netwerk vanaf de Docker-host:** DNS naar de resolver (standaard de resolver van de host,
of `DMARC_DNS_NAMESERVERS`) en HTTPS naar `download.db-ip.com`.

## Instellingen die je tijdens bedrijf kunt wijzigen

Het mailboxadres, de mappen, het interval, de batchgrootte en aan/uit staan in de database.
In fase 4 kun je ze wijzigen in de UI; tot dan via de CLI:

```bash
docker compose run --rm cli settings
```

```bash
docker compose run --rm cli settings set mailbox.poll_minutes 30
```

```bash
docker compose run --rm cli settings reset mailbox.poll_minutes
```

Een waarde in de database gaat vóór de `DMARC_MAILBOX_*`-variabele uit `.env`. Secrets
(client secret, certificaat) staan bewust alleen in de environment, nooit in de database.

> **Let op:** wijzig je het mailboxadres, pas dan eerst de Exchange-scope aan
> (zie [docs/app-registratie.md §1.4](docs/app-registratie.md)).

## Wat werkt nu

- Uitpakken van `.xml`, `.xml.gz`, `.zip` (ook meerdere bestanden, en een `.gz` in een zip)
  en XML inline in de mailbody. De herkenning gaat op inhoud, niet op bestandsnaam of
  content-type.
- Een RUA-parser volgens RFC 7489, tolerant voor DMARCbis (namespace, `np`, `testing`,
  `generator`) en voor afwijkingen per rapporteur: verkeerde encoding-declaratie, spaties,
  hoofdletters, ISO-datums, IPv4-mapped IPv6, ontbrekende `header_from` en een extra
  wrapper-element.
- **Eigen berekening van SPF- en DKIM-alignment** (relaxed/strict, op basis van de
  meegeleverde Public Suffix List). Een SPF-pass op HELO-scope telt niet mee.
- Een RUF-parser voor ARF (RFC 5965/6591), met `message/rfc822`, `text/rfc822-headers` en
  base64-gecodeerde onderdelen.
- **Privacy:** van RUF slaan we standaard alleen de headers op, geen body. De standaard
  bewaartermijn is 30 dagen.
- **Idempotent:** de sleutel is `org_name + report_id + domain`. Een RUF-rapport wordt
  herkend aan een fingerprint.
- **Robuust:** elk rapport wordt in een eigen savepoint opgeslagen. Elke mail krijgt een
  logregel in `inbound_message` met status `processed`, `duplicate`, `partial` of `failed`
  en de foutmeldingen.
- **Veiligheid:**
  - XML lezen we met `defusedxml`, dus XXE en entity expansion worden geweigerd.
  - Bij het uitpakken gelden limieten voor de grootte per bestand en in totaal, het aantal
    bestanden, de compressieverhouding en de nesting. Daarmee worden zip- en gzip-bombs
    afgewezen.
  - Er wordt niets naar schijf geschreven en niets uitgevoerd.

## Lokaal testen

### Met Docker

```bash
cp .env.example .env        # zet POSTGRES_PASSWORD
docker compose up -d db
docker compose run --rm cli migrate
docker compose run --rm --entrypoint pytest cli -q   # incl. tests tegen een nagebootste Graph
```

Eigen rapporten importeren: zet `.eml`-, `.xml`-, `.gz`- of `.zip`-bestanden in `./import`
en voer uit:

```bash
docker compose run --rm cli import /import
docker compose run --rm cli parse /import/bestand.eml   # alleen tonen, niets opslaan
```

Een `.eml` exporteer je uit Outlook door de mail naar een map te slepen, of via
"Opslaan als".

### Zonder Docker (Python 3.12+)

```bash
python -m venv .venv && .venv/bin/pip install -e 'backend[dev]'
cd backend
../.venv/bin/pytest -q                       # parsertests; databasetests worden overgeslagen
DMARC_TEST_DATABASE_URL=postgresql+psycopg://dmarc:PASS@localhost:5432/dmarc_test ../.venv/bin/pytest -q
```

**Let op:** de testsuite wist het schema van `DMARC_TEST_DATABASE_URL`. Gebruik daarvoor
nooit de productiedatabase.

### CLI

| Commando | Doel |
|---|---|
| `dmarc parse <bestanden/mappen>` | Parsen en als JSON tonen, zonder database |
| `dmarc import <bestanden/mappen>` | Importeren in de database |
| `dmarc migrate` | Databasemigraties uitvoeren (Alembic) |
| `dmarc domain add tenazenergy.com [--parked]` | Domein toevoegen dat bewaakt wordt |
| `dmarc purge` | RUF en oude RUA verwijderen volgens de bewaartermijn |
| `dmarc settings [set\|reset] [key] [value]` | Instellingen tonen of wijzigen (mailbox, mappen, interval) |
| `dmarc graph-check [--other-mailbox x]` | App-registratie en mailboxrechten stap voor stap controleren |
| `dmarc fetch` | Eén keer direct mail ophalen, buiten de worker om |
| `dmarc queue fetch\|enrich\|dnscheck\|geoip\|purge\|alerts` | De draaiende worker vragen om een job direct uit te voeren |
| `dmarc worker` | De worker starten (doet de `worker`-container) |
| `dmarc dns-check [--domain x --selector s]` | DNS-controle van alle domeinen, of ad hoc van één domein |
| `dmarc enrich [--reassign]` | PTR/ASN ophalen, bronnen toekennen, dagtotalen herberekenen |
| `dmarc geoip-update` | DB-IP Lite direct downloaden |
| `dmarc analyze <domein> [--days n] [--json]` | Bronnen, aanbevelingen en p=reject-indicator |
| `dmarc classify <domein> <bron> legit\|unknown\|abuse` | Een bron markeren |
| `dmarc user list\|add\|password\|disable\|enable [naam] [--role]` | Lokale noodaccounts beheren |
| `dmarc api [--port 8080]` | De webinterface/API starten (doet de `api`-container) |

## Configuratie

Alle instellingen gaan via environment variables met de prefix `DMARC_`, zie `.env.example`.
Secrets staan nooit in de code.

## Datamodel

- **`inbound_message`**: elke verwerkte mail of elk verwerkt bestand, met status en fouten.
- **`aggregate_report`**: metadata en de gepubliceerde policy. De ruwe XML staat
  gzip-gecomprimeerd in de database, zodat we opnieuw kunnen parsen. Er geldt een
  unieke sleutel op `org_name + report_id + domain`.
- **`aggregate_record`**: bron-IP, aantal, disposition, `header_from`, `envelope_from` en
  `envelope_to`, plus de alignment- en pass-velden.
- **`auth_result`**: per SPF- of DKIM-uitslag het domein, de selector of scope, het resultaat
  en of de uitslag aligned is.
- **`forensic_report`**: de ARF-velden en headers. De body staat er alleen in als die
  instelling aan staat. Elk rapport heeft een `expires_at` voor het opschonen.
- **`domain`**: de eigen domeinen die bewaakt worden.
- **`app_setting`**: instellingen die je tijdens bedrijf kunt wijzigen, met wie ze wanneer
  heeft gewijzigd.
- **`job_run`**: de geschiedenis van de worker-jobs en de wachtrij voor "nu uitvoeren".
- **`inbound_message.moved_to` / `move_error`**: naar welke map de mail is verplaatst, of
  waarom dat niet lukte.
- **`aggregate_record.source_key`**: de toegekende bron: `sender:<x>`, `asn:<n>` of `ip:<a>`.
- **`ip_info`**: PTR (met een vlag of hij forward-confirmed is), ASN, provider, land en de
  herkende verzender.
- **`dns_check`**: de geschiedenis van de DNS-controles, met het volledige resultaat
  (inclusief de SPF-boom) en de bevindingen.
- **`daily_stat`**: dagtotalen per domein en bron.
- **`source_classification`**: legitiem, onbekend of misbruik per domein en bron.
- **`app_user`**: Entra ID-gebruikers (aangemaakt bij de eerste login) en lokale
  noodaccounts.
- **`audit_log`**: wie wat wanneer deed: logins, mislukte logins, classificaties,
  instellingen, exports en het inzien van RUF.
- **`alert_state`**: welke problemen al gemeld zijn en of ze opgelost zijn.
- **`alert_event`**: de meldingen en hun verzendstatus.

## Testfixtures

`backend/tests/fixtures/src/*.xml` zijn geanonimiseerde rapporten in de vorm van Google,
Microsoft, Yahoo, Mail.ru, DMARCbis en een "quirky" rapporteur. Ze gebruiken
voorbeelddomeinen en documentatie-IP's. Uit deze bronnen genereert
`build_fixtures.py` de `.eml`-, `.gz`- en `.zip`-varianten, de kapotte varianten en de
RUF-fixtures:

```bash
cd backend && python tests/fixtures/build_fixtures.py
```

Zip- en gzip-bombs worden in de tests zelf gegenereerd.

## Backup

- **Wat:** de `backup`-container maakt dagelijks na `BACKUP_HOUR_UTC` (standaard 02:00 UTC)
  een `pg_dump` in custom-formaat.
- **Waar:** de dumps staan in `BACKUP_DIR` (standaard `./backups`) en worden
  `BACKUP_KEEP_DAYS` dagen bewaard (standaard 14).
- **Buiten de host:** neem die map mee in de Azure-backup, of mount er een Azure Files-share
  op.

Direct een backup maken:

```bash
docker compose run --rm --entrypoint /bin/sh backup /backup.sh now
```

Terugzetten, met de worker gestopt:

```bash
docker compose stop worker
```

```bash
docker compose exec -T db pg_restore -U dmarc -d dmarc --clean --if-exists < backups/dmarc-YYYYMMDDTHHMMSSZ.dump
```

```bash
docker compose start worker
```

Bewaar daarnaast `.env` en `secrets/` op een veilige plek, bijvoorbeeld in Azure Key Vault.
Die zitten niet in de databasedump.
