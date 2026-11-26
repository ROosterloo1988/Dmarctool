# DMARC-rapportagesysteem

Leest DMARC-aggregate reports (RUA) en forensic/failure reports (RUF) in, slaat ze op in
PostgreSQL en toont de resultaten in een webinterface. Het doel is veilig naar
`p=quarantine` / `p=reject` gaan voor tenazenergy.com.

> **Status: fase 2 van 5 — parser, opslag en ophalen van mail via Microsoft Graph.**
> DNS-controle en verrijking (fase 3), UI met SSO (fase 4) en meldingen (fase 5) volgen.

## Installatie (Docker-host in Azure)

1. **App-registratie:** volg [docs/app-registratie.md](docs/app-registratie.md).
2. **Configuratie:**
   ```bash
   cp .env.example .env
   ```
   Vul in `.env` in: `POSTGRES_PASSWORD`, `DMARC_GRAPH_TENANT_ID`, `DMARC_GRAPH_CLIENT_ID`
   en het certificaat (in `./secrets/`) of het secret.
3. **Starten:** dit voert de migraties uit en start de worker en de backup-container.
   ```bash
   docker compose up -d --build
   ```
4. **Mailbox instellen en testen:**
   ```bash
   docker compose run --rm cli settings set mailbox.address dmarc@tenazenergy.com
   ```
   ```bash
   docker compose run --rm cli graph-check --other-mailbox iemand@tenazenergy.com
   ```
   ```bash
   docker compose run --rm cli queue fetch
   ```
   ```bash
   docker compose logs -f worker
   ```

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
  foutmelding, voor de UI. `dmarc queue fetch` vraagt de worker om direct te draaien; dat
  wordt straks de knop "Nu ophalen" in de UI.
- **Retentie:** dagelijks na `DMARC_PURGE_HOUR_UTC` (standaard 03:00 UTC) draait de purge
  volgens de bewaartermijnen.

### Instellingen die je tijdens bedrijf kunt wijzigen

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
| `dmarc queue fetch\|purge` | De draaiende worker vragen om een job direct uit te voeren |
| `dmarc worker` | De worker starten (doet de `worker`-container) |

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
