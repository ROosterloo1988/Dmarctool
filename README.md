# DMARC-rapportagesysteem

Leest DMARC-aggregate reports (RUA) en forensic/failure reports (RUF) in, slaat ze op in
PostgreSQL en toont de resultaten in een webinterface. Het doel is veilig naar
`p=quarantine` / `p=reject` gaan voor tenazenergy.com.

> **Status: fase 1 van 5 — parser + opslag.** Ophalen via Microsoft Graph (fase 2),
> DNS-controle en verrijking (fase 3), UI met SSO (fase 4) en meldingen (fase 5) volgen.

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
docker compose run --rm --entrypoint pytest cli -q
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

## Configuratie

Alle instellingen gaan via environment variables met de prefix `DMARC_`, zie `.env.example`.
Secrets staan nooit in de code.

## Datamodel (fase 1)

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

Volgt in fase 2 (een `backup`-container met dagelijkse `pg_dump`). Tot die tijd:

```bash
docker compose exec db pg_dump -U dmarc -Fc dmarc > backup.dump
```
