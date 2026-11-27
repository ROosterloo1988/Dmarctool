# App-registraties in Entra ID

Het systeem heeft **twee** app-registraties nodig. Houd ze gescheiden, zodat het
inlogportaal nooit rechten op de mailbox heeft.

| App | Doel | Nodig vanaf |
|---|---|---|
| **DMARC-rapportage (mailbox)** | De worker leest de gedeelde mailbox, verplaatst mail en verstuurt meldingen | Fase 2 (nu) |
| **DMARC-rapportage (portal)** | SSO-inlog voor de webinterface, met de rollen Admin en Viewer | Fase 4 |

---

## 1. Mailbox-app (fase 2)

Mailtoegang voor de app beperken we via **Exchange Online RBAC for Applications**. Daarmee
kan de app alleen de DMARC-mailbox lezen en geen andere mailboxen. Microsoft raadt dit aan;
het vervangt de oudere Application Access Policies.

> ⚠️ **Ken in Entra ID géén `Mail.ReadWrite`- of `Mail.Send`-applicatierechten toe.** Rechten
> die je in Entra toekent, gelden voor *alle* mailboxen in de tenant en gaan bovenop de
> beperking in Exchange. Bij RBAC for Applications ken je de rechten alleen in Exchange toe.

### 1.1 App-registratie aanmaken

1. Ga naar het **Microsoft Entra admin center** en kies **Identity → Applications → App
   registrations → New registration**.
2. Vul het formulier zo in:

   | Veld | Waarde |
   |---|---|
   | Name | `DMARC-rapportage (mailbox)` |
   | Supported account types | *Accounts in this organizational directory only (Single tenant)* |
   | Redirect URI | leeg laten |

3. Kies **Register** en noteer op de overzichtspagina:
   - **Application (client) ID**. Dit wordt `DMARC_GRAPH_CLIENT_ID`.
   - **Directory (tenant) ID**. Dit wordt `DMARC_GRAPH_TENANT_ID`.
4. Ga naar **API permissions**. Je mag de standaardpermissie `User.Read` (delegated)
   verwijderen, want die is niet nodig. Voeg niets toe.

### 1.2 Credential: certificaat (aanbevolen) of client secret

**Certificaat.** Maak het aan op de Docker-host, in de projectmap:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes -keyout key.pem -out cert.pem -subj "/CN=dmarc-graph"
```

```bash
cat key.pem cert.pem > secrets/graph-cert.pem && chmod 600 secrets/graph-cert.pem && rm key.pem
```

Upload daarna in de app-registratie via **Certificates & secrets → Certificates → Upload
certificate** het bestand `cert.pem`. Dat bevat alleen de publieke sleutel. In `.env` zet je:

```
DMARC_GRAPH_CERTIFICATE_PATH=/run/secrets/dmarc/graph-cert.pem
```

**Alternatief: client secret.** Kies **Certificates & secrets → Client secrets → New client
secret**, met een geldigheid van maximaal 24 maanden. Kopieer de **Value** (niet het
Secret ID) naar `DMARC_GRAPH_CLIENT_SECRET` in `.env`.

> Zet een herinnering in de agenda voor de verloopdatum. Daarna stopt het ophalen van mail.
> In de UI tonen we dat straks als fout bij de laatste run.

### 1.3 Toegang tot de gedeelde mailbox (Exchange Online PowerShell)

Dit voert een Exchange-beheerder uit. Vervang `dmarc@example.com` door het echte adres.

```powershell
Connect-ExchangeOnline

$AppId   = "<Application (client) ID>"
$Mailbox = "dmarc@example.com"

# Object ID van de *Enterprise application* (service principal), NIET die van de app-registratie!
# Te vinden onder Entra -> Enterprise applications -> DMARC-rapportage (mailbox) -> Object ID.
$SpObjectId = "<Object ID van de Enterprise application>"

New-ServicePrincipal -AppId $AppId -ObjectId $SpObjectId -DisplayName "DMARC-rapportage (mailbox)"

New-ManagementScope -Name "DMARC mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$Mailbox'"

New-ManagementRoleAssignment -App $AppId -Role "Application Mail.ReadWrite" -CustomResourceScope "DMARC mailbox"
New-ManagementRoleAssignment -App $AppId -Role "Application Mail.Send"      -CustomResourceScope "DMARC mailbox"

# Controle: InScope moet True zijn voor de DMARC-mailbox...
Test-ServicePrincipalAuthorization -Identity $AppId -Resource $Mailbox | Format-Table
# ...en False voor een willekeurige andere mailbox:
Test-ServicePrincipalAuthorization -Identity $AppId -Resource "iemand@example.com" | Format-Table
```

Het kan 30 minuten tot 2 uur duren voordat de rechten actief zijn.

- **`Mail.ReadWrite`** is nodig voor het lezen van mail, het aanmaken van de mappen
  "Verwerkt" en "Fout" en het verplaatsen van mail. Mail wordt nooit verwijderd.
- **`Mail.Send`** is nodig voor de meldingen in fase 5, die vanuit de DMARC-mailbox worden
  verstuurd.

### 1.4 Later een andere mailbox gebruiken

Je kunt het mailboxadres in de UI wijzigen (setting `mailbox.address`). Pas dan **eerst**
de scope in Exchange aan, anders krijgt de worker een 403-fout:

```powershell
Set-ManagementScope -Identity "DMARC mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'nieuw-adres@example.com'"
```

### 1.5 Configureren en testen

Netwerk: de Docker-host moet uitgaand HTTPS (443) kunnen maken naar
`login.microsoftonline.com` en `graph.microsoft.com`.

**In het portaal (aanbevolen):** ga naar **Settings → Microsoft 365 connection** en vul in:
- **Directory (tenant) ID**;
- **Application (client) ID**;
- **Client secret**: plak de *Value* van het secret.

Hoe het secret wordt bewaard:
- versleuteld in de database, met een sleutel die is afgeleid van `DMARC_SECRET_KEY`;
- het is daarna voor niemand meer zichtbaar, ook niet voor beheerders;
- vervangen of verwijderen kan wel;
- wijzigingen werken direct, zonder herstart.

Daarna:
- vul onder **Mailbox** het adres van de gedeelde mailbox in;
- kies **Test connection**.

> Verander je `DMARC_SECRET_KEY`, dan kan het opgeslagen secret niet meer ontsleuteld worden.
> Het portaal meldt dat; vul het secret dan opnieuw in.

**Alternatief: via `.env`.** Zet `DMARC_GRAPH_TENANT_ID` en `DMARC_GRAPH_CLIENT_ID`, plus
`DMARC_GRAPH_CERTIFICATE_PATH` of `DMARC_GRAPH_CLIENT_SECRET`, en voer `docker compose up -d`
uit (niet `restart`).
- Waarden in het portaal gaan vóór `.env`.
- Volgorde van de credential: secret uit het portaal, dan het certificaat uit `.env`, dan
  het secret uit `.env`.
- Het secret kan ook via de CLI, zonder dat het in de shell-history komt:
  `docker compose run --rm -T cli graph-secret set < bestand-met-secret`.

Controle via de CLI:

```bash
docker compose run --rm cli graph-check --other-mailbox iemand@example.com
```

Verwachte uitvoer:

```
[ OK ] access token obtained (credential from: portal)
[ OK ] read access to 'Inbox' in dmarc@example.com (10+ messages waiting)
[ -- ] folder 'Verwerkt' does not exist yet; it is created on the first fetch
[ -- ] folder 'Fout' does not exist yet; it is created on the first fetch
[ OK ] no access to iemand@example.com (access is correctly restricted)
```

| Melding | Oorzaak |
|---|---|
| `AADSTS7000215` / `invalid_client` | Verkeerd secret: je hebt het Secret ID gebruikt in plaats van de Value, of het secret is verlopen |
| `AADSTS700027` | Het certificaat is niet (of een ander certificaat is) geüpload naar de app-registratie |
| `403 ErrorAccessDenied` | De scope of rol uit stap 1.3 ontbreekt of is nog niet actief. Wacht dan maximaal 2 uur |
| `[WARN] the app can ALSO read ...` | Er zijn in Entra toch `Mail.*`-applicatierechten toegekend. Verwijder die |

---

## 2. Portal-app voor SSO

1. Kies **App registrations → New registration** en vul in:

   | Veld | Waarde |
   |---|---|
   | Name | `DMARC-rapportage (portal)` |
   | Supported account types | Single tenant |
   | Redirect URI | platform **Web**, `https://dmarc.example.com/auth/callback` |

   Bij **Authentication** zet je de *Front-channel logout URL* op
   `https://dmarc.example.com/auth/logged-out`. Laat *Access tokens* en *ID tokens*
   (implicit grant) **uit**: de portal gebruikt de authorization-code flow met PKCE.

2. Ga naar **Certificates & secrets** en maak een **client secret** aan. De waarde wordt
   straks `DMARC_OIDC_CLIENT_SECRET`.
3. Maak onder **App roles → Create app role** twee rollen aan, beide met *Allowed member
   types*: **Users/Groups**:

   | Display name | Value | Description |
   |---|---|---|
   | DMARC Admin | `DMARC.Admin` | Beheer: bronnen markeren, instellingen, gebruikers |
   | DMARC Viewer | `DMARC.Viewer` | Alleen lezen en exporteren |

4. Onder **API permissions** staat Microsoft Graph `User.Read` (delegated). Voeg **openid**,
   **profile** en **email** (delegated) toe en kies **Grant admin consent**.
5. Ga naar **Enterprise applications → DMARC-rapportage (portal)**:
   - Zet onder **Properties** de optie **Assignment required?** op **Yes**. Dan kan alleen
     wie toegewezen is inloggen.
   - Wijs onder **Users and groups** de mensen of groepen toe aan een rol, bijvoorbeeld
     IT-beheer → *DMARC Admin* en managers → *DMARC Viewer*.

   > Groepen aan een app-rol toewijzen vereist Entra ID P1 of hoger. Zonder P1 wijs je
   > gebruikers individueel toe.

Zet de waarden in `.env`:

```
DMARC_OIDC_CLIENT_ID=<Application (client) ID van de portal-app>
DMARC_OIDC_CLIENT_SECRET=<Value van het client secret>
# DMARC_OIDC_TENANT_ID is niet nodig als het dezelfde tenant is als DMARC_GRAPH_TENANT_ID
```

Controleer na het starten de login:
- een gebruiker met *DMARC Admin* ziet ook **Settings** en **Users & audit**;
- een gebruiker zonder rol krijgt "Your account has no access".

Wijzig je de rol van iemand in Entra, dan geldt die bij de volgende login.

### 2.1 Azure Application Gateway

De Application Gateway handelt TLS af met het wildcard-certificaat `*.example.com` en
stuurt het verkeer via HTTP door naar de `api`-container op de Docker-host.

| Onderdeel | Instelling |
|---|---|
| Listener | HTTPS 443, hostname `dmarc.example.com`, wildcard-certificaat (bij voorkeur uit Key Vault) |
| Backend pool | Het privé-IP van de Docker-host |
| Backend setting | HTTP, poort `8080`, *Override with new host name*: **nee** (de app moet `dmarc.example.com` als Host zien) |
| Health probe | `GET /healthz`, verwacht 200 |
| Rewrite (optioneel) | De App Gateway zet zelf al `X-Forwarded-Proto` en `X-Forwarded-For`; de app vertrouwt die alleen van het subnet van de gateway |
| Toegang | Alleen een privé-frontend-IP, of een WAF-/NSG-regel die alleen interne netwerken en de VPN toelaat |

DNS: zet een A-record voor `dmarc.example.com` in de interne zone, of als
split-horizon, naar het frontend-IP van de gateway.
