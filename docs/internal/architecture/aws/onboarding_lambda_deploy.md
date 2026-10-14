# Uitrol: team- en auditor-Lambda (#265, #266)

Deze twee functies horen bij de onboardingstappen Invite Team en Invite
Auditors. Ze zijn met de hand aangemaakt via de AWS-console, net als de
dertien bestaande functies (zie `api_inventory.md` — `serverless.yml` is
leeg, er is geen Infrastructure-as-Code). Dit bestand legt vast wat er is
ingesteld, zodat de uitrol reproduceerbaar is ook al is het handwerk.

## Pakket

Gebouwd naar `scratch/onboarding-lambda.zip` (~4 MB, 40 bestanden).
Inhoud: `api/`, `config/`, `auth/` uit `backend/src/`, plus de
meegeleverde `psycopg2` uit `backend/src/psycopg2_lambda/`. `boto3` wordt
niet meegeleverd — dat zit al in de Lambda-runtime.

**Een pakket, twee functies.** `auditor_handler` importeert uit
`team_handler`, dus de code hoort bij elkaar. Beide functies gebruiken
hetzelfde bestand met een ander instappunt en blijven zo vanzelf gelijk.

`api/lambda_handler.py` zit er bewust niet in: die hoort bij de scanner
en trekt `engine.scanner` en `notifications.email` mee.

## Instellingen per functie

| | team | auditor |
|---|---|---|
| Handler | `api.team_handler.lambda_handler` | `api.auditor_handler.lambda_handler` |

Voor allebei hetzelfde:

- **Runtime: Python 3.12** en **architectuur x86_64.** Niet vrij te
  kiezen: de meegeleverde psycopg2 is gebouwd als
  `cp312 / manylinux_2_17_x86_64`. Een andere runtime of arm64 laadt niet.
- **Timeout 30 s.** De standaard van 3 s is te kort: elke aanroep doet
  eerst Secrets Manager en dan een databaseverbinding.
- **Geheugen 256 MB.**

## Omgevingsvariabelen

| Naam | Waarde | Waarvoor |
|---|---|---|
| `DB_SECRET_NAME` | `cspm/database/credentials` | databasewachtwoord; er is een standaardwaarde, maar expliciet zetten is duidelijker |
| `COGNITO_USER_POOL_ID` | `eu-west-1_mHQf9RNTc` | nodig voor het beëindigen van sessies bij offboarding (#265, criterium 4). Ontbreekt hij, dan faalt alleen dát onderdeel — stil |

## Rechten

- `secretsmanager:GetSecretValue` op `cspm/database/credentials`
- `cognito-idp:AdminUserGlobalSignOut` op de user pool
- standaard CloudWatch-logrechten

**Geen recht nodig voor het valideren van tokens.** `cognito-idp:GetUser`
wordt geautoriseerd door het token van de aanroeper zelf, niet door de
rol van de Lambda. Bevestigd door Daniil Sokolov, die de profile- en
github-oauth-handler op dezelfde manier heeft gebouwd.

## API Gateway

API `hzf92ft6j7`, **payloadversie 2.0**. Dat is geen detail: bij 2.0
geeft API Gateway headernamen in kleine letters door, en
`_get_authenticated_email()` leest daarom zowel `Authorization` als
`authorization`. Op 1.0 gedraagt het zich anders dan getest.

Ook de `OPTIONS`-varianten registreren, anders blokkeert de browser de
aanroepen.

## Netwerk

De RDS-instantie `cspm-db` is publiek benaderbaar, dus de functies
hoeven niet in een VPC. Neem de netwerkinstelling over van een
bestaande functie die al met deze database praat, zodat de
security group-regels kloppen.

---

## Wat er daadwerkelijk is uitgerold (6 oktober 2026)

Hieronder staat wat er is aangemaakt, met de commando's erbij. Dat is
geen verslag maar een recept: deze reeks bouwt de uitrol opnieuw op.

### Rol

Een eigen rol in plaats van de gedeelde rol van `profile-handler` en
`github-oauth-handler` (`get-dashboard-data-role-nib9ttvx`). Die rol mag
naast het databasewachtwoord ook de Stripe-sleutel en de GitHub-tokens van
klanten lezen, en heeft geen Cognito-recht. Hergebruiken zou dus twee
dingen betekenen: toegang geven tot secrets waar deze functies niets mee
te maken hebben, én `cognito-idp:AdminUserGlobalSignOut` toevoegen aan een
rol die vijf functies delen — waaronder `stripe-checkout`.

    TeamAuditorHandlerLambdaRole
      - AWSLambdaBasicExecutionRole (logs)
      - secretsmanager:GetSecretValue op cspm/database/credentials*
      - cognito-idp:AdminUserGlobalSignOut op userpool/eu-west-1_mHQf9RNTc

### Functies

    aws lambda create-function --function-name team-handler \
      --runtime python3.12 --architectures x86_64 \
      --role arn:aws:iam::225989360315:role/TeamAuditorHandlerLambdaRole \
      --handler api.team_handler.lambda_handler \
      --zip-file fileb://scratch/onboarding-lambda.zip \
      --timeout 30 --memory-size 256 \
      --environment "Variables={DB_SECRET_NAME=cspm/database/credentials,COGNITO_USER_POOL_ID=eu-west-1_mHQf9RNTc}"

Idem voor `auditor-handler` met `api.auditor_handler.lambda_handler`.

### Routes

Twintig expliciete routes op API `hzf92ft6j7`, aangemeld met
`scripts/routes-aanmelden.ps1`. **Geen** `{proxy+}`-route: de handlers
lezen `{id}`, `{engagement_id}`, `{request_id}` en `{cloud_account_id}`
uit het pad, en API Gateway geeft die namen alleen door als de route ze
declareert.

Geen `OPTIONS`-routes nodig: CORS staat op API-niveau en staat
`authorization` en `content-type` toe.

## Wat pas bij de eerste echte aanroep bleek

De API staat op een stage met de naam `default` (niet `$default`). API
Gateway routeert op het pad zónder die stagenaam — de route `GET /team`
werd dus gewoon gevonden — maar geeft de Lambda een `rawPath` van
`/default/team`. De router vergeleek dat letterlijk met `/team` en gaf op
élk verzoek een 404 terug: bereikbaar, geauthenticeerd, en dan afgewezen
door onze eigen code.

Lokaal was dit niet te zien: voor de testserver en de unittests staat geen
stage. Opgelost met `_route_path()` in `team_handler.py`, dat de stagenaam
eraf haalt; `auditor_handler` importeert dezelfde functie. Afgedekt met
acht regressietests.

De stagenaam is bewust niet in de route-keys gezet: dan zou de stage in de
applicatie gaan zitten en werkt dezelfde code niet meer op een tweede stage.

## Rookproef na de uitrol

    GET /default/team                 -> 401 unauthorized
    GET /default/team/audit-log       -> 401 unauthorized
    GET /default/auditor/scope        -> 401 unauthorized
    GET /default/auditors/engagements -> 401 unauthorized
    GET /default/team/onzin           -> 404 (API Gateway, geen route)

401 is hier het goede antwoord: het bewijst dat het pakket laadt, dat de
meegeleverde psycopg2 op deze runtime werkt, dat de rol het
databasewachtwoord mag lezen, dat de functie de database bereikt, en dat
een verzoek zonder geldig token wordt geweigerd.
