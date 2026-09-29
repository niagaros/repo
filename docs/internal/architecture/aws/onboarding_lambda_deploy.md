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
