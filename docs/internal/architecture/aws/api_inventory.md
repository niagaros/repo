# API Gateway & Lambda Inventory (Niagaros)

**Doel:** dit document legt vast welke API Gateway's en Lambda-functies er daadwerkelijk
in het AWS-account draaien, omdat de bijbehorende code nooit in deze repository is
gecommit (`backend/serverless.yml` is leeg; alleen `get-dashboard-data/lambda_function.py`
staat in de repo). Zonder dit overzicht is er geen manier om te weten wat `/onboard`,
`/profile`, `/github-integration` etc. daadwerkelijk doen.

Opgesteld op: 8 september 2026, account `225989360315`, regio `eu-west-1`,
via `aws apigatewayv2 get-apis / get-routes / get-integrations`.

---

## 1. Overzicht van bestaande API's

Er bestaan **5 HTTP API's** in `eu-west-1`. Slechts één ervan wordt daadwerkelijk door
de frontend gebruikt (zie `frontend/public/config.json` → `REACT_APP_API_BASE_URL`).

| API ID | Naam | Status | Opmerking |
|---|---|---|---|
| **`hzf92ft6j7`** | get-dashboard-data-API | **ACTIEF** | dit is de API die de frontend aanspreekt; bevat 13 verschillende Lambda-integraties (zie tabel hieronder) |
| `zlm0sbtl66` | niagaros-cspm-api | vrijwel ongebruikt | CORS staat wél specifiek op de Amplify-domeinen ingesteld, maar bevat maar één route: `GET /health`. Lijkt een gestarte maar nooit afgemaakte migratie. |
| `i37b60hcdd` | get-dashboard-data-API | **duplicaat / opruimen** | losse `ANY /get-dashboard-data` route, andere integratie dan de actieve API |
| `q42k65ewe2` | get-dashboard-data-API | **duplicaat / opruimen** | idem, losse `ANY /get-dashboard-data` route |
| `jm5l7w4apf` | Stripe-checkout-API | apart in gebruik | wordt aangesproken door `frontend/src/settings/Plans.tsx` (regio eu-north-1 in config, let op mismatch — zie sectie 4) |

**Aanbeveling:** `i37b60hcdd` en `q42k65ewe2` kunnen na verificatie met het team worden
verwijderd — het zijn losstaande duplicaten zonder overige routes.

---

## 2. Routes en Lambda-functies achter `hzf92ft6j7`

| Route(s) | Lambda-functienaam | Payload-versie | Aanwezig in deze repo? |
|---|---|---|---|
| `POST /onboard` | `cspm-onboarding` | 2.0 | ❌ nee |
| `GET/PATCH/OPTIONS /profile`<br>`PATCH/OPTIONS /account` | `profile-handler` | 2.0 | ❌ nee |
| `GET/POST/DELETE/OPTIONS /github-integration`<br>`POST/OPTIONS /github-connect` | `github-oauth-handler` | 2.0 | ❌ nee |
| `GET/POST/OPTIONS /audit-management` | `audit-management-handler` | 1.0 | ❌ nee — **mogelijk overlap met issue #266 (Invite Auditors)** |
| `GET/POST/OPTIONS /tprm` | `tprm-handler` | 1.0 | ❌ nee |
| `GET/POST/OPTIONS /trust-center` | `trust-center-handler` | 1.0 | ❌ nee |
| `GET/POST/DELETE/OPTIONS /custom-frameworks` | `custom-framework-handler` | 1.0 | ❌ nee |
| `GET/POST/OPTIONS /calculators` | `calculator-handler` | 1.0 | ❌ nee |
| `GET/POST/DELETE/OPTIONS /questionnaires` | `questionnaire-handler` | 1.0 | ❌ nee |
| `POST/OPTIONS /monthly-report-preview` | `monthly-report-generator` | 1.0 | ❌ nee |
| `POST/OPTIONS /stripe-checkout` | `stripe-checkout` | 2.0 | ❌ nee |
| `POST /trigger-orchestrator` | `trigger-orchestrator` | 2.0 | ❌ nee |
| `GET/OPTIONS /get-dashboard-data` | `get-dashboard-data` | 1.0 | ✅ ja — `get-dashboard-data/lambda_function.py` |

**13 Lambda-functies in totaal, waarvan 12 nergens in versiebeheer staan.**

---

## 3. Relevantie voor de Onboarding Accelerator (stageopdracht)

| Backend bouwsteen | Relevant voor |
|---|---|
| `cspm-onboarding` | Stage 1 — Integrate Cloud Infrastructure (#269), huidige AWS-wizard in `App.tsx` |
| `github-oauth-handler` | sjabloon-patroon voor connect/status/disconnect — te hergebruiken voor Stage 1 (Azure) en Stage 4 (Workspaces) |
| `profile-handler` | randvoorwaarde: user/account-model waar Team (#265) op voortbouwt |
| `audit-management-handler` | **te verifiëren met begeleider** of dit al (deels) issue #266 dekt, vóór er iets nieuws wordt gebouwd |
| `tprm-handler`, `trust-center-handler` | genoemd als integraties in de PVA-PDF (stage 4), maar buiten de MVP-scope |

**Actiepunt:** voordat Stage 3 (Auditors) wordt gebouwd, eerst de code van
`audit-management-handler` bekijken — mogelijk hoeft niet alles from scratch.

---

## 4. Bekende inconsistenties

- **Twee regio's:** de hoofd-API draait in `eu-west-1`, maar `Plans.tsx` gebruikt een
  fallback-URL in `eu-north-1` (`ylcz8a4v24`). Nooit opgehelderd waarom.
- **Drie API's met dezelfde naam** (`get-dashboard-data-API`) — verwarrend bij beheer,
  twee ervan lijken dood.
- **`backend/serverless.yml` is leeg (0 regels).** Alle 13 Lambda's hierboven zijn dus
  buiten Infrastructure-as-Code om aangemaakt (waarschijnlijk handmatig via de Console).
  Dit betekent: geen reproduceerbare deploys, geen PR-review op infra-wijzigingen, en
  het risico dat iemand per ongeluk een functie verwijdert zonder dat iemand het merkt.

---

## 5. Hoe dit overzicht is gegenereerd (reproduceerbaar)

```powershell
# 1. Alle API's
aws apigatewayv2 get-apis --region eu-west-1 --output json

# 2. Routes per API
aws apigatewayv2 get-routes --api-id hzf92ft6j7 --region eu-west-1 --output json

# 3. Lambda-functie achter elke integratie
aws apigatewayv2 get-integrations --api-id hzf92ft6j7 --region eu-west-1 --output json
```
