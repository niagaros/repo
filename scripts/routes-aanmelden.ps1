# Meldt de routes van #265 en #266 aan bij API Gateway hzf92ft6j7.
#
# Twintig expliciete routes in plaats van een "vang alles op"-route: de
# handlers lezen {id}, {engagement_id}, {request_id} en {cloud_account_id}
# uit het pad, en die namen geeft API Gateway alleen door als de route ze
# ook echt declareert.
#
# OPTIONS staat er niet bij: CORS is op API-niveau geregeld, API Gateway
# beantwoordt preflight-verzoeken zelf.

$ErrorActionPreference = "Stop"
$api     = "hzf92ft6j7"
$regio   = "eu-west-1"
$account = "225989360315"

function Stap($tekst) { Write-Host "`n=== $tekst ===" }

# ── 1. API Gateway toestemming geven de functies aan te roepen ───────
Stap "Toestemming voor API Gateway"
foreach ($fn in @("team-handler", "auditor-handler")) {
    try {
        aws lambda add-permission --function-name $fn `
            --statement-id apigateway-invoke `
            --action lambda:InvokeFunction `
            --principal apigateway.amazonaws.com `
            --source-arn "arn:aws:execute-api:${regio}:${account}:${api}/*/*" `
            --output text --query Statement | Out-Null
        Write-Host "  OK    $fn"
    } catch {
        Write-Host "  AL GEREGELD  $fn (toestemming bestond al)"
    }
}

# ── 2. Integraties aanmaken ─────────────────────────────────────────
Stap "Integraties"
$integratie = @{}
foreach ($fn in @("team-handler", "auditor-handler")) {
    $id = aws apigatewayv2 create-integration --api-id $api `
        --integration-type AWS_PROXY `
        --integration-uri "arn:aws:lambda:${regio}:${account}:function:${fn}" `
        --payload-format-version 2.0 `
        --integration-method POST `
        --query IntegrationId --output text
    $integratie[$fn] = $id
    Write-Host "  OK    $fn -> $id"
}

# ── 3. Routes ───────────────────────────────────────────────────────
$routes = @(
    # Invite Team (#265)
    @{ fn = "team-handler"; key = "GET /team" },
    @{ fn = "team-handler"; key = "GET /team/audit-log" },
    @{ fn = "team-handler"; key = "GET /team/cloud-accounts" },
    @{ fn = "team-handler"; key = "GET /team/shared-resources" },
    @{ fn = "team-handler"; key = "POST /team/shared-resources" },
    @{ fn = "team-handler"; key = "DELETE /team/shared-resources/{id}" },
    @{ fn = "team-handler"; key = "POST /team/invite" },
    @{ fn = "team-handler"; key = "POST /team/accept-invite" },
    @{ fn = "team-handler"; key = "DELETE /team/invite/{id}" },
    @{ fn = "team-handler"; key = "PATCH /team/mfa-policy" },
    @{ fn = "team-handler"; key = "PATCH /team/member/{id}" },
    @{ fn = "team-handler"; key = "DELETE /team/member/{id}" },

    # Invite Auditors (#266) -- beheerderskant
    @{ fn = "auditor-handler"; key = "POST /auditors/engagements" },
    @{ fn = "auditor-handler"; key = "GET /auditors/engagements" },
    @{ fn = "auditor-handler"; key = "GET /auditors/engagements/{engagement_id}/requests" },
    @{ fn = "auditor-handler"; key = "PATCH /auditors/engagements/{engagement_id}/requests/{request_id}" },
    @{ fn = "auditor-handler"; key = "GET /auditors/engagements/{engagement_id}/activity" },

    # Invite Auditors (#266) -- auditorkant
    @{ fn = "auditor-handler"; key = "GET /auditor/scope" },
    @{ fn = "auditor-handler"; key = "POST /auditor/evidence-requests" },
    @{ fn = "auditor-handler"; key = "GET /auditor/evidence/{cloud_account_id}" }
)

Stap "Routes ($($routes.Count) stuks)"
$mislukt = @()
foreach ($r in $routes) {
    try {
        aws apigatewayv2 create-route --api-id $api `
            --route-key $r.key `
            --target "integrations/$($integratie[$r.fn])" `
            --output text --query RouteId | Out-Null
        Write-Host "  OK    $($r.key)"
    } catch {
        Write-Host "  FOUT  $($r.key)"
        $mislukt += $r.key
    }
}

# ── 4. Uitrollen als de stage dat niet zelf doet ────────────────────
Stap "Stage"
$auto = aws apigatewayv2 get-stage --api-id $api --stage-name default --query AutoDeploy --output text
if ($auto -eq "True") {
    Write-Host "  Stage 'default' rolt automatisch uit -- niets te doen."
} else {
    Write-Host "  Stage 'default' rolt niet automatisch uit; nu uitrollen..."
    aws apigatewayv2 create-deployment --api-id $api --stage-name default --query DeploymentStatus --output text
}

Stap "Klaar"
if ($mislukt.Count -gt 0) {
    Write-Host "  $($mislukt.Count) route(s) mislukt:"
    $mislukt | ForEach-Object { Write-Host "    - $_" }
} else {
    Write-Host "  Alle $($routes.Count) routes aangemeld."
}
