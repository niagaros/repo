#!/usr/bin/env bash
# Deploy the CIS GitHub scanner Lambda.
#
# Prerequisites:
#   - AWS CLI configured (same account/region as the other scanners)
#   - jq installed
#   - psql access to the RDS instance (or run the SQL migration via AWS console)
#
# Usage:
#   cd backend/src/collectors/github
#   chmod +x deploy.sh && ./deploy.sh
#
# The script creates a zip with:
#   - lambda_handler.py
#   - psycopg2 (copied from the existing working cloudwatch scanner)
#   - requests (installed fresh via pip)

set -euo pipefail

FUNCTION_NAME="github-cis-scanner"
REGION="eu-west-1"
RUNTIME="python3.11"
MEMORY=256
TIMEOUT=600   # 10 min — large orgs can take a while

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# ── 1. Build package directory ────────────────────────────────────────────────
BUILD_DIR="$(mktemp -d)"
echo "Building in $BUILD_DIR"

cp "$SCRIPT_DIR/lambda_handler.py" "$BUILD_DIR/"

# Copy psycopg2 from the existing working scanner (already compiled for Lambda)
PSYCOPG2_SRC="$REPO_ROOT/backend/src/collectors/aws/scanner/psycopg2"
if [ -d "$PSYCOPG2_SRC" ]; then
    cp -r "$PSYCOPG2_SRC" "$BUILD_DIR/psycopg2"
    echo "Copied psycopg2 from cloudwatch scanner"
else
    echo "ERROR: psycopg2 not found at $PSYCOPG2_SRC" >&2
    exit 1
fi

# Also copy psycopg2_binary.libs if it exists alongside the cloudwatch scanner
SCANNER_DIR="$REPO_ROOT/backend/src/collectors/aws/scanner"
if [ -d "$SCANNER_DIR/psycopg2_binary.libs" ]; then
    cp -r "$SCANNER_DIR/psycopg2_binary.libs" "$BUILD_DIR/"
fi

# Install requests
pip install requests -t "$BUILD_DIR" --quiet --no-deps
pip install certifi urllib3 charset-normalizer idna -t "$BUILD_DIR" --quiet --no-deps

# ── 2. Zip ─────────────────────────────────────────────────────────────────────
ZIP_PATH="/tmp/github-cis-scanner.zip"
(cd "$BUILD_DIR" && zip -r "$ZIP_PATH" . -x "*.pyc" -x "**/__pycache__/*") > /dev/null
echo "Package size: $(du -sh "$ZIP_PATH" | cut -f1)"

# ── 3. Get the Lambda execution role from an existing scanner ─────────────────
EXISTING_ROLE=$(
    aws lambda get-function-configuration \
        --function-name cloudwatch-cis-scanner \
        --region "$REGION" \
        --query "Role" --output text 2>/dev/null \
    || echo ""
)
if [ -z "$EXISTING_ROLE" ]; then
    echo "ERROR: Could not determine Lambda execution role from cloudwatch-cis-scanner." >&2
    echo "Set LAMBDA_ROLE_ARN manually and re-run." >&2
    exit 1
fi
echo "Using IAM role: $EXISTING_ROLE"

# ── 4. Create or update Lambda ─────────────────────────────────────────────────
if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" &>/dev/null; then
    echo "Updating existing Lambda..."
    aws lambda update-function-code \
        --function-name "$FUNCTION_NAME" \
        --zip-file "fileb://$ZIP_PATH" \
        --region "$REGION" > /dev/null
    aws lambda update-function-configuration \
        --function-name "$FUNCTION_NAME" \
        --timeout "$TIMEOUT" \
        --memory-size "$MEMORY" \
        --region "$REGION" > /dev/null
else
    echo "Creating Lambda $FUNCTION_NAME..."
    aws lambda create-function \
        --function-name "$FUNCTION_NAME" \
        --runtime "$RUNTIME" \
        --role "$EXISTING_ROLE" \
        --handler "lambda_handler.lambda_handler" \
        --timeout "$TIMEOUT" \
        --memory-size "$MEMORY" \
        --zip-file "fileb://$ZIP_PATH" \
        --region "$REGION" > /dev/null
fi
echo "Lambda deployed: $FUNCTION_NAME"

# ── 5. Cleanup ─────────────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"

echo ""
echo "=== Next steps ==="
echo "1. Run the SQL migration:"
echo "   psql \$DB_URL < backend/migrations/001_github_integrations.sql"
echo ""
echo "2. Create a Secrets Manager secret with the GitHub PAT:"
echo "   aws secretsmanager create-secret \\"
echo "     --name 'niagaros/github/<ORG_NAME>/token' \\"
echo "     --secret-string '{\"github_token\": \"ghp_...\"}' \\"
echo "     --region $REGION"
echo ""
echo "3. Insert a github_integrations row for the customer account:"
echo "   INSERT INTO github_integrations (cloud_account_id, org_name, github_token_secret)"
echo "   VALUES ('<UUID>', '<ORG_NAME>', 'niagaros/github/<ORG_NAME>/token');"
echo ""
echo "4. The orchestrator will pick up the scanner automatically on the next run."
echo "   To test immediately:"
echo "   aws lambda invoke --function-name $FUNCTION_NAME \\"
echo "     --payload '{\"cloud_account_id\": \"<UUID>\"}' \\"
echo "     --region $REGION /tmp/github-scan-result.json"
echo "   cat /tmp/github-scan-result.json | jq ."
