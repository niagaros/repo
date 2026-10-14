import json
import os
import uuid
import boto3
import psycopg2


def get_db_connection():
    client = boto3.client("secretsmanager", region_name="eu-west-1")
    secret = json.loads(
        client.get_secret_value(SecretId="cspm/database/credentials")["SecretString"]
    )
    return psycopg2.connect(
        host=secret["host"],
        port=secret.get("port", 5432),
        dbname=secret["database"],
        user=secret["username"],
        password=secret["password"],
        sslmode="require",
        connect_timeout=10,
    )


CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def authenticated_email(event):
    """Email of the signed-in Cognito user, or None. Onboarding must belong to a verified identity —
    otherwise anyone could register an account for someone else's email address."""
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer ") or not auth[7:].strip():
        return None
    try:
        user = boto3.client("cognito-idp", region_name="eu-west-1").get_user(AccessToken=auth[7:].strip())
    except Exception:
        return None
    return next((a["Value"] for a in user["UserAttributes"] if a["Name"] == "email"), None)


def lambda_handler(event, context):
    # Support both REST API (httpMethod) and HTTP API v2 (requestContext.http.method)
    method = (
        event.get("httpMethod")
        or (event.get("requestContext") or {}).get("http", {}).get("method", "")
    ).upper()

    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS, "body": ""}

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        return {"statusCode": 400, "headers": CORS, "body": json.dumps({"error": "Invalid JSON"})}

    email          = (body.get("email") or "").strip()
    if os.environ.get("TENANT_AUTH_ENFORCE", "1") != "0":
        verified = authenticated_email(event)
        if not verified:
            return {"statusCode": 401, "headers": CORS, "body": json.dumps({"error": "Unauthorized"})}
        if email and email.lower() != verified.lower():
            return {"statusCode": 403, "headers": CORS, "body": json.dumps({"error": "Forbidden"})}
        email = verified
    company_name   = (body.get("company_name") or "").strip()
    aws_account_id = (body.get("aws_account_id") or "").strip()
    region         = (body.get("region") or "eu-west-1").strip()

    if not email or not company_name or not aws_account_id:
        return {"statusCode": 400, "headers": CORS, "body": json.dumps({"error": "email, company_name en aws_account_id zijn verplicht"})}

    if not aws_account_id.isdigit() or len(aws_account_id) != 12:
        return {"statusCode": 400, "headers": CORS, "body": json.dumps({"error": "aws_account_id moet 12 cijfers zijn"})}

    account_id  = str(uuid.uuid4())
    external_id = str(uuid.uuid4())
    role_arn    = f"arn:aws:iam::{aws_account_id}:role/CSPMScannerRole"

    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                # 1. This exact email already has an account → return it
                cur.execute(
                    "SELECT id, external_id, role_arn FROM cloud_accounts WHERE owner_email = %s LIMIT 1",
                    (email,),
                )
                existing = cur.fetchone()
                if existing:
                    return {
                        "statusCode": 200,
                        "headers": CORS,
                        "body": json.dumps({
                            "account_id":    str(existing[0]),
                            "external_id":   str(existing[1]),
                            "role_arn":      existing[2],
                            "already_exists": True,
                        }),
                    }

                # 2. Different email, same AWS account ID → reuse external_id & role_arn
                #    so the existing CloudFormation stack keeps working.
                cur.execute(
                    """
                    SELECT external_id, role_arn, account_name
                    FROM cloud_accounts
                    WHERE account_id = %s
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (aws_account_id,),
                )
                existing_aws = cur.fetchone()
                if existing_aws:
                    external_id  = str(existing_aws[0])
                    role_arn     = existing_aws[1]
                    # Keep original company name if not provided
                    if not company_name:
                        company_name = existing_aws[2] or company_name

                # 3. Insert a new row for this email (owns its own cloud_account_id
                #    so dashboard filtering by owner_email works per user)
                cur.execute(
                    """
                    INSERT INTO cloud_accounts
                        (id, account_name, account_id, owner_email, role_arn, external_id, region)
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (account_id, company_name, aws_account_id, email, role_arn, external_id, region),
                )
        conn.close()
    except Exception as e:
        return {"statusCode": 500, "headers": CORS, "body": json.dumps({"error": str(e)})}

    return {
        "statusCode": 200,
        "headers": CORS,
        "body": json.dumps({
            "account_id":  account_id,
            "external_id": external_id,
            "role_arn":    role_arn,
        }),
    }
