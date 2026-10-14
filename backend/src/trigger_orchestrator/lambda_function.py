import json
import os
import boto3

REGION = "eu-west-1"
ORCHESTRATOR = os.environ.get("ORCHESTRATOR_FUNCTION_NAME", "cspm_orchestrator")


def _authenticated(event):
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer ") or not auth[7:].strip():
        return False
    try:
        boto3.client("cognito-idp", region_name=REGION).get_user(AccessToken=auth[7:].strip())
        return True
    except Exception:
        return False


def lambda_handler(event, context):
    # CORS preflight
    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
            "body": "",
        }

    # Starting a scan is a privileged action: require a verified Cognito session (kill switch: TENANT_AUTH_ENFORCE=0).
    if os.environ.get("TENANT_AUTH_ENFORCE", "1") != "0" and not _authenticated(event):
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"error": "Unauthorized"}),
        }

    try:
        client = boto3.client("lambda", region_name=REGION)
        client.invoke(FunctionName=ORCHESTRATOR, InvocationType="Event")
        return {
            "statusCode": 202,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({"message": "Scan triggered"}),
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({"error": str(e)}),
        }
