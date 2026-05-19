import json
import logging
import os
import urllib.request
import urllib.parse
import boto3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_NAME = os.environ.get("STRIPE_SECRET_NAME", "niagaros/stripe/secret-key")
REGION      = os.environ.get("AWS_REGION", "eu-west-1")


def _get_stripe_key() -> str:
    sm = boto3.client("secretsmanager", region_name=REGION)
    return sm.get_secret_value(SecretId=SECRET_NAME)["SecretString"]


def _cors_headers() -> dict:
    return {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Content-Type":                 "application/json",
    }


def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")

    if method == "OPTIONS":
        return {"statusCode": 200, "headers": _cors_headers(), "body": ""}

    try:
        body = json.loads(event.get("body") or "{}")
        price_id    = body["price_id"]
        success_url = body["success_url"]
        cancel_url  = body["cancel_url"]
    except (KeyError, json.JSONDecodeError) as e:
        return {
            "statusCode": 400,
            "headers": _cors_headers(),
            "body": json.dumps({"error": f"Missing or invalid field: {e}"}),
        }

    try:
        stripe_key = _get_stripe_key()
    except Exception as e:
        logger.error(f"Could not fetch Stripe key: {e}")
        return {
            "statusCode": 500,
            "headers": _cors_headers(),
            "body": json.dumps({"error": "Internal configuration error"}),
        }

    payload = urllib.parse.urlencode({
        "line_items[0][price]":    price_id,
        "line_items[0][quantity]": "1",
        "mode":                    "subscription",
        "success_url":             success_url,
        "cancel_url":              cancel_url,
    }).encode()

    req = urllib.request.Request(
        "https://api.stripe.com/v1/checkout/sessions",
        data=payload,
        headers={
            "Authorization":  f"Bearer {stripe_key}",
            "Content-Type":   "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            session = json.loads(resp.read().decode())
        logger.info(f"Stripe session created: {session['id']}")
        return {
            "statusCode": 200,
            "headers": _cors_headers(),
            "body": json.dumps({"url": session["url"]}),
        }
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        logger.error(f"Stripe API error {e.code}: {err_body}")
        return {
            "statusCode": 502,
            "headers": _cors_headers(),
            "body": json.dumps({"error": "Stripe API error", "detail": err_body}),
        }
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": _cors_headers(),
            "body": json.dumps({"error": str(e)}),
        }
