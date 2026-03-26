import csv
import io
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError


def parse_credential_report_csv(csv_bytes: bytes) -> Dict[str, Dict[str, Any]]:
    text = csv_bytes.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    parsed: Dict[str, Dict[str, Any]] = {}

    for row in reader:
        username = row.get("user")
        if not username:
            continue

        parsed[username] = {
            "arn": row.get("arn"),
            "password_enabled": row.get("password_enabled") == "true",
            "password_last_used": row.get("password_last_used"),
            "mfa_active": row.get("mfa_active") == "true",
            "access_key_1_active": row.get("access_key_1_active") == "true",
            "access_key_1_last_rotated": row.get("access_key_1_last_rotated"),
            "access_key_2_active": row.get("access_key_2_active") == "true",
            "access_key_2_last_rotated": row.get("access_key_2_last_rotated"),
            "access_key_2_last_used_date": row.get("access_key_2_last_used_date"),
        }

    return parsed


class IAMCollector:

    def __init__(self, session=None):
        if session is None:
            session = boto3.session.Session()

        self.session = session
        self.iam = session.client("iam")
        self.sts = session.client("sts")

    def collect(self) -> List[Dict[str, Any]]:
        resources: List[Dict[str, Any]] = []

        account_id = self.sts.get_caller_identity()["Account"]

        password_policy = None
        try:
            response = self.iam.get_account_password_policy()
            password_policy = response.get("PasswordPolicy")
        except ClientError:
            password_policy = None

        credential_map: Dict[str, Dict[str, Any]] = {}
        try:
            self.iam.generate_credential_report()
            report = self.iam.get_credential_report()
            content = report.get("Content", b"")
            if content:
                credential_map = parse_credential_report_csv(content)
        except ClientError:
            credential_map = {}

        root = credential_map.get("<root_account>", {})

        resources.append({
            "resource_type": "iam-account",
            "resource_id": f"arn:aws:iam::{account_id}:root",
            "resource_name": "account",
            "account_id": account_id,
            "region": "global",
            "config": {
                "root_mfa_enabled": root.get("mfa_active"),
                "root_access_keys_present": bool(root.get("access_key_1_active")) or bool(root.get("access_key_2_active")),
                "root_last_used": root.get("password_last_used") or root.get("access_key_2_last_used_date"),
                "password_policy": password_policy
            }
        })

        paginator = self.iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user.get("UserName")
                arn = user.get("Arn")

                if not username or not arn:
                    continue

                cred = credential_map.get(username, {})

                resources.append({
                    "resource_type": "iam-user",
                    "resource_id": arn,
                    "resource_name": username,
                    "account_id": account_id,
                    "region": "global",
                    "config": {
                        "mfa_enabled": cred.get("mfa_active"),
                        "password_enabled": cred.get("password_enabled"),
                        "password_last_used": cred.get("password_last_used"),
                        "access_keys": [],
                        "attached_policies": [],
                        "inline_policies": [],
                        "has_administrator_access": False
                    }
                })

        return resources