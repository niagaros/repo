import csv
import io
import time
from datetime import datetime, timezone
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

    def _get_access_keys(self, username: str) -> List[Dict[str, Any]]:
        keys = []
        try:
            response = self.iam.list_access_keys(UserName=username)
            for key in response.get("AccessKeyMetadata", []):
                active = key.get("Status") == "Active"
                created = key.get("CreateDate")
                last_rotated = str(created) if created else None
                keys.append({
                    "access_key_id": key.get("AccessKeyId"),
                    "active": active,
                    "last_rotated": last_rotated,
                })
        except ClientError:
            pass
        return keys

    def _get_attached_policies(self, username: str) -> List[str]:
        policies = []
        try:
            response = self.iam.list_attached_user_policies(UserName=username)
            for policy in response.get("AttachedPolicies", []):
                policies.append(policy.get("PolicyArn", ""))
        except ClientError:
            pass
        return policies

    def _get_inline_policies(self, username: str) -> List[str]:
        policies = []
        try:
            response = self.iam.list_user_policies(UserName=username)
            policies = response.get("PolicyNames", [])
        except ClientError:
            pass
        return policies

    def _has_administrator_access(self, attached_policies: List[str]) -> bool:
        return "arn:aws:iam::aws:policy/AdministratorAccess" in attached_policies

    def _has_support_role(self) -> bool:
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role.get("RoleName", "")
                    try:
                        attached = self.iam.list_attached_role_policies(RoleName=role_name)
                        for policy in attached.get("AttachedPolicies", []):
                            if policy.get("PolicyArn") == "arn:aws:iam::aws:policy/AWSSupportAccess":
                                return True
                    except ClientError:
                        continue
        except ClientError:
            pass
        return False

    def _get_root_mfa_info(self) -> Dict[str, bool]:
        """Check of root MFA actief is en of het een hardware MFA is."""
        result = {
            "root_mfa_enabled": False,
            "root_hardware_mfa_enabled": False,
        }
        try:
            summary = self.iam.get_account_summary()
            account_mfa = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
            result["root_mfa_enabled"] = account_mfa == 1

            if result["root_mfa_enabled"]:
                # Controleer of het een hardware MFA is
                mfa_devices = self.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
                for device in mfa_devices.get("VirtualMFADevices", []):
                    user = device.get("User", {})
                    if user.get("Arn", "").endswith(":root"):
                        # Root gebruikt een virtual MFA, dus geen hardware
                        result["root_hardware_mfa_enabled"] = False
                        return result
                # Geen virtual MFA gevonden voor root, dus hardware MFA
                result["root_hardware_mfa_enabled"] = True
        except ClientError:
            pass
        return result

    def _get_ssl_certificates(self) -> List[Dict[str, Any]]:
        """Haal SSL/TLS certificaten op die beheerd worden in IAM."""
        certs = []
        try:
            response = self.iam.list_server_certificates()
            for cert in response.get("ServerCertificateMetadataList", []):
                expiry = cert.get("Expiration")
                certs.append({
                    "resource_type": "iam-ssl-certificate",
                    "resource_id": cert.get("Arn", ""),
                    "resource_name": cert.get("ServerCertificateName", ""),
                    "region": "global",
                    "config": {
                        "expiration": str(expiry) if expiry else None,
                        "uploaded_date": str(cert.get("UploadDate", "")),
                    }
                })
        except ClientError:
            pass
        return certs

    def _is_access_analyzer_enabled(self, account_id: str) -> bool:
        """Controleer of IAM Access Analyzer ingeschakeld is."""
        try:
            analyzer_client = self.session.client("accessanalyzer", region_name="eu-west-1")
            response = analyzer_client.list_analyzers()
            for analyzer in response.get("analyzers", []):
                if analyzer.get("status") == "ACTIVE" and analyzer.get("type") == "ACCOUNT":
                    return True
        except ClientError:
            pass
        return False

    def collect(self) -> List[Dict[str, Any]]:
        resources: List[Dict[str, Any]] = []

        account_id = self.sts.get_caller_identity()["Account"]

        # Password policy
        password_policy = None
        try:
            response = self.iam.get_account_password_policy()
            password_policy = response.get("PasswordPolicy")
        except ClientError:
            password_policy = None

        # Credential report — generate_credential_report() is asynchronous. Calling
        # get_credential_report() immediately after frequently hits AWS while the
        # report is still in state STARTED/INPROGRESS, which raises a ClientError.
        # That was previously swallowed here and silently left credential_map empty —
        # meaning root_access_keys_present, every user's mfa_enabled, and
        # password_last_used would all silently read as "not present" / falsy, i.e.
        # a security scanner defaulting to "no problem found" when it simply
        # couldn't fetch the data. Poll until the report is actually ready instead.
        credential_map: Dict[str, Dict[str, Any]] = {}
        try:
            for _ in range(15):
                state = self.iam.generate_credential_report().get("State")
                if state == "COMPLETE":
                    break
                time.sleep(2)
            report = self.iam.get_credential_report()
            content = report.get("Content", b"")
            if content:
                credential_map = parse_credential_report_csv(content)
        except ClientError:
            credential_map = {}

        root = credential_map.get("<root_account>", {})

        # Root MFA info (inclusief hardware MFA)
        root_mfa_info = self._get_root_mfa_info()

        # Support role
        has_support_role = self._has_support_role()

        # Access Analyzer
        access_analyzer_enabled = self._is_access_analyzer_enabled(account_id)

        # Account resource
        resources.append({
            "resource_type": "iam-account",
            "resource_id": f"arn:aws:iam::{account_id}:root",
            "resource_name": "account",
            "account_id": account_id,
            "region": "global",
            "config": {
                "root_mfa_enabled": root_mfa_info["root_mfa_enabled"],
                "root_hardware_mfa_enabled": root_mfa_info["root_hardware_mfa_enabled"],
                "root_access_keys_present": bool(root.get("access_key_1_active")) or bool(root.get("access_key_2_active")),
                "root_last_used": root.get("password_last_used") or root.get("access_key_2_last_used_date"),
                "password_policy": password_policy,
                "has_support_role": has_support_role,
                "access_analyzer_enabled": access_analyzer_enabled,
            }
        })

        # Users
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user.get("UserName")
                arn = user.get("Arn")

                if not username or not arn:
                    continue

                cred = credential_map.get(username, {})
                access_keys = self._get_access_keys(username)
                attached_policies = self._get_attached_policies(username)
                inline_policies = self._get_inline_policies(username)
                has_admin = self._has_administrator_access(attached_policies)

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
                        "access_keys": access_keys,
                        "attached_policies": attached_policies,
                        "inline_policies": inline_policies,
                        "has_administrator_access": has_admin,
                    }
                })

        # SSL certificaten
        ssl_certs = self._get_ssl_certificates()
        resources.extend(ssl_certs)

        return resources