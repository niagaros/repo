import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


BOTO_CONFIG = Config(
    retries={"max_attempts": 8, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
)


# ----------------------------
# Logging
# ----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            payload.update(ctx)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


log = get_logger("collector.aws.iam")


# ----------------------------
# Shared helpers
# ----------------------------

def _to_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None

    text = str(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    if text in {"n/a", "not_supported", ""}:
        return None

    return None


def _to_iso8601(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    text = str(value).strip()
    if text in {"", "N/A", "n/a", "not_supported"}:
        return None

    try:
        if text.endswith("Z"):
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return text


def _is_access_denied(error: ClientError) -> bool:
    code = error.response.get("Error", {}).get("Code", "")
    return code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedException",
    }


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_credential_report_csv(csv_bytes: bytes) -> Dict[str, Dict[str, Any]]:
    """
    Parse AWS IAM credential report CSV into a dict keyed by user name.
    Includes <root_account> when present.
    """
    text = csv_bytes.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    parsed: Dict[str, Dict[str, Any]] = {}

    for row in reader:
        username = row.get("user")
        if not username:
            continue

        parsed[username] = {
            "user": username,
            "arn": row.get("arn"),
            "user_creation_time": _to_iso8601(row.get("user_creation_time")),
            "password_enabled": _to_bool(row.get("password_enabled")),
            "password_last_used": _to_iso8601(row.get("password_last_used")),
            "password_last_changed": _to_iso8601(row.get("password_last_changed")),
            "password_next_rotation": _to_iso8601(row.get("password_next_rotation")),
            "mfa_active": _to_bool(row.get("mfa_active")),
            "access_key_1_active": _to_bool(row.get("access_key_1_active")),
            "access_key_1_last_rotated": _to_iso8601(row.get("access_key_1_last_rotated")),
            "access_key_1_last_used_date": _to_iso8601(row.get("access_key_1_last_used_date")),
            "access_key_2_active": _to_bool(row.get("access_key_2_active")),
            "access_key_2_last_rotated": _to_iso8601(row.get("access_key_2_last_rotated")),
            "access_key_2_last_used_date": _to_iso8601(row.get("access_key_2_last_used_date")),
        }

    return parsed


def normalize_policy_document(policy_doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes IAM policy docs into a structure suitable for analysis.
    Full wildcard expansion is NOT implemented because that requires a full AWS action catalog.
    Instead, this detects dangerous wildcard patterns reliably.
    """
    statements_raw = policy_doc.get("Statement", [])
    statements = _ensure_list(statements_raw)

    normalized_statements: List[Dict[str, Any]] = []
    all_actions: List[str] = []
    all_resources: List[str] = []
    service_action_wildcards: List[str] = []

    has_action_star = False
    has_resource_star = False
    has_star_star = False
    is_admin_like = False

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        actions = [str(x) for x in _ensure_list(stmt.get("Action"))]
        resources = [str(x) for x in _ensure_list(stmt.get("Resource"))]

        all_actions.extend(actions)
        all_resources.extend(resources)

        local_has_action_star = "*" in actions
        local_has_resource_star = "*" in resources
        local_has_star_star = "*:*" in actions

        has_action_star = has_action_star or local_has_action_star
        has_resource_star = has_resource_star or local_has_resource_star
        has_star_star = has_star_star or local_has_star_star

        for action in actions:
            if ":" in action and action.endswith(":*"):
                service_action_wildcards.append(action)

        if stmt.get("Effect") == "Allow" and ("*" in actions or "*:*" in actions) and "*" in resources:
            is_admin_like = True

        normalized_statements.append(
            {
                "Sid": stmt.get("Sid"),
                "Effect": stmt.get("Effect"),
                "Action": actions,
                "Resource": resources,
                "Condition": stmt.get("Condition"),
                "wildcards": {
                    "has_action_star": local_has_action_star,
                    "has_resource_star": local_has_resource_star,
                    "has_star_star": local_has_star_star,
                    "service_action_wildcards": [a for a in actions if ":" in a and a.endswith(":*")],
                },
            }
        )

    return {
        "Version": policy_doc.get("Version"),
        "Statement": normalized_statements,
        "extracted": {
            "actions": list(dict.fromkeys(all_actions)),
            "resources": list(dict.fromkeys(all_resources)),
            "wildcards": {
                "has_action_star": has_action_star,
                "has_resource_star": has_resource_star,
                "has_star_star": has_star_star,
                "service_action_wildcards": list(dict.fromkeys(service_action_wildcards)),
            },
            "is_administrator_like": is_admin_like,
        },
    }


# ----------------------------
# STS assume role
# ----------------------------

def assume_role_session(role_arn: str, external_id: str, session_name: str) -> boto3.session.Session:
    sts = boto3.client("sts", config=BOTO_CONFIG)

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        ExternalId=external_id,
    )

    credentials = response["Credentials"]

    return boto3.session.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


# ----------------------------
# IAM Collector
# ----------------------------

class IAMCollector:
    def __init__(
        self,
        session: Optional[boto3.session.Session] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        session_name: str = "cspm-iam-collector",
    ):
        if session is not None:
            self.session = session
        elif role_arn and external_id:
            self.session = assume_role_session(
                role_arn=role_arn,
                external_id=external_id,
                session_name=session_name,
            )
        else:
            self.session = boto3.session.Session()

        self.iam = self.session.client("iam", config=BOTO_CONFIG)
        self.sts = self.session.client("sts", config=BOTO_CONFIG)

    # ------------------------
    # Low-level safe calls
    # ------------------------

    def _safe(self, func, action: str, default=None, **kwargs):
        try:
            return func(**kwargs)
        except ClientError as error:
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied, continuing",
                    extra={"ctx": {"action": action, "error_code": error.response.get("Error", {}).get("Code")}},
                )
                return default
            raise

    def _get_account_id(self) -> str:
        response = self.sts.get_caller_identity()
        return response["Account"]

    # ------------------------
    # Account-level
    # ------------------------

    def get_account_password_policy(self) -> Optional[Dict[str, Any]]:
        response = self._safe(
            self.iam.get_account_password_policy,
            action="iam.get_account_password_policy",
            default=None,
        )
        if not response:
            return None
        return response.get("PasswordPolicy")

    def generate_credential_report(self) -> Optional[Dict[str, Any]]:
        return self._safe(
            self.iam.generate_credential_report,
            action="iam.generate_credential_report",
            default=None,
        )

    def get_credential_report(self) -> Optional[bytes]:
        response = self._safe(
            self.iam.get_credential_report,
            action="iam.get_credential_report",
            default=None,
        )
        if not response:
            return None
        return response.get("Content")

    def _extract_root_metadata(self, credential_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        root = credential_map.get("<root_account>", {})

        return {
            "root_mfa_enabled": root.get("mfa_active"),
            "root_access_keys_present": bool(root.get("access_key_1_active")) or bool(root.get("access_key_2_active")),
            "root_last_used": root.get("password_last_used")
            or root.get("access_key_1_last_used_date")
            or root.get("access_key_2_last_used_date"),
        }

    # ------------------------
    # Users
    # ------------------------

    def list_users(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_users")

        try:
            for page in paginator.paginate():
                results.extend(page.get("Users", []))
        except ClientError as error:
            if _is_access_denied(error):
                log.warning("AccessDenied listing users", extra={"ctx": {"action": "iam.list_users"}})
                return []
            raise

        return results

    def _list_attached_user_policies(self, user_name: str) -> List[str]:
        policies: List[str] = []
        paginator = self.iam.get_paginator("list_attached_user_policies")

        try:
            for page in paginator.paginate(UserName=user_name):
                for policy in page.get("AttachedPolicies", []):
                    arn = policy.get("PolicyArn")
                    if arn:
                        policies.append(arn)
        except ClientError as error:
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied listing attached user policies",
                    extra={"ctx": {"action": "iam.list_attached_user_policies", "user_name": user_name}},
                )
                return []
            raise

        return policies

    def _list_user_inline_policies(self, user_name: str) -> List[str]:
        names: List[str] = []
        paginator = self.iam.get_paginator("list_user_policies")

        try:
            for page in paginator.paginate(UserName=user_name):
                names.extend(page.get("PolicyNames", []))
        except ClientError as error:
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied listing user inline policies",
                    extra={"ctx": {"action": "iam.list_user_policies", "user_name": user_name}},
                )
                return []
            raise

        return names

    def _get_user_inline_policy_document(self, user_name: str, policy_name: str) -> Optional[Dict[str, Any]]:
        response = self._safe(
            self.iam.get_user_policy,
            action="iam.get_user_policy",
            default=None,
            UserName=user_name,
            PolicyName=policy_name,
        )
        if not response:
            return None
        return response.get("PolicyDocument")

    def _list_access_keys(self, user_name: str) -> List[Dict[str, Any]]:
        keys: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_access_keys")

        try:
            for page in paginator.paginate(UserName=user_name):
                keys.extend(page.get("AccessKeyMetadata", []))
        except ClientError as error:
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied listing access keys",
                    extra={"ctx": {"action": "iam.list_access_keys", "user_name": user_name}},
                )
                return []
            raise

        return keys

    def _get_access_key_last_used(self, access_key_id: str) -> Optional[str]:
        response = self._safe(
            self.iam.get_access_key_last_used,
            action="iam.get_access_key_last_used",
            default=None,
            AccessKeyId=access_key_id,
        )
        if not response:
            return None

        last_used = response.get("AccessKeyLastUsed", {}).get("LastUsedDate")
        return _to_iso8601(last_used)

    def _has_console_login_profile(self, user_name: str) -> bool:
        try:
            self.iam.get_login_profile(UserName=user_name)
            return True
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code == "NoSuchEntity":
                return False
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied checking login profile",
                    extra={"ctx": {"action": "iam.get_login_profile", "user_name": user_name}},
                )
                return False
            raise

    # ------------------------
    # Roles
    # ------------------------

    def list_roles(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_roles")

        try:
            for page in paginator.paginate():
                results.extend(page.get("Roles", []))
        except ClientError as error:
            if _is_access_denied(error):
                log.warning("AccessDenied listing roles", extra={"ctx": {"action": "iam.list_roles"}})
                return []
            raise

        return results

    def _list_attached_role_policies(self, role_name: str) -> List[str]:
        policies: List[str] = []
        paginator = self.iam.get_paginator("list_attached_role_policies")

        try:
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    arn = policy.get("PolicyArn")
                    if arn:
                        policies.append(arn)
        except ClientError as error:
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied listing attached role policies",
                    extra={"ctx": {"action": "iam.list_attached_role_policies", "role_name": role_name}},
                )
                return []
            raise

        return policies

    def _list_role_inline_policies(self, role_name: str) -> List[str]:
        names: List[str] = []
        paginator = self.iam.get_paginator("list_role_policies")

        try:
            for page in paginator.paginate(RoleName=role_name):
                names.extend(page.get("PolicyNames", []))
        except ClientError as error:
            if _is_access_denied(error):
                log.warning(
                    "AccessDenied listing role inline policies",
                    extra={"ctx": {"action": "iam.list_role_policies", "role_name": role_name}},
                )
                return []
            raise

        return names

    def _get_role_inline_policy_document(self, role_name: str, policy_name: str) -> Optional[Dict[str, Any]]:
        response = self._safe(
            self.iam.get_role_policy,
            action="iam.get_role_policy",
            default=None,
            RoleName=role_name,
            PolicyName=policy_name,
        )
        if not response:
            return None
        return response.get("PolicyDocument")

    # ------------------------
    # Managed policies
    # ------------------------

    def list_policies(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_policies")

        try:
            for page in paginator.paginate(Scope="All", OnlyAttached=False):
                results.extend(page.get("Policies", []))
        except ClientError as error:
            if _is_access_denied(error):
                log.warning("AccessDenied listing policies", extra={"ctx": {"action": "iam.list_policies"}})
                return []
            raise

        return results

    def _get_policy(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        response = self._safe(
            self.iam.get_policy,
            action="iam.get_policy",
            default=None,
            PolicyArn=policy_arn,
        )
        if not response:
            return None
        return response.get("Policy")

    def _get_policy_version_document(self, policy_arn: str, version_id: str) -> Optional[Dict[str, Any]]:
        response = self._safe(
            self.iam.get_policy_version,
            action="iam.get_policy_version",
            default=None,
            PolicyArn=policy_arn,
            VersionId=version_id,
        )
        if not response:
            return None
        return response.get("PolicyVersion", {}).get("Document")

    def _resolve_managed_policy_documents(self, policy_arns: List[str]) -> List[Dict[str, Any]]:
        docs: List[Dict[str, Any]] = []

        for policy_arn in policy_arns:
            policy = self._get_policy(policy_arn)
            if not policy:
                continue

            default_version_id = policy.get("DefaultVersionId")
            if not default_version_id:
                continue

            doc = self._get_policy_version_document(policy_arn, default_version_id)
            if doc:
                docs.append(doc)

        return docs

    def _has_admin_access(self, policy_documents: List[Dict[str, Any]]) -> bool:
        for doc in policy_documents:
            normalized = normalize_policy_document(doc)
            if normalized.get("extracted", {}).get("is_administrator_like") is True:
                return True
        return False

    # ------------------------
    # Resource normalization
    # ------------------------

    def _resource(
        self,
        *,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        account_id: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "account_id": account_id,
            "region": "global",
            "config": config,
        }

    # ------------------------
    # Main collect
    # ------------------------

    def collect(self) -> List[Dict[str, Any]]:
        account_id = self._get_account_id()

        log.info(
            "Starting IAM collection",
            extra={"ctx": {"action": "iam.collect.start", "account_id": account_id}},
        )

        resources: List[Dict[str, Any]] = []

        # credential report
        self.generate_credential_report()
        credential_report_bytes = self.get_credential_report()
        credential_map = parse_credential_report_csv(credential_report_bytes) if credential_report_bytes else {}

        # account-level resource
        password_policy = self.get_account_password_policy()
        root_metadata = self._extract_root_metadata(credential_map)

        resources.append(
            self._resource(
                resource_type="iam-account",
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_name="account",
                account_id=account_id,
                config={
                    "password_policy": password_policy,
                    **root_metadata,
                },
            )
        )

        # users
        for user in self.list_users():
            user_name = user.get("UserName")
            user_arn = user.get("Arn")

            if not user_name or not user_arn:
                continue

            attached_policy_arns = self._list_attached_user_policies(user_name)
            inline_policy_names = self._list_user_inline_policies(user_name)
            access_keys = self._list_access_keys(user_name)
            has_console_login_profile = self._has_console_login_profile(user_name)

            inline_docs: List[Dict[str, Any]] = []
            for policy_name in inline_policy_names:
                doc = self._get_user_inline_policy_document(user_name, policy_name)
                if doc:
                    inline_docs.append(doc)

            managed_docs = self._resolve_managed_policy_documents(attached_policy_arns)
            has_admin_access = self._has_admin_access(inline_docs + managed_docs)

            credential = credential_map.get(user_name, {})

            normalized_access_keys: List[Dict[str, Any]] = []
            for key in access_keys:
                access_key_id = key.get("AccessKeyId")
                normalized_access_keys.append(
                    {
                        "key_id": access_key_id,
                        "active": key.get("Status") == "Active",
                        "last_rotated": _to_iso8601(key.get("CreateDate")),
                        "last_used": self._get_access_key_last_used(access_key_id) if access_key_id else None,
                    }
                )

            resources.append(
                self._resource(
                    resource_type="iam-user",
                    resource_id=user_arn,
                    resource_name=user_name,
                    account_id=account_id,
                    config={
                        "mfa_enabled": credential.get("mfa_active"),
                        "password_enabled": credential.get("password_enabled"),
                        "password_last_used": credential.get("password_last_used"),
                        "has_console_login_profile": has_console_login_profile,
                        "access_keys": normalized_access_keys,
                        "attached_policies": attached_policy_arns,
                        "inline_policies": inline_policy_names,
                        "credential_report": {
                            "access_key_1_active": credential.get("access_key_1_active"),
                            "access_key_1_last_rotated": credential.get("access_key_1_last_rotated"),
                            "access_key_2_active": credential.get("access_key_2_active"),
                            "access_key_2_last_rotated": credential.get("access_key_2_last_rotated"),
                        },
                        "has_administrator_access": has_admin_access,
                    },
                )
            )

        # roles
        for role in self.list_roles():
            role_name = role.get("RoleName")
            role_arn = role.get("Arn")

            if not role_name or not role_arn:
                continue

            attached_policy_arns = self._list_attached_role_policies(role_name)
            inline_policy_names = self._list_role_inline_policies(role_name)

            inline_docs: List[Dict[str, Any]] = []
            for policy_name in inline_policy_names:
                doc = self._get_role_inline_policy_document(role_name, policy_name)
                if doc:
                    inline_docs.append(doc)

            managed_docs = self._resolve_managed_policy_documents(attached_policy_arns)
            has_admin_access = self._has_admin_access(inline_docs + managed_docs)

            trust_policy = role.get("AssumeRolePolicyDocument")

            resources.append(
                self._resource(
                    resource_type="iam-role",
                    resource_id=role_arn,
                    resource_name=role_name,
                    account_id=account_id,
                    config={
                        "attached_policies": attached_policy_arns,
                        "inline_policies": inline_policy_names,
                        "trust_policy": trust_policy,
                        "normalized_trust_policy": normalize_policy_document(trust_policy) if isinstance(trust_policy, dict) else None,
                        "has_administrator_access": has_admin_access,
                    },
                )
            )

        # managed policies
        for policy in self.list_policies():
            policy_arn = policy.get("Arn")
            policy_name = policy.get("PolicyName")
            default_version_id = policy.get("DefaultVersionId")

            if not policy_arn or not policy_name or not default_version_id:
                continue

            policy_document = self._get_policy_version_document(policy_arn, default_version_id)
            normalized_document = normalize_policy_document(policy_document) if isinstance(policy_document, dict) else None

            resources.append(
                self._resource(
                    resource_type="iam-policy",
                    resource_id=policy_arn,
                    resource_name=policy_name,
                    account_id=account_id,
                    config={
                        "default_version_id": default_version_id,
                        "document": policy_document,
                        "normalized_document": normalized_document,
                        "is_administrator_like": (
                            normalized_document.get("extracted", {}).get("is_administrator_like")
                            if normalized_document
                            else None
                        ),
                    },
                )
            )

        log.info(
            "Finished IAM collection",
            extra={
                "ctx": {
                    "action": "iam.collect.finish",
                    "account_id": account_id,
                    "resource_count": len(resources),
                }
            },
        )

        return resources