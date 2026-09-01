import boto3
import os

class KMSCollector:
    def __init__(self, role_arn: str = None, external_id: str = None, region: str = "eu-west-1"):
        self.role_arn = role_arn
        self.external_id = external_id
        self.region = region

    def _assume_role(self):
        # Lokaal: gebruik SSO profile als AWS_PROFILE gezet is
        # Lambda: gebruik execution role automatisch (geen profile)
        profile = os.environ.get("AWS_PROFILE")
        base_session = boto3.Session(
            profile_name=profile,
            region_name=self.region
        )

        sts = base_session.client("sts")

        assume_kwargs = {
            "RoleArn": self.role_arn,
            "RoleSessionName": "KMSSession",
        }
        if self.external_id and self.external_id not in ("none", ""):
            assume_kwargs["ExternalId"] = self.external_id

        response = sts.assume_role(**assume_kwargs)
        creds = response["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region
        )

    def collect(self):
        session = self._assume_role()
        kms = session.client("kms")

        keys = kms.list_keys().get("Keys", [])
        aliases = kms.list_aliases().get("Aliases", [])
        alias_map = {a["TargetKeyId"]: a["AliasName"] for a in aliases if "TargetKeyId" in a}

        normalized_keys = []
        for key in keys:
            key_id = key["KeyId"]
            metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            try:
                rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled")
            except Exception:
                rotation_enabled = None
            try:
                policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            except Exception:
                policy = None
            try:
                grants = kms.list_grants(KeyId=key_id).get("Grants", [])
            except Exception:
                grants = []
            try:
                tags = kms.list_resource_tags(KeyId=key_id).get("Tags", [])
            except Exception:
                tags = []

            normalized_keys.append({
                "key_id": key_id,
                "arn": metadata.get("Arn"),
                "alias": alias_map.get(key_id),
                "key_manager": metadata.get("KeyManager"),
                "key_state": metadata.get("KeyState"),
                "origin": metadata.get("Origin"),
                "multi_region": metadata.get("MultiRegion"),
                "rotation_enabled": rotation_enabled,
                "policy": policy,
                "grants": grants,
                "tags": tags
            })
        return normalized_keys