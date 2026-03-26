from src.collectors.iam_collector import normalize_policy_document


def test_detect_admin_policy():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ],
    }

    norm = normalize_policy_document(doc)

    assert norm["extracted"]["is_administrator_like"] is True
    assert norm["extracted"]["wildcards"]["has_action_star"] is True
    assert norm["extracted"]["wildcards"]["has_resource_star"] is True


def test_detect_service_wildcard():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:*", "ec2:Describe*"], "Resource": "*"}
        ],
    }

    norm = normalize_policy_document(doc)

    wildcards = norm["extracted"]["wildcards"]
    assert "s3:*" in wildcards["service_action_wildcards"]


def test_statement_as_dict_supported():
    doc = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "iam:ListUsers",
            "Resource": "*"
        },
    }

    norm = normalize_policy_document(doc)

    assert "iam:ListUsers" in norm["extracted"]["actions"]