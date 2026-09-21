"""Real Cognito sessions: sign in -> use the session -> refresh -> sign out (the token stops working), plus the
credential-attack basics (wrong password, unknown user, no account enumeration). Uses the dedicated test client and
test users; needs no AWS credentials."""
import json
import os

import pytest
import requests

from conftest import API_BASE, COGNITO_CLIENT_ID, USER_A

pytestmark = [pytest.mark.live, pytest.mark.needs_token, pytest.mark.flow("E2E-AUTH-002"), pytest.mark.severity("P0")]
PASSWORD = os.environ.get("E2E_PASSWORD", "")


def cognito(target, body):
    r = requests.post("https://cognito-idp.eu-west-1.amazonaws.com/", timeout=30,
                      headers={"X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}", "Content-Type": "application/x-amz-json-1.1"},
                      data=json.dumps(body))
    return r.status_code, (r.json() if r.text else {})


def sign_in(username=USER_A, password=PASSWORD):
    return cognito("InitiateAuth", {"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": COGNITO_CLIENT_ID,
                                    "AuthParameters": {"USERNAME": username, "PASSWORD": password}})


def dashboard(token):
    return requests.get(f"{API_BASE}/get-dashboard-data", headers={"Authorization": f"Bearer {token}"}, timeout=30).status_code


@pytest.mark.skipif(not PASSWORD, reason="blocked: E2E_PASSWORD not set")
def test_sign_in_use_refresh_and_sign_out_lifecycle(step):
    with step("sign in with the correct password"):
        s, d = sign_in()
        assert s == 200 and {"AccessToken", "RefreshToken"} <= set(d["AuthenticationResult"])
        access, refresh = d["AuthenticationResult"]["AccessToken"], d["AuthenticationResult"]["RefreshToken"]
    with step("the session works against the API"):
        assert dashboard(access) == 200
    with step("a refresh token yields a new working session"):
        s, d = cognito("InitiateAuth", {"AuthFlow": "REFRESH_TOKEN_AUTH", "ClientId": COGNITO_CLIENT_ID, "AuthParameters": {"REFRESH_TOKEN": refresh}})
        assert s == 200 and dashboard(d["AuthenticationResult"]["AccessToken"]) == 200
    with step("signing out revokes the session: the old token is rejected"):
        s, _ = cognito("RevokeToken", {"Token": refresh, "ClientId": COGNITO_CLIENT_ID})
        assert s == 200
        assert dashboard(access) == 401


def test_wrong_password_is_rejected():
    s, d = sign_in(password="Definitely-Wrong-1!")
    assert s == 400 and d["__type"] == "NotAuthorizedException"


def test_unknown_user_is_indistinguishable_from_a_wrong_password():
    """No account enumeration: an attacker must not learn whether an email is registered."""
    s1, d1 = sign_in(password="Definitely-Wrong-1!")
    s2, d2 = sign_in(username="nobody-registered-here@niagaros.test", password="Definitely-Wrong-1!")
    assert (s1, d1["__type"], d1["message"]) == (s2, d2["__type"], d2["message"])


@pytest.mark.parametrize("bad", ["", "   ", "not-a-token"])
def test_refresh_with_invalid_token_fails(bad):
    s, _ = cognito("InitiateAuth", {"AuthFlow": "REFRESH_TOKEN_AUTH", "ClientId": COGNITO_CLIENT_ID, "AuthParameters": {"REFRESH_TOKEN": bad}})
    assert s == 400


@pytest.mark.flow("E2E-AUTH-002")
def test_the_real_login_client_also_prevents_account_enumeration():
    """Only checkable with AWS credentials (local runs); reported as blocked in CI instead of pretending."""
    boto3 = pytest.importorskip("boto3")
    try:
        c = boto3.client("cognito-idp", region_name="eu-west-1")
        pool = os.environ.get("E2E_USER_POOL_ID", "eu-west-1_mHQf9RNTc")
        real = c.describe_user_pool_client(UserPoolId=pool, ClientId="55e12uo3ktbnh9d7sgbm3h4r0p")["UserPoolClient"]
    except Exception as e:  # no credentials / no permission
        pytest.skip(f"blocked: needs AWS credentials to read the app client ({type(e).__name__})")
    assert real.get("PreventUserExistenceErrors") == "ENABLED"
