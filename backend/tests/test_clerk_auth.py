"""
MailSentinel AI - Enterprise Clerk Authentication & RBAC Test Suite
Validates:
- RS256 Clerk JWT signature verification
- Token expiration rejection
- Issuer and authorized parties enforcement
- Role derivation (Admin, SOC Analyst, Customer default)
- API endpoint RBAC protection
- Backward-compatible API key authentication
"""

import time
import pytest
from httpx import AsyncClient, ASGITransport
from jose import jwt, jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from backend.app.main import app
from backend.app.core.auth import (
    clerk_jwks_manager,
    ROLE_ADMIN,
    ROLE_SOC_ANALYST,
    ROLE_CUSTOMER
)
from backend.app.core.config import settings


# Generate RSA key pair for testing
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_priv_pem = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

_pub_pem = _private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

TEST_KID = "test-clerk-key-001"
_jwk_dict = jwk.RSAKey(key=_pub_pem, algorithm="RS256").to_dict()
_jwk_dict["kid"] = TEST_KID
_jwk_dict["use"] = "sig"

TEST_JWKS = {"keys": [_jwk_dict]}
TEST_ISSUER = "https://clerk.mailsentinel.dev"


def create_test_token(
    user_id: str = "user_clerk_test_123",
    email: str = "test.analyst@mailsentinel.ai",
    role: str = None,
    expires_in_seconds: int = 3600,
    issuer: str = TEST_ISSUER,
    azp: str = "http://localhost:5173",
    kid: str = TEST_KID,
    tamper_private_key: str = None
) -> str:
    """Helper to generate signed RS256 JWT tokens for testing."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "email": email,
        "exp": now + expires_in_seconds,
        "iat": now,
        "nbf": now - 10,
        "iss": issuer,
        "azp": azp
    }
    if role:
        payload["public_metadata"] = {"role": role}

    signing_key = tamper_private_key or _priv_pem
    return jwt.encode(payload, signing_key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture(autouse=True)
def setup_clerk_test_environment(monkeypatch):
    """Sets up JWKS and test environment for every test."""
    clerk_jwks_manager.set_test_jwks(TEST_JWKS)
    monkeypatch.setattr(settings, "CLERK_ISSUER", TEST_ISSUER)
    monkeypatch.setattr(settings, "CLERK_AUTHORIZED_PARTIES", ["http://localhost:5173", "http://127.0.0.1:5173"])
    yield
    clerk_jwks_manager.set_test_jwks(None)


@pytest.mark.asyncio
async def test_valid_clerk_jwt_admin():
    """Verify valid Clerk JWT with Admin role is authenticated."""
    token = create_test_token(user_id="user_admin_001", role=ROLE_ADMIN)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "user_admin_001"
        assert data["role"] == ROLE_ADMIN
        assert "admin:manage_users" in data["permissions"]


@pytest.mark.asyncio
async def test_new_user_default_customer_role():
    """Verify newly registered public users receive Customer role by default."""
    token = create_test_token(user_id="user_public_new", role=None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "user_public_new"
        assert data["role"] == ROLE_CUSTOMER


@pytest.mark.asyncio
async def test_expired_token_rejection():
    """Verify expired tokens are rejected with 401."""
    expired_token = create_test_token(expires_in_seconds=-60)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        assert res.status_code == 401
        assert "expired" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_tampered_signature_rejection():
    """Verify tokens signed with an unknown or forged key are rejected with 401."""
    # Generate an untrusted rogue key
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_pem = rogue_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    forged_token = create_test_token(tamper_private_key=rogue_pem)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged_token}"})
        assert res.status_code == 401
        assert "signature" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_issuer_mismatch_rejection():
    """Verify tokens from unauthorized issuers are rejected."""
    bad_iss_token = create_test_token(issuer="https://unauthorized-phishing.clerk.dev")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad_iss_token}"})
        assert res.status_code == 401
        assert "issuer" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_unauthorized_party_azp_rejection():
    """Verify tokens from unauthorized frontend origins/parties are rejected."""
    bad_azp_token = create_test_token(azp="http://attacker-site.com")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad_azp_token}"})
        assert res.status_code == 401
        assert "unauthorized client party" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rbac_customer_restricted_from_admin_endpoints():
    """Verify Customer role is rejected from Admin endpoints with 403."""
    customer_token = create_test_token(user_id="user_customer_01", role=ROLE_CUSTOMER)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Customer check: allowed
        res_cust = await ac.get("/api/v1/auth/customer-check", headers={"Authorization": f"Bearer {customer_token}"})
        assert res_cust.status_code == 200

        # 2. SOC check: rejected
        res_soc = await ac.get("/api/v1/auth/soc-check", headers={"Authorization": f"Bearer {customer_token}"})
        assert res_soc.status_code == 403
        assert "insufficient privileges" in res_soc.json()["detail"].lower()

        # 3. Admin check: rejected
        res_admin = await ac.get("/api/v1/auth/admin-check", headers={"Authorization": f"Bearer {customer_token}"})
        assert res_admin.status_code == 403
        assert "insufficient privileges" in res_admin.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rbac_soc_analyst_authorized_for_soc_restricted_from_admin():
    """Verify SOC Analyst is allowed on SOC endpoints but rejected from Admin."""
    soc_token = create_test_token(user_id="user_soc_01", role=ROLE_SOC_ANALYST)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Allowed on SOC check
        res_soc = await ac.get("/api/v1/auth/soc-check", headers={"Authorization": f"Bearer {soc_token}"})
        assert res_soc.status_code == 200

        # Rejected from Admin check
        res_admin = await ac.get("/api/v1/auth/admin-check", headers={"Authorization": f"Bearer {soc_token}"})
        assert res_admin.status_code == 403


@pytest.mark.asyncio
async def test_rbac_admin_has_full_access():
    """Verify Admin is allowed on all endpoints."""
    admin_token = create_test_token(user_id="user_superadmin", role=ROLE_ADMIN)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res_admin = await ac.get("/api/v1/auth/admin-check", headers={"Authorization": f"Bearer {admin_token}"})
        assert res_admin.status_code == 200
        res_soc = await ac.get("/api/v1/auth/soc-check", headers={"Authorization": f"Bearer {admin_token}"})
        assert res_soc.status_code == 200


@pytest.mark.asyncio
async def test_backward_compatible_dev_api_key():
    """Verify existing developer API keys continue to work seamlessly."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": "Bearer mailsentinel-dev-secret-key-2026"})
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "analyst-default-dev"
        assert data["role"] == ROLE_ADMIN


@pytest.mark.asyncio
async def test_google_oauth_provider_claim_detection():
    """Verify tokens identifying Google external accounts map provider to oauth_google."""
    now = int(time.time())
    payload = {
        "sub": "user_google_oauth_test",
        "email": "analyst.google@gmail.com",
        "exp": now + 3600,
        "iat": now,
        "nbf": now - 10,
        "iss": TEST_ISSUER,
        "azp": "http://localhost:5173",
        "external_accounts": "google_oauth2"
    }
    google_token = jwt.encode(payload, _priv_pem, algorithm="RS256", headers={"kid": TEST_KID})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {google_token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["provider"] == "oauth_google"


def test_jwks_auto_derivation_from_publishable_key(monkeypatch):
    """Verify JWKS URL correctly decodes domain from base64 publishable key."""
    # pk_test_Y2xlcmsuZXhhbXBsZS5jb20k -> clerk.example.com
    monkeypatch.setattr(settings, "CLERK_ISSUER", "")
    monkeypatch.setattr(settings, "CLERK_PUBLISHABLE_KEY", "pk_test_Y2xlcmsuZXhhbXBsZS5jb20k")
    url = clerk_jwks_manager._resolve_jwks_url()
    assert url == "https://clerk.example.com/.well-known/jwks.json"

