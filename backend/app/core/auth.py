"""
MailSentinel AI - Enterprise Authentication & Role-Based Access Control (RBAC)

Provides production-ready authentication using Clerk with Google OAuth & API keys:
- Cryptographically verifies Clerk JWTs (RS256) via Clerk JWKS.
- Validates token expiration, issuer (iss), and authorized parties (azp).
- Never trusts client-supplied user IDs, roles, or identity headers.
- Implements secure server-side RBAC: 'Admin', 'SOC Analyst', 'Customer'.
- Assigns 'Customer' role by default for new public registrations.
- Preserves internal developer & automated agent API keys for regression resilience.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import time
import base64
from fastapi import Header, HTTPException, status, Depends
try:
    from jose import jwt, JWTError
    from jose.exceptions import ExpiredSignatureError, JWTClaimsError
except ImportError:
    jwt = None
    JWTError = Exception
    ExpiredSignatureError = Exception
    JWTClaimsError = Exception
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger


# Enterprise RBAC Role Definitions
ROLE_ADMIN = "Admin"
ROLE_SOC_ANALYST = "SOC Analyst"
ROLE_CUSTOMER = "Customer"
DEFAULT_ROLE = ROLE_CUSTOMER
VALID_ROLES = {ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_CUSTOMER}


@dataclass
class AuthenticatedUser:
    """Authenticated user / analyst security context derived strictly on the server."""
    id: str
    email: Optional[str] = None
    role: str = ROLE_CUSTOMER
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    provider: str = "clerk"  # "clerk", "oauth_google", "api_key"
    claims: Optional[Dict[str, Any]] = None


# Backward-compatible alias for existing SOC investigator modules
AuthenticatedAnalyst = AuthenticatedUser


# Valid internal API keys for automated agents and local regression tests
VALID_ANALYST_CREDENTIALS: Dict[str, AuthenticatedUser] = {
    "mailsentinel-soc-analyst-key-alpha": AuthenticatedUser(
        id="analyst-alpha-001",
        role=ROLE_SOC_ANALYST,
        email="analyst.alpha@mailsentinel.internal",
        provider="api_key"
    ),
    "mailsentinel-soc-analyst-key-beta": AuthenticatedUser(
        id="analyst-beta-002",
        role=ROLE_SOC_ANALYST,
        email="analyst.beta@mailsentinel.internal",
        provider="api_key"
    ),
    # Default development key for local testing
    "mailsentinel-dev-secret-key-2026": AuthenticatedUser(
        id="analyst-default-dev",
        role=ROLE_ADMIN,
        email="lead.architect@mailsentinel.local",
        provider="api_key"
    ),
    # Dedicated demo key for interview evaluation mode
    "mailsentinel-demo-analyst-key": AuthenticatedUser(
        id="demo-analyst",
        role=ROLE_SOC_ANALYST,
        email="demo.analyst@mailsentinel.ai",
        first_name="Demo",
        last_name="Analyst",
        provider="demo"
    )
}


class ClerkJwksManager:
    """
    Manages in-memory caching and fetching of Clerk JWKS public keys.
    Prevents repeated network queries while respecting cache TTLs.
    """
    def __init__(self):
        self._cached_jwks: Optional[Dict[str, Any]] = None
        self._cache_timestamp: float = 0.0
        self._test_jwks: Optional[Dict[str, Any]] = None

    def set_test_jwks(self, jwks: Optional[Dict[str, Any]]) -> None:
        """Injects test JWKS for unit testing without live network calls."""
        self._test_jwks = jwks

    async def get_jwks(self) -> Dict[str, Any]:
        """Returns the current JWKS, fetching from Clerk if cache is expired."""
        if self._test_jwks is not None:
            return self._test_jwks

        now = time.time()
        if self._cached_jwks and (now - self._cache_timestamp < settings.CLERK_JWKS_CACHE_TTL_SECONDS):
            return self._cached_jwks

        jwks_url = self._resolve_jwks_url()
        if not jwks_url:
            return {"keys": []}

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(jwks_url)
                if res.status_code == 200:
                    self._cached_jwks = res.json()
                    self._cache_timestamp = now
                    logger.info("Successfully refreshed Clerk JWKS keys.")
                    return self._cached_jwks
                else:
                    logger.error("Failed to fetch Clerk JWKS: HTTP %d", res.status_code)
        except Exception as exc:
            logger.error("Error communicating with Clerk JWKS endpoint: %s", exc)

        return self._cached_jwks or {"keys": []}

    def _resolve_jwks_url(self) -> Optional[str]:
        """Constructs the JWKS URL based on configured settings or derives from publishable key."""
        if settings.CLERK_ISSUER:
            base = settings.CLERK_ISSUER.rstrip("/")
            return f"{base}/.well-known/jwks.json"

        # Auto-derive from publishable key if available
        if settings.CLERK_PUBLISHABLE_KEY and "_" in settings.CLERK_PUBLISHABLE_KEY:
            try:
                parts = settings.CLERK_PUBLISHABLE_KEY.split("_", 2)
                if len(parts) >= 3:
                    raw_b64 = parts[2]
                    padded = raw_b64 + "=" * ((4 - len(raw_b64) % 4) % 4)
                    domain = base64.b64decode(padded).decode("utf-8", errors="ignore").rstrip("$")
                    if domain and "." in domain:
                        return f"https://{domain}/.well-known/jwks.json"
            except Exception as e:
                logger.debug("Could not derive JWKS URL from CLERK_PUBLISHABLE_KEY: %s", e)

        return None


# Global JWKS manager singleton
clerk_jwks_manager = ClerkJwksManager()


async def verify_clerk_jwt(token: str) -> AuthenticatedUser:
    """
    Cryptographically verifies a Clerk-issued JWT token.
    Validates:
    - RS256 signature against Clerk JWKS
    - Token expiration (exp)
    - Issuer (iss)
    - Authorized party (azp)
    - Derives authenticated identity and role
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as exc:
        logger.warning("JWT header decoding failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token header.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    kid = unverified_header.get("kid")
    jwks = await clerk_jwks_manager.get_jwks()
    keys = jwks.get("keys", [])
    matching_key = next((k for k in keys if k.get("kid") == kid), None)

    # If key is missing from cache, force a refresh once
    if not matching_key and not clerk_jwks_manager._test_jwks:
        clerk_jwks_manager._cache_timestamp = 0
        jwks = await clerk_jwks_manager.get_jwks()
        keys = jwks.get("keys", [])
        matching_key = next((k for k in keys if k.get("kid") == kid), None)

    if not matching_key:
        logger.warning("No matching public key found in JWKS for kid: %s", kid)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unable to verify token signature: Unknown key identifier.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    decode_options = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "verify_aud": False  # Clerk tokens rely on azp rather than aud
    }

    try:
        claims = jwt.decode(
            token,
            matching_key,
            algorithms=["RS256"],
            options=decode_options
        )
    except ExpiredSignatureError:
        logger.info("Authentication rejected: Expired Clerk session token.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Re-authentication required.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTClaimsError as exc:
        logger.warning("Authentication rejected: Invalid JWT claims (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token claims: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTError as exc:
        logger.warning("Authentication rejected: Cryptographic verification failed (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # 1. Validate Issuer if configured
    if settings.CLERK_ISSUER:
        token_iss = claims.get("iss")
        if token_iss != settings.CLERK_ISSUER:
            logger.warning("Issuer mismatch: token '%s' vs configured '%s'", token_iss, settings.CLERK_ISSUER)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token issuer is invalid.",
                headers={"WWW-Authenticate": "Bearer"}
            )

    # 2. Validate Authorized Party (azp) if present and configured
    token_azp = claims.get("azp")
    if token_azp and settings.CLERK_AUTHORIZED_PARTIES:
        if token_azp not in settings.CLERK_AUTHORIZED_PARTIES:
            logger.warning("Unauthorized client party: %s", token_azp)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unauthorized client party '{token_azp}'.",
                headers={"WWW-Authenticate": "Bearer"}
            )

    # 3. Extract Verified User ID (sub is guaranteed in Clerk tokens)
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject identity.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # 4. Resolve Email
    email = claims.get("email") or claims.get("primary_email_address")
    if not email:
        email_addresses = claims.get("email_addresses")
        if isinstance(email_addresses, list) and email_addresses:
            email = email_addresses[0]

    # 5. Extract Server-Enforced Role
    # Check public_metadata, metadata, or role claim
    public_meta = claims.get("public_metadata") or claims.get("metadata") or {}
    raw_role = public_meta.get("role") or claims.get("role")

    # Only assign privileged roles if explicitly set and valid; default to Customer
    assigned_role = DEFAULT_ROLE
    if raw_role in VALID_ROLES:
        assigned_role = raw_role

    provider = "oauth_google" if "google" in claims.get("external_accounts", "") or "google" in str(claims).lower() else "clerk"

    return AuthenticatedUser(
        id=user_id,
        email=email,
        role=assigned_role,
        first_name=claims.get("first_name"),
        last_name=claims.get("last_name"),
        provider=provider,
        claims=claims
    )


async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> AuthenticatedUser:
    """
    FastAPI dependency that enforces server-side authentication.
    Supports:
    1. Clerk-issued RS256 JWT tokens (Bearer ey...)
    2. Validated server-side internal API keys (e.g. for background agents)
    Never trusts client-supplied user IDs or role headers.
    """
    provided_token = None

    if authorization and authorization.lower().startswith("bearer "):
        provided_token = authorization.split(" ", 1)[1].strip()
    elif x_api_key:
        provided_token = x_api_key.strip()

    if not provided_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Path A: Clerk RS256 JWT verification (Primary & Mandatory for all end-user traffic)
    if provided_token.startswith("ey"):
        return await verify_clerk_jwt(provided_token)

    # Path B: Internal automated agent API key (Scoped strictly to development/testing)
    if settings.DEBUG and provided_token in VALID_ANALYST_CREDENTIALS:
        return VALID_ANALYST_CREDENTIALS[provided_token]

    logger.warning("Authentication rejected: Invalid credential format or unverified token.")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Valid Clerk Bearer token required.",
        headers={"WWW-Authenticate": "Bearer"}
    )


# Alias for backward compatibility with existing SOC modules
get_current_analyst = get_current_user


def require_roles(allowed_roles: List[str]):
    """
    FastAPI dependency factory enforcing server-side Role-Based Access Control (RBAC).
    Rejects users who lack any of the required roles with HTTP 403 Forbidden.
    """
    async def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            logger.warning(
                "RBAC Access Denied: User %s (Role: '%s') attempted to access endpoint restricted to %s",
                user.id,
                user.role,
                allowed_roles
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required role: {', '.join(allowed_roles)}. Current role: '{user.role}'."
            )
        return user
    return role_checker


# Role-specific dependency shortcuts
require_admin = require_roles([ROLE_ADMIN])
require_soc_analyst = require_roles([ROLE_ADMIN, ROLE_SOC_ANALYST])
require_customer = require_roles([ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_CUSTOMER])
