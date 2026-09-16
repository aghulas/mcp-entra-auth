"""Verification de jetons Entra ID (Azure AD) pour un serveur MCP en
transport streamable-http. Sans lien avec un projet particulier - le scope
requis est parametrable (chaque serveur MCP a le sien).
"""

from __future__ import annotations

import logging
import os
import time

import httpx
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

logger = logging.getLogger("mcp_entra_auth")

_JWKS_TTL_SECONDS = 3600


class EntraTokenVerifier(TokenVerifier):
    """Valide un jeton Bearer Entra ID (Azure AD v2.0).

    Verifie, dans l'ordre : signature (JWKS du tenant), issuer, audience,
    expiration, puis presence du scope requis. Verifie ensuite
    l'appartenance au groupe autorise si allowed_group_id est renseigne.

    Toute erreur (jeton invalide, JWKS injoignable, reponse Entra ID
    inattendue...) se traduit par un rejet propre (None -> 401 cote MCP),
    jamais par une exception non rattrapee qui remonterait en 500.
    """

    def __init__(
        self,
        tenant_id: str | None = None,
        app_id_uri: str | None = None,
        required_scope: str | None = None,
        allowed_group_id: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.tenant_id = tenant_id or _require_env("MCP_ENTRA_TENANT_ID")
        self.app_id_uri = app_id_uri or _require_env("MCP_ENTRA_APP_ID_URI")
        self.required_scope = required_scope or _require_env("MCP_ENTRA_REQUIRED_SCOPE")
        self.allowed_group_id = allowed_group_id or os.environ.get("MCP_ENTRA_ALLOWED_GROUP_ID")
        self.issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
        self._http = http_client or httpx.Client(timeout=5.0)
        # Cache JWKS propre a cette instance (jamais de cache module-level partage
        # entre instances - source d'un bug de tests decouvert lors du developpement
        # initial : une instance heritait du cache d'une autre).
        self._jwks_cache: dict | None = None
        self._jwks_fetched_at: float = 0.0

    def _jwks_uri(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"

    def _get_jwks(self) -> dict:
        now = time.time()
        if self._jwks_cache is None or now - self._jwks_fetched_at > _JWKS_TTL_SECONDS:
            resp = self._http.get(self._jwks_uri())
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._jwks_fetched_at = now
        return self._jwks_cache

    def _signing_key(self, token: str):
        jwks = self._get_jwks()
        header = jwt.get_unverified_header(token)
        for key in jwks["keys"]:
            if key["kid"] == header["kid"]:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        # Cle non trouvee : peut-etre une rotation recente, on force un refresh unique.
        self._jwks_cache = None
        jwks = self._get_jwks()
        for key in jwks["keys"]:
            if key["kid"] == header["kid"]:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        raise jwt.InvalidTokenError(f"Cle de signature introuvable (kid={header.get('kid')})")

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = self._signing_key(token)
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=["RS256"],
                audience=self.app_id_uri,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            logger.info("Jeton rejete (invalide) : %s", exc)
            return None
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            logger.warning("Jeton rejete (JWKS/Entra ID injoignable ou reponse inattendue) : %s", exc)
            return None

        scopes = claims.get("scp", "").split()
        if self.required_scope not in scopes:
            return None

        if self.allowed_group_id:
            groups = claims.get("groups", [])
            if self.allowed_group_id not in groups:
                return None

        return AccessToken(
            token=token,
            client_id=claims.get("appid", claims.get("azp", "unknown")),
            scopes=scopes,
            expires_at=claims.get("exp"),
        )


def entra_auth_kwargs(
    required_scope: str,
    *,
    tenant_id: str | None = None,
    app_id_uri: str | None = None,
    allowed_group_id: str | None = None,
    public_url: str | None = None,
) -> dict:
    """Construit les kwargs `token_verifier=` et `auth=` a passer directement
    au constructeur de MCPServer, pour un transport streamable-http avec
    authentification Entra ID.

    required_scope : nom du scope Entra ID que ce serveur exige (ex.
        "Charlemagne.Read", "EcoleDirecteAdmin.Read", "Edumoov.Read") -
        propre a chaque serveur, jamais partage entre projets.
    Les autres parametres, si omis, sont lus depuis les variables
    d'environnement MCP_ENTRA_TENANT_ID / MCP_ENTRA_APP_ID_URI /
    MCP_ENTRA_ALLOWED_GROUP_ID / MCP_ENTRA_PUBLIC_URL.
    """
    from mcp.server.auth.settings import AuthSettings
    from pydantic import AnyHttpUrl

    verifier = EntraTokenVerifier(
        tenant_id=tenant_id,
        app_id_uri=app_id_uri,
        required_scope=required_scope,
        allowed_group_id=allowed_group_id,
    )
    resolved_public_url = (
        public_url
        or os.environ.get("MCP_ENTRA_PUBLIC_URL")
        or "http://127.0.0.1:8000/mcp"
    )
    return {
        "token_verifier": verifier,
        "auth": AuthSettings(
            issuer_url=AnyHttpUrl(verifier.issuer),
            resource_server_url=AnyHttpUrl(resolved_public_url),
            # False : c'est EntraTokenVerifier.verify_token qui verifie deja
            # l'audience (aud = Application ID URI) a l'interieur du JWT.
            validate_token_resource=False,
        ),
    }


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Variable d'environnement {name} manquante - requise pour le transport "
            "streamable-http avec authentification Entra ID."
        )
    return value
