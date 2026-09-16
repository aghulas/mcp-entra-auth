"""Valide EntraTokenVerifier avec un tenant Entra ID simule (paire RSA locale,
aucun appel reseau reel, aucune donnee personnelle)."""

import asyncio
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_entra_auth import EntraTokenVerifier, entra_auth_kwargs

TENANT_ID = "11111111-1111-1111-1111-111111111111"
APP_ID_URI = "api://mcp-test"
REQUIRED_SCOPE = "Test.Read"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
GROUP_OK = "grp-personnel-autorise"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_numbers = private_key.public_key().public_numbers()


def _b64url_uint(n: int) -> str:
    import base64

    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-kid-1",
            "use": "sig",
            "alg": "RS256",
            "n": _b64url_uint(public_numbers.n),
            "e": _b64url_uint(public_numbers.e),
        }
    ]
}


def make_token(**overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": APP_ID_URI,
        "exp": now + 3600,
        "iat": now,
        "scp": REQUIRED_SCOPE,
        "groups": [GROUP_OK],
        "appid": "test-client",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-kid-1"})


class FakeTransport(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert "discovery/v2.0/keys" in str(request.url)
        return httpx.Response(200, json=JWKS)


class BrokenTransport(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connexion refusee (simulee)")


def make_verifier(**kwargs) -> EntraTokenVerifier:
    client = httpx.Client(transport=FakeTransport())
    return EntraTokenVerifier(
        tenant_id=TENANT_ID,
        app_id_uri=APP_ID_URI,
        required_scope=REQUIRED_SCOPE,
        http_client=client,
        **kwargs,
    )


def run(coro):
    return asyncio.run(coro)


def test_jeton_valide_accepte():
    verifier = make_verifier(allowed_group_id=GROUP_OK)
    token = make_token()
    result = run(verifier.verify_token(token))
    assert result is not None
    assert result.client_id == "test-client"
    assert REQUIRED_SCOPE in result.scopes


def test_mauvaise_audience_rejetee():
    verifier = make_verifier()
    token = make_token(aud="api://autre-app")
    assert run(verifier.verify_token(token)) is None


def test_jeton_expire_rejete():
    verifier = make_verifier()
    token = make_token(exp=int(time.time()) - 10)
    assert run(verifier.verify_token(token)) is None


def test_scope_manquant_rejete():
    verifier = make_verifier()
    token = make_token(scp="AutreScope")
    assert run(verifier.verify_token(token)) is None


def test_mauvais_issuer_rejete():
    verifier = make_verifier()
    token = make_token(iss="https://login.microsoftonline.com/autre-tenant/v2.0")
    assert run(verifier.verify_token(token)) is None


def test_groupe_non_autorise_rejete():
    verifier = make_verifier(allowed_group_id="grp-different")
    token = make_token()
    assert run(verifier.verify_token(token)) is None


def test_sans_contrainte_de_groupe_jeton_valide_accepte():
    verifier = make_verifier()
    token = make_token(groups=["nimporte-quel-groupe"])
    assert run(verifier.verify_token(token)) is not None


def test_jwks_injoignable_rejette_proprement_sans_exception():
    client = httpx.Client(transport=BrokenTransport())
    verifier = EntraTokenVerifier(
        tenant_id=TENANT_ID,
        app_id_uri=APP_ID_URI,
        required_scope=REQUIRED_SCOPE,
        http_client=client,
    )
    token = make_token()
    assert run(verifier.verify_token(token)) is None


def test_jeton_mal_forme_rejette_proprement():
    verifier = make_verifier()
    assert run(verifier.verify_token("ceci.nest.pasunjeton")) is None


def test_deux_serveurs_scopes_differents_sont_etanches():
    """Le jeton valide pour le scope d'un serveur ne doit jamais passer pour un
    autre serveur qui exige un scope different - ce qui garantit l'isolation
    entre Charlemagne / EcoleDirecte / Edumoov meme s'ils partagent ce module."""
    verifier_a = make_verifier()  # exige Test.Read
    token_pour_autre_scope = make_token(scp="AutreServeur.Read")
    assert run(verifier_a.verify_token(token_pour_autre_scope)) is None


def test_entra_auth_kwargs_construit_les_bons_objets(monkeypatch):
    monkeypatch.setenv("MCP_ENTRA_TENANT_ID", TENANT_ID)
    monkeypatch.setenv("MCP_ENTRA_APP_ID_URI", APP_ID_URI)
    kwargs = entra_auth_kwargs(required_scope="MonServeur.Read", public_url="https://example.test/mcp")
    assert set(kwargs.keys()) == {"token_verifier", "auth"}
    assert kwargs["token_verifier"].required_scope == "MonServeur.Read"
    assert str(kwargs["auth"].resource_server_url) == "https://example.test/mcp"


def test_entra_auth_kwargs_sans_tenant_id_leve_une_erreur_claire(monkeypatch):
    monkeypatch.delenv("MCP_ENTRA_TENANT_ID", raising=False)
    with pytest.raises(RuntimeError, match="MCP_ENTRA_TENANT_ID"):
        entra_auth_kwargs(required_scope="MonServeur.Read")


# --- apply_entra_auth (serveur deja construit, cf. ecoledirecte-admin-mcp) ---

from mcp_entra_auth import apply_entra_auth  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402


def test_apply_entra_auth_attache_verifier_et_auth_settings(monkeypatch):
    monkeypatch.setenv("MCP_ENTRA_TENANT_ID", TENANT_ID)
    monkeypatch.setenv("MCP_ENTRA_APP_ID_URI", APP_ID_URI)
    server = MCPServer(name="deja-construit")
    assert server.settings.auth is None

    result = apply_entra_auth(server, required_scope="MonServeur.Read")

    assert result is server
    assert server.settings.auth is not None
    assert server._token_verifier is not None
    assert server._token_verifier.required_scope == "MonServeur.Read"


def test_apply_entra_auth_conserve_les_outils_deja_enregistres(monkeypatch):
    """Le cas reel : @mcp.tool() a deja tourne a l'import, avant apply_entra_auth."""
    monkeypatch.setenv("MCP_ENTRA_TENANT_ID", TENANT_ID)
    monkeypatch.setenv("MCP_ENTRA_APP_ID_URI", APP_ID_URI)
    server = MCPServer(name="deja-construit")

    @server.tool()
    def mon_outil() -> str:
        return "ok"

    apply_entra_auth(server, required_scope="MonServeur.Read")

    run(server.list_tools())  # ne doit pas lever - l'ajout d'auth ne touche pas aux outils


def test_apply_entra_auth_fonctionne_en_conditions_reelles(monkeypatch):
    """Verifie le comportement live (pas seulement la presence des attributs) :
    un serveur construit sans auth, sur lequel apply_entra_auth() est appele
    juste avant run(), doit effectivement rejeter une requete sans jeton -
    confirme que MCPServer.run_streamable_http_async() lit bien
    self.settings.auth / self._token_verifier au moment de l'appel, et pas
    seulement a la construction (ce qui validerait l'approche pour un projet
    dont les outils sont deja enregistres sur l'instance module-level)."""
    import socket
    import threading
    import time as time_mod

    import uvicorn

    monkeypatch.setenv("MCP_ENTRA_TENANT_ID", TENANT_ID)
    monkeypatch.setenv("MCP_ENTRA_APP_ID_URI", APP_ID_URI)

    server = MCPServer(name="deja-construit-live")

    @server.tool()
    def mon_outil() -> str:
        return "ok"

    apply_entra_auth(server, required_scope="MonServeur.Read")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    app = server.streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    uv_server = uvicorn.Server(config)

    thread = threading.Thread(target=uv_server.run, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            try:
                httpx.get(f"http://127.0.0.1:{port}/mcp", timeout=0.2)
                break
            except httpx.TransportError:
                time_mod.sleep(0.1)

        resp = httpx.post(
            f"http://127.0.0.1:{port}/mcp",
            headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            timeout=5,
        )
        assert resp.status_code == 401
    finally:
        uv_server.should_exit = True
        thread.join(timeout=5)
