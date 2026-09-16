# mcp-entra-auth

Authentification Entra ID (Azure AD) réutilisable pour un serveur MCP (SDK
officiel `mcp`, classe `MCPServer`) exposé en transport `streamable-http` —
typiquement pour le rendre accessible depuis Microsoft 365 Copilot / Copilot
Studio, sans dupliquer le code de vérification de jeton dans chaque projet.

Extrait à l'origine du projet `charlemagne-mcp`, réutilisé par
`ecoledirecte-admin-mcp` et `edumoov-mcp-prototype`.

## Installation

Dans le `requirements.txt` (ou `pyproject.toml`) du projet consommateur :

```
git+https://github.com/aghulas/mcp-entra-auth.git
```

## Usage

Deux facons de l'utiliser, selon comment le projet consommateur construit son
serveur MCP.

### 1. Serveur construit via une fonction (ex. charlemagne-mcp)

```python
import os
from mcp.server.mcpserver import MCPServer
from mcp_entra_auth import entra_auth_kwargs

INSTRUCTIONS = "..."

def build_server(transport: str) -> MCPServer:
    if transport == "stdio":
        return MCPServer(name="mon-serveur", instructions=INSTRUCTIONS)
    return MCPServer(
        name="mon-serveur",
        instructions=INSTRUCTIONS,
        # Un scope different par serveur : c'est ce qui garantit qu'un jeton
        # valide pour un serveur ne fonctionne jamais sur un autre, même en
        # partageant ce module (voir tests/test_verifier.py).
        **entra_auth_kwargs(required_scope="MonServeur.Read"),
    )
```

Dans `__main__.py` :

```python
import argparse
from .server import build_server, register_tools

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = build_server(args.transport)
    register_tools(server)

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport="streamable-http", host=args.host, port=args.port)
```

### 2. Serveur deja construit au niveau module (ex. ecoledirecte-admin-mcp)

Quand `server.py` fait deja `mcp = MCPServer(...)` au niveau module avec les
outils enregistres via `@mcp.tool()` directement a l'import, restructurer en
`build_server()`/`register_tools()` serait trop invasif pour un simple ajout
de transport HTTP. `apply_entra_auth()` attache l'authentification sur
l'instance existante, sans toucher `server.py` :

```python
# server.py : totalement inchange
from .server import mcp

# __main__.py : seul fichier modifie
from mcp_entra_auth import apply_entra_auth

def main() -> None:
    ...
    if args.transport == "streamable-http":
        apply_entra_auth(mcp, required_scope="MonServeur.Read")
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
```

`apply_entra_auth` doit toujours être appelé juste avant `mcp.run(...)`,
jamais avant (voir sa docstring pour le détail technique : il s'appuie sur le
fait que `MCPServer` lit `settings.auth` / le vérificateur de jeton au moment
de l'appel à `run()`, pas à la construction).

## Variables d'environnement (transport streamable-http uniquement)

| Variable | Obligatoire | Description |
|---|---|---|
| `MCP_ENTRA_TENANT_ID` | oui | ID du tenant Entra ID de l'école |
| `MCP_ENTRA_APP_ID_URI` | oui | Application ID URI de l'app "ressource" côté Entra ID |
| `MCP_ENTRA_ALLOWED_GROUP_ID` | non | ID du groupe de sécurité autorisé (sinon : pas de vérification de groupe, seulement le jeton) |
| `MCP_ENTRA_PUBLIC_URL` | non | URL publique HTTPS du serveur (défaut `http://127.0.0.1:8000/mcp`, à définir en production) |

Le scope requis (`required_scope`) n'est **pas** une variable d'environnement :
il est propre à chaque serveur et passé explicitement dans le code
(`entra_auth_kwargs(required_scope=...)`), pour ne jamais risquer qu'un jeton
valide pour un serveur soit accepté par un autre.

## Sécurité

- Toute erreur de validation (jeton invalide, JWKS injoignable, réponse Entra
  ID inattendue) se traduit par un rejet propre (401), jamais par une
  exception non rattrapée qui remonterait en 500.
- Le cache JWKS est propre à chaque instance de `EntraTokenVerifier` (pas de
  cache global partagé entre instances).
- `stdio` (Claude Desktop) n'utilise jamais ce module — l'authentification
  Entra ID ne s'applique qu'au transport `streamable-http`.

## Tests

```
pip install -e ".[dev]"
pytest
```
