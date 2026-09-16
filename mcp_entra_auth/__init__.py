"""mcp-entra-auth : authentification Entra ID (Azure AD) reutilisable pour un
serveur MCP (SDK `mcp` officiel, classe MCPServer) expose en transport
streamable-http, typiquement pour Microsoft 365 Copilot / Copilot Studio.

Deux facons de l'utiliser cote projet consommateur, selon comment le serveur
est construit :

1. Projet construit via une fonction (ex. build_server(transport)) :

    import os
    from mcp.server.mcpserver import MCPServer
    from mcp_entra_auth import entra_auth_kwargs

    def build_server(transport: str) -> MCPServer:
        if transport == "stdio":
            return MCPServer(name="mon-serveur", instructions="...")
        return MCPServer(
            name="mon-serveur",
            instructions="...",
            **entra_auth_kwargs(required_scope="MonServeur.Read"),
        )

2. Projet avec un serveur deja construit au niveau module (`mcp = MCPServer(...)`
   avec les outils enregistres via @mcp.tool() a l'import) :

    # server.py : inchange
    from mcp.server.mcpserver import MCPServer
    mcp = MCPServer(name="mon-serveur", instructions="...")

    @mcp.tool()
    def mon_outil(...): ...

    # __main__.py : seul fichier modifie
    from .server import mcp
    from mcp_entra_auth import apply_entra_auth

    def main() -> None:
        if transport_http:
            apply_entra_auth(mcp, required_scope="MonServeur.Read")
        mcp.run(transport=...)

Variables d'environnement lues par defaut (voir EntraTokenVerifier,
entra_auth_kwargs et apply_entra_auth pour les surcharger explicitement au
lieu de passer par les variables d'environnement) :
  MCP_ENTRA_TENANT_ID          - ID du tenant Entra ID (obligatoire en http)
  MCP_ENTRA_APP_ID_URI         - Application ID URI de l'app "ressource" (obligatoire)
  MCP_ENTRA_ALLOWED_GROUP_ID   - optionnel, ID de groupe de securite autorise
  MCP_ENTRA_PUBLIC_URL         - URL publique du serveur (defaut http://127.0.0.1:8000/mcp)
"""

from .verifier import EntraTokenVerifier, apply_entra_auth, entra_auth_kwargs

__all__ = ["EntraTokenVerifier", "entra_auth_kwargs", "apply_entra_auth"]
__version__ = "0.2.0"
