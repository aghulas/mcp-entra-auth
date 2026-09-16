"""mcp-entra-auth : authentification Entra ID (Azure AD) reutilisable pour un
serveur MCP (SDK `mcp` officiel, classe MCPServer) expose en transport
streamable-http, typiquement pour Microsoft 365 Copilot / Copilot Studio.

Usage typique dans un projet consommateur (server.py) :

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

Variables d'environnement lues par defaut (voir EntraTokenVerifier et
entra_auth_kwargs pour les surcharger explicitement au lieu de passer par les
variables d'environnement) :
  MCP_ENTRA_TENANT_ID          - ID du tenant Entra ID (obligatoire en http)
  MCP_ENTRA_APP_ID_URI         - Application ID URI de l'app "ressource" (obligatoire)
  MCP_ENTRA_ALLOWED_GROUP_ID   - optionnel, ID de groupe de securite autorise
  MCP_ENTRA_PUBLIC_URL         - URL publique du serveur (defaut http://127.0.0.1:8000/mcp)
"""

from .verifier import EntraTokenVerifier, entra_auth_kwargs

__all__ = ["EntraTokenVerifier", "entra_auth_kwargs"]
__version__ = "0.1.0"
