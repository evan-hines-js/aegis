defmodule Aegis.MCP.OAuth.ProtectedResourceMetadata do
  @moduledoc """
  Implementation of OAuth 2.0 Protected Resource Metadata (RFC 9728) for MCP servers.

  This module handles the discovery mechanism that allows MCP clients to find
  authorization servers associated with this MCP resource server.
  """

  require Logger
  alias Aegis.MCP.OAuth.Config

  @doc """
  Generate the Protected Resource Metadata document according to RFC 9728.

  This metadata document informs MCP clients about:
  - The authorization servers that can issue tokens for this resource
  - The resource identifier (canonical URI)
  - Supported OAuth scopes for this MCP server
  - Supported token types and other OAuth metadata
  """
  @spec generate_metadata(String.t()) :: map()
  def generate_metadata(resource_uri) do
    authorization_servers = get_authorization_servers()

    metadata = %{
      "resource" => resource_uri,
      "authorization_servers" => authorization_servers,
      "scopes_supported" => get_supported_scopes()
    }

    # Add optional metadata if configured
    metadata
    |> maybe_add_bearer_methods_supported()
    |> maybe_add_resource_documentation()
  end

  @doc """
  Get the canonical resource URI for this MCP server.

  The canonical URI follows RFC 8707 Section 2 guidelines:
  - Uses lowercase scheme and host
  - No trailing slash unless semantically significant
  - Includes path if necessary to identify this specific MCP server
  """
  @spec get_canonical_resource_uri(Plug.Conn.t()) :: String.t()
  def get_canonical_resource_uri(conn) do
    scheme = conn.scheme |> to_string() |> String.downcase()
    host = conn.host |> String.downcase()
    port = get_port_string(conn)
    path = get_mcp_path(conn)

    "#{scheme}://#{host}#{port}#{path}"
  end

  @doc """
  Validate that a resource parameter matches this MCP server.

  Per RFC 8707, the resource parameter should identify this specific
  MCP server that the client intends to use the token with.
  """
  @spec validate_resource_parameter(String.t(), String.t()) :: boolean()
  def validate_resource_parameter(resource_param, canonical_uri) do
    # Normalize both URIs for comparison
    normalized_param = normalize_uri(resource_param)
    normalized_canonical = normalize_uri(canonical_uri)

    # Allow exact match or if the resource param is a parent URI
    normalized_param == normalized_canonical or
      String.starts_with?(normalized_canonical, normalized_param <> "/")
  end

  @doc """
  Get the well-known URI paths for metadata discovery.

  Returns a list of paths to try for .well-known discovery according to RFC 9728.
  """
  @spec get_well_known_paths(String.t()) :: [String.t()]
  def get_well_known_paths(mcp_path) do
    base_path = "/.well-known/oauth-protected-resource"

    if mcp_path == "/" or mcp_path == "" do
      [base_path]
    else
      # Try path-specific first, then root
      [
        "#{base_path}#{mcp_path}",
        base_path
      ]
    end
  end

  # Private helper functions

  defp get_authorization_servers do
    # Get configured authorization servers from application config
    config = Application.get_env(:aegis, __MODULE__, [])

    case Keyword.get(config, :authorization_servers) do
      servers when is_list(servers) and length(servers) > 0 ->
        servers

      _ ->
        # Default to OAuth config if no explicit servers configured
        keycloak_base_url = Config.keycloak_base_url()
        realm = Config.keycloak_realm()
        ["#{keycloak_base_url}/realms/#{realm}"]
    end
  end

  @doc """
  Get supported OAuth scopes for this MCP server.

  Per RFC 9728 and MCP OAuth specification, scopes_supported indicates
  the minimal set of scopes necessary for basic MCP functionality.
  Additional scopes may be requested through step-up authorization.

  ## Scope Minimization Strategy

  The MCP spec recommends: "scopes_supported field is intended to represent
  the minimal set of scopes necessary for basic functionality, with additional
  scopes requested incrementally through the step-up authorization flow."

  Default scopes are intentionally minimal to follow the principle of least privilege.
  Clients should request only what they need initially, then use step-up authorization
  (insufficient_scope challenges) to request additional scopes as needed.

  ## MCP Scope Format

  Scopes follow pattern: `<resource_type>:<action>`

  ### Core MCP Scopes (Based on MCP Protocol Methods)

  **Resource Operations:**
  - `resources:read` - Read MCP resources (resources/list, resources/read)
  - `resources:subscribe` - Subscribe to resource updates (resources/subscribe)

  **Tool Operations:**
  - `tools:list` - List available tools (tools/list)
  - `tools:call` - Execute MCP tools (tools/call)

  **Prompt Operations:**
  - `prompts:list` - List available prompts (prompts/list)
  - `prompts:get` - Get prompt details and templates (prompts/get)

  **Filesystem Operations:**
  - `roots:list` - List filesystem roots (roots/list)

  **Sampling Operations:**
  - `sampling:create` - Create sampling messages (sampling/createMessage)

  ### Minimal Scopes (Default)

  The default configuration provides only `resources:read` for basic discovery.
  Clients must use step-up authorization to request additional capabilities.

  ### Recommended Scope Combinations

  - **Read-only discovery**: `["resources:read"]` (default)
  - **Tool execution**: `["resources:read", "tools:list", "tools:call"]`
  - **Prompt access**: `["resources:read", "prompts:list", "prompts:get"]`
  - **Full MCP access**: All scopes (use sparingly, grants broad permissions)

  ## Configuration

  Override default scopes via environment:

      config :aegis, Aegis.MCP.OAuth.ProtectedResourceMetadata,
        scopes_supported: ["resources:read", "tools:list", "tools:call"]

  You can also configure different scope sets for different security contexts:

      config :aegis, Aegis.MCP.OAuth.ProtectedResourceMetadata,
        # Minimal scopes for initial authorization (recommended)
        scopes_supported: ["resources:read"],
        # All available scopes (for documentation/discovery)
        all_scopes: [
          "resources:read",
          "resources:subscribe",
          "tools:list",
          "tools:call",
          "prompts:list",
          "prompts:get",
          "roots:list",
          "sampling:create"
        ]
  """
  @spec get_supported_scopes() :: [String.t()]
  def get_supported_scopes do
    # Allow configuration override for custom scope requirements
    config = Application.get_env(:aegis, __MODULE__, [])

    case Keyword.get(config, :scopes_supported) do
      scopes when is_list(scopes) and length(scopes) > 0 ->
        scopes

      _ ->
        # Minimal default scope following principle of least privilege
        # Per MCP OAuth spec: "minimal set of scopes necessary for basic functionality"
        # Clients can request additional scopes via step-up authorization
        ["resources:read"]
    end
  end

  @doc """
  Get all available OAuth scopes for this MCP server.

  This returns the complete list of scopes that this MCP server supports,
  regardless of what's included in scopes_supported. This is useful for:
  - Documentation and API discovery
  - Administrative interfaces
  - Scope validation during step-up authorization

  This list reflects the actual MCP protocol methods implemented by this server.
  """
  @spec get_all_available_scopes() :: [String.t()]
  def get_all_available_scopes do
    config = Application.get_env(:aegis, __MODULE__, [])

    case Keyword.get(config, :all_scopes) do
      scopes when is_list(scopes) and length(scopes) > 0 ->
        scopes

      _ ->
        # Default: All MCP protocol scopes based on implemented handlers
        [
          "resources:read",
          "resources:subscribe",
          "tools:list",
          "tools:call",
          "prompts:list",
          "prompts:get",
          "roots:list",
          "sampling:create"
        ]
    end
  end

  defp maybe_add_bearer_methods_supported(metadata) do
    # RFC 9728 optional field for supported bearer token methods
    Map.put(metadata, "bearer_methods_supported", ["header"])
  end

  defp maybe_add_resource_documentation(metadata) do
    # RFC 9728 optional field for human-readable documentation
    config = Application.get_env(:aegis, __MODULE__, [])

    case Keyword.get(config, :resource_documentation) do
      nil -> metadata
      doc_url -> Map.put(metadata, "resource_documentation", doc_url)
    end
  end

  defp get_port_string(conn) do
    case {conn.scheme, conn.port} do
      {:https, 443} -> ""
      {:http, 80} -> ""
      {_, nil} -> ""
      {_, port} when is_integer(port) -> ":#{port}"
      _ -> ""
    end
  end

  defp get_mcp_path(conn) do
    # Extract the MCP endpoint path from the request
    # Per RFC 8707 and MCP OAuth spec: Use the most specific URI available
    # to properly identify this MCP server resource

    path = conn.request_path

    cond do
      # Well-known metadata endpoints should return the MCP endpoint path, not themselves
      String.starts_with?(path, "/.well-known/oauth-protected-resource") ->
        extract_mcp_path_from_metadata_request(path)

      # Direct MCP endpoint request - use as-is
      String.starts_with?(path, "/mcp") ->
        path

      # OAuth proxy endpoints - these are for the authorization server, not the resource
      String.starts_with?(path, "/oauth/") ->
        "/mcp"

      # Fallback for any other endpoints
      true ->
        "/mcp"
    end
  end

  # Extract the MCP path from a metadata request path
  # /.well-known/oauth-protected-resource/mcp -> /mcp
  # /.well-known/oauth-protected-resource -> /mcp (default)
  defp extract_mcp_path_from_metadata_request(metadata_path) do
    case String.replace_prefix(metadata_path, "/.well-known/oauth-protected-resource", "") do
      "" -> "/mcp"
      "/" -> "/mcp"
      path -> path
    end
  end

  defp normalize_uri(uri) when is_binary(uri) do
    uri
    |> String.trim()
    |> String.downcase()
    |> remove_trailing_slash()
  end

  defp normalize_uri(_), do: ""

  defp remove_trailing_slash(uri) do
    if String.ends_with?(uri, "/") and String.length(uri) > 1 do
      String.slice(uri, 0..-2//1)
    else
      uri
    end
  end
end
