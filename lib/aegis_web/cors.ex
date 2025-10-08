defmodule AegisWeb.CORS do
  @moduledoc """
  CORS (Cross-Origin Resource Sharing) header management for Aegis.

  Provides consistent CORS header handling across controllers with
  support for client-specific origin whitelists and different access patterns.
  """

  import Plug.Conn
  require Logger

  @type cors_config :: :mcp | :oauth_metadata | :oauth_registration

  @doc """
  Add CORS headers for MCP endpoints.

  Allows GET, POST, DELETE, OPTIONS methods and exposes session headers.
  Supports development localhost origins and production whitelist.
  """
  @spec add_mcp_headers(Plug.Conn.t()) :: Plug.Conn.t()
  def add_mcp_headers(conn) do
    origin = get_origin(conn, :mcp)

    conn
    |> put_resp_header("access-control-allow-origin", origin)
    |> put_resp_header("access-control-allow-methods", "GET, POST, DELETE, OPTIONS")
    |> put_resp_header(
      "access-control-allow-headers",
      "accept, content-type, authorization, mcp-protocol-version, mcp-session-id"
    )
    |> put_resp_header("access-control-expose-headers", "mcp-session-id, content-type")
  end

  @doc """
  Add CORS headers for OAuth metadata discovery endpoints.

  Read-only access for OAuth discovery (GET, OPTIONS only).
  """
  @spec add_oauth_metadata_headers(Plug.Conn.t()) :: Plug.Conn.t()
  def add_oauth_metadata_headers(conn) do
    origin = get_origin(conn, :oauth_metadata)

    conn
    |> put_resp_header("access-control-allow-origin", origin)
    |> put_resp_header("access-control-allow-methods", "GET, OPTIONS")
    |> put_resp_header(
      "access-control-allow-headers",
      "accept, content-type, authorization, mcp-protocol-version"
    )
  end

  @doc """
  Add CORS headers for OAuth registration and token endpoints.

  Full CRUD access for OAuth client registration and token operations.
  Supports client-specific origin validation.
  """
  @spec add_oauth_registration_headers(Plug.Conn.t()) :: Plug.Conn.t()
  def add_oauth_registration_headers(conn) do
    origin = get_origin_for_registration(conn)

    conn
    |> put_resp_header("access-control-allow-origin", origin)
    |> put_resp_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
    |> put_resp_header(
      "access-control-allow-headers",
      "accept, content-type, authorization, origin, x-requested-with, mcp-protocol-version"
    )
    |> put_resp_header("access-control-expose-headers", "location, content-type")
  end

  @doc """
  Add standard OPTIONS response headers for preflight requests.

  Sets max-age to 1 hour for preflight caching.
  """
  @spec add_preflight_headers(Plug.Conn.t()) :: Plug.Conn.t()
  def add_preflight_headers(conn) do
    put_resp_header(conn, "access-control-max-age", "3600")
  end

  # Private Functions

  # Get CORS origin for registration endpoints
  # Clients are AI agents (not browsers), so we use global CORS config
  defp get_origin_for_registration(conn) do
    get_origin(conn, :oauth_registration)
  end

  # Get CORS origin based on configuration type
  defp get_origin(conn, config_type) do
    request_origin = extract_request_origin(conn)

    # For development, allow localhost origins
    if localhost_origin?(request_origin) do
      request_origin
    else
      check_against_allowed_origins(request_origin, config_type)
    end
  end

  # Check if origin is localhost/127.0.0.1
  defp localhost_origin?(nil), do: false

  defp localhost_origin?(origin) do
    String.contains?(origin, "localhost") or String.contains?(origin, "127.0.0.1")
  end

  # Check origin against allowed origins list
  defp check_against_allowed_origins(origin, config_type) do
    allowed_origins = get_allowed_origins(config_type)

    cond do
      # No origin header (non-browser request)
      is_nil(origin) ->
        case allowed_origins do
          ["*"] -> "*"
          [first | _] -> first
          [] -> "null"
        end

      # Origin in whitelist
      origin in allowed_origins or "*" in allowed_origins ->
        origin

      # Origin not allowed
      true ->
        "null"
    end
  end

  # Get allowed origins from application config
  defp get_allowed_origins(:mcp) do
    config = Application.get_env(:aegis, AegisWeb.MCPController, [])
    Keyword.get(config, :allowed_origins, ["*"])
  end

  defp get_allowed_origins(:oauth_metadata) do
    config = Application.get_env(:aegis, AegisWeb.OAuthMetadataController, [])
    Keyword.get(config, :allowed_origins, ["*"])
  end

  defp get_allowed_origins(:oauth_registration) do
    config = Application.get_env(:aegis, AegisWeb.OAuthMetadataController, [])
    Keyword.get(config, :allowed_origins, ["*"])
  end

  # Extract origin from request headers
  defp extract_request_origin(conn) do
    case get_req_header(conn, "origin") do
      [origin] -> origin
      [] -> nil
      _multiple -> nil
    end
  end
end
