defmodule AegisWeb.OAuth.DiscoveryController do
  @moduledoc """
  OAuth metadata and discovery endpoints.

  Implements RFC 8414 (Authorization Server Metadata) and RFC 9728
  (Protected Resource Metadata) for client discovery.
  """

  use AegisWeb, :controller
  require Logger

  alias Aegis.MCP.Client
  alias Aegis.MCP.OAuth.ProtectedResourceMetadata

  @doc """
  Serve Protected Resource Metadata at the well-known URI.

  Supports optional client_id query parameter to return client-specific
  authorization servers.
  """
  def metadata(conn, params) do
    canonical_uri = ProtectedResourceMetadata.get_canonical_resource_uri(conn)
    client_id = Map.get(params, "client_id")

    metadata = generate_metadata_for_client(canonical_uri, client_id)

    Logger.debug(
      "Serving OAuth Protected Resource Metadata for: #{canonical_uri}, client_id: #{inspect(client_id)}"
    )

    conn
    |> AegisWeb.CORS.add_oauth_metadata_headers()
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "public, max-age=3600")
    |> json(metadata)
  end

  @doc """
  Handle requests to the root well-known endpoint.
  """
  def root_metadata(conn, params) do
    canonical_uri = build_default_mcp_uri(conn)
    client_id = Map.get(params, "client_id")

    metadata = generate_metadata_for_client(canonical_uri, client_id)

    Logger.debug(
      "Serving root OAuth Protected Resource Metadata for: #{canonical_uri}, client_id: #{inspect(client_id)}"
    )

    conn
    |> AegisWeb.CORS.add_oauth_metadata_headers()
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "public, max-age=3600")
    |> json(metadata)
  end

  @doc """
  Handle requests to path-specific well-known endpoints.
  """
  def path_metadata(conn, %{"path" => path_segments} = params) do
    mcp_path = "/" <> Enum.join(path_segments, "/")
    canonical_uri = build_mcp_uri_for_path(conn, mcp_path)
    client_id = Map.get(params, "client_id")

    metadata = generate_metadata_for_client(canonical_uri, client_id)

    Logger.debug(
      "Serving path-specific OAuth Protected Resource Metadata for: #{canonical_uri}, client_id: #{inspect(client_id)}"
    )

    conn
    |> AegisWeb.CORS.add_oauth_metadata_headers()
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "public, max-age=3600")
    |> json(metadata)
  end

  @doc """
  Handle OAuth 2.0 Authorization Server Metadata requests.

  This MCP server is a resource server, not an authorization server.
  """
  def authorization_server_metadata(conn, _params) do
    Logger.debug("Authorization server metadata requested on resource server")

    conn
    |> AegisWeb.CORS.add_oauth_metadata_headers()
    |> put_status(404)
    |> put_resp_content_type("application/json")
    |> json(%{
      "error" => "not_found",
      "error_description" =>
        "This is an MCP resource server, not an authorization server. Please discover authorization servers via /.well-known/oauth-protected-resource"
    })
  end

  @doc """
  Handle OpenID Connect Discovery requests.
  """
  def openid_configuration(conn, _params) do
    Logger.debug("OpenID Connect configuration requested for OAuth proxy")

    base_url = build_base_url(conn)

    discovery_doc = %{
      "issuer" => base_url,
      "authorization_endpoint" =>
        "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/auth",
      "token_endpoint" => "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/token",
      "userinfo_endpoint" =>
        "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/userinfo",
      "jwks_uri" => "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/certs",
      "registration_endpoint" =>
        "#{base_url}/oauth/realms/aegis-mcp/clients-registrations/openid-connect",
      "scopes_supported" => Application.get_env(:aegis, :oauth_scopes_supported, ["openid"]),
      "response_types_supported" => [
        "code",
        "id_token",
        "token",
        "code id_token",
        "code token",
        "id_token token",
        "code id_token token"
      ],
      "grant_types_supported" => ["authorization_code", "refresh_token", "client_credentials"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256"],
      "code_challenge_methods_supported" => ["S256", "plain"],
      "token_endpoint_auth_methods_supported" => [
        "client_secret_basic",
        "client_secret_post",
        "none"
      ]
    }

    conn
    |> AegisWeb.CORS.add_oauth_metadata_headers()
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "public, max-age=3600")
    |> json(discovery_doc)
  end

  @doc """
  Handle OAuth Authorization Server Metadata requests when acting as proxy.
  """
  def oauth_authorization_server_metadata(conn, _params) do
    Logger.debug("OAuth Authorization Server Metadata requested for proxy")

    base_url = build_base_url(conn)

    metadata = %{
      "issuer" => "#{base_url}/oauth",
      "registration_endpoint" =>
        "#{base_url}/oauth/realms/aegis-mcp/clients-registrations/openid-connect",
      "token_endpoint" => "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/token",
      "authorization_endpoint" =>
        "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/auth",
      "userinfo_endpoint" =>
        "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/userinfo",
      "jwks_uri" => "#{base_url}/oauth/realms/aegis-mcp/protocol/openid-connect/certs",
      "scopes_supported" => Application.get_env(:aegis, :oauth_scopes_supported, ["openid"]),
      "response_types_supported" => ["code", "code id_token", "id_token", "token id_token"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256"],
      "code_challenge_methods_supported" => ["S256", "plain"],
      "registration_endpoint_auth_methods_supported" => [
        "client_secret_basic",
        "client_secret_post"
      ]
    }

    conn
    |> AegisWeb.CORS.add_oauth_registration_headers()
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "public, max-age=3600")
    |> json(metadata)
  end

  @doc """
  Handle CORS preflight OPTIONS requests.
  """
  def options(conn, _params) do
    conn
    |> AegisWeb.CORS.add_oauth_registration_headers()
    |> AegisWeb.CORS.add_preflight_headers()
    |> send_resp(200, "")
  end

  # Private functions

  defp generate_metadata_for_client(canonical_uri, nil) do
    ProtectedResourceMetadata.generate_metadata(canonical_uri)
  end

  defp generate_metadata_for_client(canonical_uri, oauth_client_id)
       when is_binary(oauth_client_id) do
    case Client.get_by_oauth_client_id(oauth_client_id) do
      {:ok, client} when client.oauth_issuer_url != nil ->
        Logger.info("Returning client-specific OAuth metadata for client_id: #{oauth_client_id}")

        %{
          "resource" => canonical_uri,
          "authorization_servers" => [client.oauth_issuer_url],
          "scopes_supported" => ProtectedResourceMetadata.get_supported_scopes(),
          "bearer_methods_supported" => ["header"]
        }

      {:ok, _client} ->
        Logger.debug("Client '#{oauth_client_id}' using default OAuth provider")
        ProtectedResourceMetadata.generate_metadata(canonical_uri)

      {:error, _} ->
        Logger.debug("Client '#{oauth_client_id}' not found, returning default metadata")
        ProtectedResourceMetadata.generate_metadata(canonical_uri)
    end
  end

  defp build_default_mcp_uri(conn) do
    scheme = conn.scheme |> to_string() |> String.downcase()
    host = conn.host |> String.downcase()
    port = get_port_string(conn)

    "#{scheme}://#{host}#{port}/mcp"
  end

  defp build_mcp_uri_for_path(conn, path) do
    scheme = conn.scheme |> to_string() |> String.downcase()
    host = conn.host |> String.downcase()
    port = get_port_string(conn)

    "#{scheme}://#{host}#{port}#{path}"
  end

  defp get_port_string(conn) do
    case {conn.scheme, conn.port} do
      {:https, 443} -> ""
      {:http, 80} -> ""
      {_, port} -> ":#{port}"
    end
  end

  defp build_base_url(conn) do
    scheme = conn.scheme |> to_string() |> String.downcase()
    host = conn.host |> String.downcase()
    port = get_port_string(conn)

    "#{scheme}://#{host}#{port}"
  end
end
