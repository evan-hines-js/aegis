defmodule Aegis.MCP.Plugs.OAuthAuthenticationPlug do
  @moduledoc """
  OAuth 2.0 authentication plug for MCP resource server compliance.

  Implements OAuth 2.1 resource server requirements:
  - Extracts Bearer token from Authorization header (RFC 6750 Section 2.1)
  - Validates JWT token signature and claims
  - Validates token audience matches this MCP server (RFC 8707)
  - Validates token issuer is authorized
  - Returns proper 401/403 responses with WWW-Authenticate headers (RFC 6750 Section 3)

  ## Security Requirements

  Per MCP OAuth specification and RFC 8707:
  - MUST validate token audience claim matches this hub's canonical URI
  - MUST reject tokens issued for other resources
  - MUST NOT forward client tokens to upstream servers (use separate tokens)

  ## Usage

  Add to router pipeline for OAuth-protected routes:

      pipeline :mcp_oauth do
        plug Aegis.MCP.Plugs.OAuthAuthenticationPlug
      end

  ## Options

  - `:required_scopes` - List of scopes required for this route (optional)
  - `:allow_api_key` - Allow API key authentication as fallback (default: true)
    For strict MCP OAuth compliance, set to false to enforce Bearer token only
  - `:optional` - Make authentication optional, only validate if present (default: false)

  ## Examples

      # Require OAuth with specific scopes
      plug OAuthAuthenticationPlug, required_scopes: ["tools:call", "resources:read"]

      # OAuth only, no API key fallback
      plug OAuthAuthenticationPlug, allow_api_key: false

      # Optional authentication (validate if present, allow if absent)
      plug OAuthAuthenticationPlug, optional: true
  """

  import Plug.Conn
  require Logger

  alias Aegis.MCP.Authorization
  alias Aegis.MCP.OAuth.{JWTService, ResourceValidation, WWWAuthenticate}

  @behaviour Plug

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, opts) do
    start_time = System.monotonic_time()
    required_scopes = Keyword.get(opts, :required_scopes, [])
    allow_api_key = Keyword.get(opts, :allow_api_key, true)
    optional = Keyword.get(opts, :optional, false)

    result =
      case extract_credentials(conn) do
        {:bearer, token} ->
          authenticate_bearer_token(conn, token, required_scopes)

        {:api_key, api_key} when allow_api_key ->
          authenticate_api_key(conn, api_key)

        {:none, _} when optional ->
          # Optional authentication - allow request to proceed without credentials
          conn

        {:none, _} ->
          # No credentials provided and authentication is required
          send_unauthorized_response(conn, required_scopes, :missing_credentials)

        {:api_key, _} when not allow_api_key ->
          # API key not allowed on this route
          send_unauthorized_response(conn, required_scopes, :invalid_token,
          error_description: "API key authentication not allowed for this endpoint"
        )
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :plug, :oauth_auth],
      %{duration: duration},
      %{}
    )

    result
  end

  # Extract credentials from Authorization header
  defp extract_credentials(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        {:bearer, String.trim(token)}

      ["bearer " <> token] ->
        {:bearer, String.trim(token)}

      [token] ->
        # Check if it's an API key format (starts with "ak_")
        trimmed_token = String.trim(token)

        if String.starts_with?(trimmed_token, "ak_") do
          {:api_key, trimmed_token}
        else
          {:none, nil}
        end

      [] ->
        {:none, nil}

      _multiple ->
        # Multiple Authorization headers not allowed
        {:none, nil}
    end
  end

  # Authenticate using Bearer token (JWT)
  defp authenticate_bearer_token(conn, token, required_scopes) do
    with {:ok, claims} <- validate_jwt_token(token, required_scopes),
         :ok <- validate_token_audience(claims, conn),
         {:ok, client} <- extract_client_from_token(claims),
         :ok <- validate_token_issuer_for_client(claims, client) do
      # Authentication successful - store client and claims in assigns
      conn
      |> assign(:current_client, client)
      |> assign(:jwt_claims, claims)
      |> assign(:auth_method, :oauth)
      |> assign(:authenticated, true)
    else
      {:error, :token_expired} ->
        send_unauthorized_response(conn, required_scopes, :invalid_token,
          error_description: "Token has expired"
        )

      {:error, :invalid_signature} ->
        send_unauthorized_response(conn, required_scopes, :invalid_token,
          error_description: "Token signature verification failed"
        )

      {:error, :invalid_audience} ->
        # Per RFC 6750 Section 3.1: Use 403 for audience mismatch
        # Client should NOT retry with refresh token - this won't fix audience issues
        send_forbidden_response_for_audience(conn, claims: extract_audience_from_token(token))

      {:error, :unauthorized_issuer} ->
        # Per RFC 6750 Section 3.1: Use 403 for unauthorized issuer
        # Client should NOT retry - issuer validation won't change
        send_forbidden_response_for_issuer(conn, issuer: extract_issuer_from_token(token))

      {:error, :insufficient_scope} ->
        # Extract current scopes from token for accumulation
        current_scopes = extract_token_scopes(token)

        send_forbidden_response(
          conn,
          required_scopes,
          current_scopes,
          error_description: "Token does not have required scopes"
        )

      {:error, :client_not_found} ->
        send_unauthorized_response(conn, required_scopes, :invalid_token,
          error_description: "Client associated with token not found"
        )

      {:error, :client_inactive} ->
        send_unauthorized_response(conn, required_scopes, :invalid_token,
          error_description: "Client account is inactive"
        )

      {:error, reason} ->
        Logger.error("OAuth authentication failed: #{inspect(reason)}")

        send_unauthorized_response(conn, required_scopes, :invalid_token,
          error_description: "Token validation failed"
        )
    end
  end

  # Authenticate using API key
  defp authenticate_api_key(conn, api_key) do
    case Authorization.authenticate_client(api_key) do
      {:ok, client} ->
        conn
        |> assign(:current_client, client)
        |> assign(:auth_method, :api_key)
        |> assign(:authenticated, true)

      {:error, :invalid_api_key} ->
        send_unauthorized_response(conn, [], :invalid_token, error_description: "Invalid API key")

      {:error, :client_inactive} ->
        send_unauthorized_response(conn, [], :invalid_token,
          error_description: "Client account is inactive"
        )

      {:error, reason} ->
        Logger.error("API key authentication failed: #{inspect(reason)}")

        send_unauthorized_response(conn, [], :invalid_token,
          error_description: "Authentication failed"
        )
    end
  end

  # Validate JWT token with optional scope validation
  defp validate_jwt_token(token, required_scopes) do
    JWTService.validate_token(token, required_scopes: required_scopes)
  end

  # Validate token audience matches this MCP server
  defp validate_token_audience(claims, conn) do
    ResourceValidation.validate_token_audience(claims, conn)
  end

  # Validate token issuer matches client's configured OAuth provider
  # In multi-tenant OAuth, each client has their own oauth_issuer_url
  defp validate_token_issuer_for_client(claims, client) do
    token_issuer = Map.get(claims, "iss")

    cond do
      # Client configured with OAuth and has issuer URL
      client.auth_type == :oauth && client.oauth_issuer_url ->
        if token_issuer == client.oauth_issuer_url do
          Logger.debug("Token issuer matches client's OAuth provider: #{token_issuer}")
          :ok
        else
          Logger.warning(
            "Token issuer mismatch. Token issuer: #{inspect(token_issuer)}, " <>
              "Client #{client.name} expects: #{inspect(client.oauth_issuer_url)}"
          )

          {:error, :unauthorized_issuer}
        end

      # OAuth client must have oauth_issuer_url configured
      client.auth_type == :oauth ->
        Logger.error("OAuth client #{client.name} missing oauth_issuer_url configuration")
        {:error, :unauthorized_issuer}

      # Client uses API key auth - shouldn't have OAuth token
      true ->
        Logger.error("Client #{client.name} uses API key auth but received OAuth token")
        {:error, :unauthorized_issuer}
    end
  end

  # Extract client information from validated token
  defp extract_client_from_token(claims) do
    JWTService.extract_client_info(claims)
  end

  # Send 401 Unauthorized response with WWW-Authenticate header
  defp send_unauthorized_response(conn, required_scopes, error_code, opts \\ []) do
    error_description = Keyword.get(opts, :error_description)

    # Per MCP OAuth spec: Include scope parameter in WWW-Authenticate to guide clients
    # on which scopes to request. Use required_scopes if provided, otherwise fall back
    # to scopes_supported from Protected Resource Metadata (minimal scopes for basic functionality)
    scopes_to_include = get_scopes_for_challenge(required_scopes)

    www_authenticate =
      if error_code == :missing_credentials do
        # No error parameter when credentials are missing (per RFC 6750)
        WWWAuthenticate.generate_header(conn, scope: scopes_to_include)
      else
        WWWAuthenticate.generate_error_header(conn, to_string(error_code), error_description,
          scope: scopes_to_include
        )
      end

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      401,
      Jason.encode!(%{
        "error" => to_string(error_code),
        "error_description" => error_description || "Authentication required"
      })
    )
    |> halt()
  end

  # Send 403 Forbidden response for insufficient scope
  # Per MCP OAuth spec, scope parameter should include existing granted scopes
  # plus newly required scopes to prevent clients from losing previously granted permissions
  defp send_forbidden_response(conn, required_scopes, current_scopes, opts) do
    error_description = Keyword.get(opts, :error_description, "Insufficient scope")

    # Combine current scopes with required scopes (MCP spec recommendation)
    # This prevents clients from losing previously granted permissions during step-up auth
    combined_scopes = combine_scopes_for_step_up(current_scopes, required_scopes)

    www_authenticate =
      WWWAuthenticate.generate_insufficient_scope_header(
        conn,
        Enum.join(combined_scopes, " "),
        error_description
      )

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      403,
      Jason.encode!(%{
        "error" => "insufficient_scope",
        "error_description" => error_description
      })
    )
    |> halt()
  end

  # Extract scopes from JWT token for scope accumulation during step-up auth
  defp extract_token_scopes(token) do
    case JWTService.extract_claims(token) do
      {:ok, claims} -> JWTService.extract_scopes(claims)
      {:error, _} -> []
    end
  end

  # Combine current scopes with newly required scopes for step-up authorization
  # Per MCP OAuth spec Section "Scope Challenge Handling":
  # "Include both existing relevant scopes and newly required scopes to prevent
  #  clients from losing previously granted permissions"
  defp combine_scopes_for_step_up(current_scopes, required_scopes) do
    (current_scopes ++ required_scopes)
    |> Enum.uniq()
    |> Enum.sort()
  end

  # Get scopes to include in WWW-Authenticate challenge
  # Per MCP OAuth spec: "MCP servers SHOULD include a scope parameter in the WWW-Authenticate
  # header as defined in RFC 6750 Section 3 to indicate the scopes required for accessing
  # the resource."
  defp get_scopes_for_challenge(required_scopes)
       when is_list(required_scopes) and required_scopes != [] do
    required_scopes
  end

  defp get_scopes_for_challenge(_) do
    # Fall back to scopes_supported from Protected Resource Metadata
    # This represents the minimal scopes for basic MCP functionality
    alias Aegis.MCP.OAuth.ProtectedResourceMetadata
    ProtectedResourceMetadata.get_supported_scopes()
  end

  # Send 403 Forbidden response for audience mismatch
  # Per RFC 6750 Section 3.1: Audience validation failures should return 403
  # because refreshing the token won't fix the audience mismatch
  defp send_forbidden_response_for_audience(conn, opts) do
    audience = Keyword.get(opts, :claims)
    expected = ResourceValidation.get_expected_resource(conn)

    error_description =
      "Token audience validation failed. Token is intended for '#{inspect(audience)}' but this server expects '#{expected}'."

    www_authenticate =
      WWWAuthenticate.generate_error_header(
        conn,
        "invalid_token",
        error_description
      )

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("x-auth-error", "invalid_audience")
    |> send_resp(
      403,
      Jason.encode!(%{
        "error" => "invalid_audience",
        "error_description" => error_description,
        "expected_audience" => expected,
        "received_audience" => audience
      })
    )
    |> halt()
  end

  # Send 403 Forbidden response for unauthorized issuer
  # Per RFC 6750 Section 3.1: Issuer validation failures should return 403
  defp send_forbidden_response_for_issuer(conn, opts) do
    issuer = Keyword.get(opts, :issuer)

    error_description =
      "Token issuer '#{inspect(issuer)}' is not authorized for this MCP server."

    www_authenticate =
      WWWAuthenticate.generate_error_header(
        conn,
        "invalid_token",
        error_description
      )

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("x-auth-error", "unauthorized_issuer")
    |> send_resp(
      403,
      Jason.encode!(%{
        "error" => "unauthorized_issuer",
        "error_description" => error_description,
        "received_issuer" => issuer
      })
    )
    |> halt()
  end

  # Extract audience from token for error messages (best effort)
  defp extract_audience_from_token(token) do
    case JWTService.extract_claims(token) do
      {:ok, claims} -> Map.get(claims, "aud")
      {:error, _} -> nil
    end
  end

  # Extract issuer from token for error messages (best effort)
  defp extract_issuer_from_token(token) do
    case JWTService.extract_claims(token) do
      {:ok, claims} -> Map.get(claims, "iss")
      {:error, _} -> nil
    end
  end
end
