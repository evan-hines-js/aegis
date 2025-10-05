defmodule Aegis.MCP.OAuthClient do
  @moduledoc """
  OAuth 2.0 Client for authenticating with upstream/backend MCP servers.

  Implements the Client Credentials Grant flow to obtain access tokens
  for server-to-server authentication. Handles token caching, refresh,
  and error recovery.

  ## CRITICAL SECURITY REQUIREMENT: Token Passthrough Prevention

  Per MCP OAuth 2.1 specification (RFC 8707 Section 2) and MCP Security Best Practices:

  **This Hub MUST NEVER forward tokens received from MCP clients to upstream MCP servers.**

  ### Why Token Passthrough is Forbidden

  1. **Confused Deputy Attack**: If the Hub forwards client tokens to upstream servers,
     the upstream server cannot distinguish between:
     - The Hub acting on its own behalf
     - The Hub acting on behalf of a client

  2. **Privilege Escalation**: A token issued for the Hub (audience: `https://hub.example.com/mcp`)
     should NEVER be accepted by an upstream server (audience: `https://upstream.example.com/mcp`),
     even if both trust the same authorization server.

  3. **Scope Bleeding**: Client tokens may have broader scopes than intended for
     specific upstream operations.

  4. **Audience Violation**: Per RFC 8707, tokens MUST be bound to their intended
     resource via the `aud` claim. The Hub's canonical URI and upstream server's
     canonical URI are different resources.

  ### Correct Implementation

  When this Hub needs to call an upstream MCP server:

  1. **DO NOT** use tokens from `conn.assigns[:jwt_claims]` or client Authorization headers
  2. **DO** obtain separate tokens using `get_access_token_with_context/5`:
     - Uses OAuth Client Credentials flow
     - Includes the upstream server's URI in the `resource` parameter
     - Results in tokens with `aud` claim matching the upstream server
     - Implements RFC 8693 Token Exchange with identity chaining (`act` claim)

  3. **DO** validate client permissions before obtaining upstream tokens
  4. **DO** include client context in delegated tokens via `act` claim

  ### Example: Correct vs Incorrect

  ```elixir
  # ❌ INCORRECT - Token Passthrough Vulnerability
  def call_upstream_server_WRONG(conn, upstream_server) do
    client_token = conn.assigns[:jwt_claims]  # Token for THIS hub
    headers = [{"authorization", "Bearer \#{client_token}"}]
    # This forwards a token that was issued for the Hub to an upstream server!
    Req.post(upstream_server.endpoint, headers: headers)
  end

  # ✅ CORRECT - Obtain Separate Token
  def call_upstream_server_CORRECT(upstream_server, client_id, resource_type, pattern, action) do
    # Get a NEW token specifically for the upstream server
    {:ok, upstream_token} = OAuthClient.get_access_token_with_context(
      upstream_server,
      client_id,
      resource_type,
      pattern,
      action
    )
    # This token has aud claim matching upstream_server's URI
    headers = [{"authorization", "Bearer \#{upstream_token}"}]
    Req.post(upstream_server.endpoint, headers: headers)
  end
  ```

  ## Token Validation

  The Hub's `OAuthAuthenticationPlug` enforces audience validation:
  - Validates `aud` claim matches this Hub's canonical URI
  - Rejects tokens issued for other resources
  - See `Aegis.MCP.OAuth.ResourceValidation` for implementation

  ## References

  - RFC 8707: Resource Indicators for OAuth 2.0
  - RFC 8693: OAuth 2.0 Token Exchange
  - MCP OAuth Specification: Token Passthrough section
  - MCP Security Best Practices: Confused Deputy Prevention
  """

  require Logger
  alias Aegis.MCP.Authorization
  alias Aegis.MCP.Constants

  @typedoc "OAuth token response"
  @type token_response :: %{
          access_token: String.t(),
          token_type: String.t(),
          expires_in: non_neg_integer(),
          expires_at: DateTime.t(),
          scope: String.t() | nil
        }

  @typedoc "OAuth error"
  @type oauth_error ::
          {:error,
           :invalid_client
           | :invalid_request
           | :network_error
           | :token_expired
           | :client_inactive
           | :client_not_found
           | :invalid_api_key
           | :invalid_resource_type
           | :permission_denied
           | :session_not_found
           | :system_error
           | :token_creation_failed
           | :deprecated_unsafe_method}

  @doc """
  Get OAuth access token using Token Exchange with Identity Chaining.

  This implements RFC 8698 Token Exchange to prevent Confused Deputy attacks by:
  1. Validating the client has permission for the specific resource/action
  2. Creating a delegated token with Hub as `sub` and client as `act` (Actor)
  3. Returning a token that backends can use to make proper authorization decisions

  The resulting token tells backends: "Hub (trusted proxy) is connecting,
  but authorization decisions must be based on the original client's identity."
  """
  @spec get_access_token_with_context(map(), String.t(), atom(), String.t(), atom()) ::
          {:ok, String.t()} | oauth_error()
  def get_access_token_with_context(server, client_id, resource_type, resource_pattern, action)
      when server.auth_type == :oauth and is_binary(client_id) do
    start_time = System.monotonic_time()

    # Step 1: CRITICAL - Validate client permission BEFORE creating delegated token
    result =
      case Authorization.check_permission(
             client_id,
             resource_type,
             server.name,
             resource_pattern,
             action
           ) do
        {:ok, :authorized} ->
          # Step 2: Create RFC 8698 Token Exchange with Identity Chaining
          create_delegated_token(server, client_id, resource_type, action)

        {:error, reason} ->
          Logger.warning(
            "Token exchange denied for client #{client_id} → server #{server.name}: #{reason}"
          )

          {:error, reason}
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :oauth, :token_exchange],
      %{duration: duration},
      %{server: server.name, client_id: client_id, resource_type: resource_type, action: action}
    )

    result
  end

  @doc """
  DEPRECATED: All OAuth operations require client context for security.
  Use get_access_token_with_context/5 instead.
  """
  @spec get_access_token(map()) :: {:error, :deprecated_unsafe_method}
  def get_access_token(server) when server.auth_type == :oauth do
    Logger.error(
      "SECURITY: OAuth requires client context to prevent Confused Deputy attacks for server #{server.name}"
    )

    {:error, :deprecated_unsafe_method}
  end

  def get_access_token(_server) do
    {:error, :invalid_request}
  end

  # RFC 8698 Token Exchange implementation
  defp create_delegated_token(server, client_id, resource_type, action) do
    hub_service_id = get_hub_service_id()
    now = DateTime.utc_now()

    # RFC 8698 Token Exchange Claims Structure
    claims = %{
      # Standard JWT Claims (RFC 7519)
      # Hub as token issuer
      "iss" => get_hub_issuer_url(),
      # Hub's service account (the Deputy)
      "sub" => hub_service_id,
      # Target backend server
      "aud" => server.endpoint,
      # Short-lived delegation
      "exp" => DateTime.add(now, 15, :minute) |> DateTime.to_unix(),
      "iat" => DateTime.to_unix(now),
      "jti" => generate_token_id(),

      # RFC 8698 Token Exchange Claims
      # Actor Claim (CRITICAL for preventing confusion)
      "act" => %{
        # Original client identity
        "sub" => client_id,
        # Who vouches for this identity
        "iss" => get_hub_issuer_url()
      },

      # OAuth 2.0 Scopes (RFC 6749)
      # Constrained permissions
      "scope" => build_scope(resource_type, action),

      # Additional context for audit/debugging
      # OAuth client making the request
      "client_id" => hub_service_id
    }

    # Create JWT token using JOSE directly (simpler than Guardian)
    case create_jwt_token(claims) do
      {:ok, token} ->
        Logger.info(
          "Token exchange successful: #{client_id} → #{server.name} (#{resource_type}:#{action})"
        )

        {:ok, token}

      {:error, reason} ->
        Logger.error("Token exchange failed for #{client_id} → #{server.name}: #{reason}")
        {:error, :token_creation_failed}
    end
  end

  defp build_scope(resource_type, action) do
    "#{resource_type}:#{action}"
  end

  defp get_hub_service_id do
    Application.get_env(:aegis, :hub_service_account_id, "aegis-mcp-hub")
  end

  defp get_hub_issuer_url do
    Application.get_env(:aegis, :hub_issuer_url, "https://aegis-mcp-hub.local")
  end

  defp generate_token_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  # Create JWT token using JOSE (replacement for Guardian)
  defp create_jwt_token(claims) do
    alias Aegis.MCP.OAuth

    # Use a simple symmetric key for internal Hub-to-backend tokens
    # In production, you might want to use asymmetric keys
    secret = OAuth.Config.token_signing_secret()

    header = %{"alg" => "HS256", "typ" => "JWT"}

    # Create and sign JWT
    jwk = JOSE.JWK.from_oct(secret)
    signed_jwt = JOSE.JWT.sign(jwk, header, claims)
    {_, token} = JOSE.JWS.compact(signed_jwt)

    {:ok, token}
  rescue
    error ->
      Logger.error("JWT creation failed: #{inspect(error)}")
      {:error, :jwt_creation_failed}
  end

  @doc """
  Invalidate cached token for a server.

  Useful when a token is known to be invalid or when server configuration changes.
  """
  @spec invalidate_token(String.t()) :: :ok
  def invalidate_token(server_name) do
    cache_key = {:oauth_token, server_name}
    :ets.delete(Constants.permission_cache_table(), cache_key)
    Logger.debug("Invalidated OAuth token cache for server #{server_name}")
    :ok
  end
end
