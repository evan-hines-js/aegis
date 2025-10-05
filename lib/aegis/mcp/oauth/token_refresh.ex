defmodule Aegis.MCP.OAuth.TokenRefresh do
  @moduledoc """
  Handles automatic refresh of expired OAuth tokens.

  When a JWT is expired but a refresh token is available, this module
  exchanges the refresh token for a new access token from Keycloak.

  ## Security: Refreshed Token Validation

  Per MCP OAuth 2.1 specification, refreshed tokens MUST undergo the same
  validation as initial tokens. This module returns the raw access token,
  which is then validated by `JWTService.validate_token/2` with:

  1. **Signature Verification**: Ensures token is signed by authorized server
  2. **Audience Validation**: Verifies `aud` claim matches this Hub's canonical URI
  3. **Issuer Validation**: Confirms token is from authorized issuer
  4. **Scope Validation**: Checks token has required scopes
  5. **Expiration Check**: Validates token hasn't expired again

  The validation flow (see `jwt_service.ex:42-45`):

  ```elixir
  # Original token expired, refresh it
  {:ok, new_access_token} = TokenRefresh.attempt_token_refresh(claims)

  # CRITICAL: Recursively validate the refreshed token with allow_refresh: false
  # This ensures the new token goes through full validation including audience checks
  validate_token(new_access_token, allow_refresh: false, required_scopes: required_scopes)
  ```

  This prevents:
  - Using refreshed tokens with incorrect audience
  - Accepting tokens from unauthorized issuers after refresh
  - Bypassing scope requirements via token refresh
  - Token passthrough vulnerabilities

  ## OAuth 2.1 Refresh Token Rotation

  Per OAuth 2.1 Section 4.3.1, authorization servers MUST rotate refresh tokens
  for public clients. Keycloak handles this automatically by:

  1. Issuing a new refresh token with each refresh request
  2. Invalidating the old refresh token
  3. Requiring PKCE for public clients

  This module updates the stored refresh token (line 34) to maintain the chain.
  """

  require Logger
  alias Aegis.MCP.OAuth.Config

  @doc """
  Attempt to refresh an expired token using the refresh token.

  Takes JWT claims from an expired token and attempts to:
  1. Find the OAuth token record by Keycloak client ID
  2. Use the stored refresh token to get a new access token
  3. Update the OAuth token record with new credentials

  Returns {:ok, new_access_token} or {:error, reason}
  """
  @spec attempt_token_refresh(map()) :: {:ok, String.t()} | {:error, atom()}
  def attempt_token_refresh(claims) do
    alias Aegis.MCP.OAuth.ClientLookup

    with {:ok, keycloak_client_id} <- extract_keycloak_client_id(claims),
         {:ok, oauth_token} <- ClientLookup.find_token_with_refresh(keycloak_client_id),
         {:ok, client} <- get_mcp_client_for_token(oauth_token),
         {:ok, new_token_data} <- refresh_token_with_keycloak(oauth_token, client) do
      alias Aegis.MCP

      # Update the OAuth token record with new access token
      case MCP.OAuthToken.refresh_token(oauth_token, %{
             access_token: new_token_data.access_token,
             refresh_token: new_token_data.refresh_token,
             expires_in: new_token_data.expires_in
           }) do
        {:ok, _updated_token} ->
          Logger.info(
            "TokenRefresh: Successfully refreshed expired token for client #{keycloak_client_id}"
          )

          {:ok, new_token_data.access_token}

        {:error, reason} ->
          Logger.error("TokenRefresh: Failed to update refreshed token: #{inspect(reason)}")
          {:error, :token_update_failed}
      end
    else
      error ->
        Logger.debug("TokenRefresh: Token refresh failed: #{inspect(error)}")
        error
    end
  end

  defp extract_keycloak_client_id(claims) do
    case Map.get(claims, "azp") do
      nil -> {:error, :missing_azp_claim}
      keycloak_client_id -> {:ok, keycloak_client_id}
    end
  end

  defp get_mcp_client_for_token(oauth_token) do
    case oauth_token.client do
      %{active: true} = client -> {:ok, client}
      %{active: false} -> {:error, :client_inactive}
      nil -> {:error, :missing_client_association}
    end
  end

  defp refresh_token_with_keycloak(oauth_token, _mcp_client) do
    keycloak_base_url = Config.keycloak_base_url()
    realm = Config.keycloak_realm()
    token_url = "#{keycloak_base_url}/realms/#{realm}/protocol/openid-connect/token"

    # Prepare refresh token request
    # Note: Public clients (PKCE) don't need client_secret for refresh
    request_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => oauth_token.refresh_token,
      "client_id" => oauth_token.keycloak_client_id
    }

    headers = [
      {"content-type", "application/x-www-form-urlencoded"},
      {"accept", "application/json"}
    ]

    case Req.post(token_url, form: request_body, headers: headers) do
      {:ok, %{status: 200, body: response_body}} ->
        parse_refresh_response(response_body)

      {:ok, %{status: status, body: body}} ->
        Logger.error("TokenRefresh: Request failed with status #{status}: #{inspect(body)}")
        {:error, :refresh_request_failed}

      {:error, reason} ->
        Logger.error("TokenRefresh: HTTP error during token refresh: #{inspect(reason)}")
        {:error, :http_error}
    end
  end

  defp parse_refresh_response(response_body) when is_map(response_body) do
    # Req library already decodes JSON responses
    case response_body do
      %{"access_token" => access_token} = token_data ->
        {:ok,
         %{
           access_token: access_token,
           refresh_token: Map.get(token_data, "refresh_token"),
           expires_in: Map.get(token_data, "expires_in", 300)
         }}

      %{"error" => error} ->
        Logger.error("TokenRefresh: OAuth error in refresh response: #{error}")
        {:error, :oauth_error}

      _ ->
        Logger.error("TokenRefresh: Invalid refresh response format: #{inspect(response_body)}")
        {:error, :invalid_response}
    end
  end
end
