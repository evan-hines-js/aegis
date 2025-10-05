defmodule Aegis.MCP.OAuth.ResourceValidation do
  @moduledoc """
  Implementation of RFC 8707 Resource Indicators validation for MCP OAuth 2.1.

  This module handles validation of the `resource` parameter in OAuth requests
  to ensure tokens are bound to their intended MCP server resources.

  ## Security: Token Passthrough Prevention

  This module is critical for preventing "confused deputy" attacks and token
  passthrough vulnerabilities. Key security requirements:

  1. **Token Audience Validation**: MUST validate that access tokens contain
     this MCP server in the `aud` claim. Tokens issued for other services
     MUST be rejected.

  2. **NO Token Passthrough**: When making requests to upstream MCP servers,
     the Hub MUST NOT forward tokens received from MCP clients. Instead:
     - Use separate OAuth client credentials flow
     - Obtain tokens specifically for the upstream server
     - Include upstream server's URI in the `resource` parameter

  3. **Resource Parameter Enforcement**: Per RFC 8707, MCP clients MUST include
     the `resource` parameter in token requests, explicitly binding tokens to
     this MCP server's canonical URI.

  ## Why Token Passthrough is Forbidden

  Token passthrough creates severe security vulnerabilities:

  - **Privilege Escalation**: A token issued for Server A should never be
    accepted by Server B, even if both trust the same authorization server.

  - **Confused Deputy**: If the Hub forwards client tokens to upstream servers,
    the upstream server cannot distinguish between the Hub acting on its own
    behalf vs. on behalf of a client.

  - **Scope Bleeding**: Client tokens may have broader scopes than intended
    for upstream operations.

  See RFC 8707 Section 2 and MCP Security Best Practices for details.
  """

  require Logger
  alias Aegis.MCP.OAuth.{Config, ProtectedResourceMetadata}

  @doc """
  Validate that an access token's audience matches this MCP server.

  Per RFC 8707 and the MCP specification, MCP servers MUST validate that
  access tokens were issued specifically for them as the intended audience.
  """
  @spec validate_token_audience(map(), Plug.Conn.t()) :: :ok | {:error, atom()}
  def validate_token_audience(token_claims, conn) do
    canonical_uri = ProtectedResourceMetadata.get_canonical_resource_uri(conn)
    audience_claim = extract_audience_claim(token_claims)

    case validate_audience_matches_resource(audience_claim, canonical_uri) do
      true ->
        Logger.debug("Token audience validation successful for resource: #{canonical_uri}")
        :ok

      false ->
        Logger.warning(
          "Token audience validation failed. " <>
            "Expected: #{canonical_uri}, Got: #{inspect(audience_claim)}"
        )

        {:error, :invalid_audience}
    end
  end

  @doc """
  Validate a resource parameter from an OAuth authorization request.

  This ensures that clients are requesting tokens for the correct MCP server.
  """
  @spec validate_resource_parameter(String.t(), Plug.Conn.t()) :: :ok | {:error, atom()}
  def validate_resource_parameter(resource_param, conn) when is_binary(resource_param) do
    canonical_uri = ProtectedResourceMetadata.get_canonical_resource_uri(conn)

    if ProtectedResourceMetadata.validate_resource_parameter(resource_param, canonical_uri) do
      Logger.debug("Resource parameter validation successful: #{resource_param}")
      :ok
    else
      Logger.warning(
        "Resource parameter validation failed. " <>
          "Expected: #{canonical_uri}, Got: #{resource_param}"
      )

      {:error, :invalid_resource}
    end
  end

  def validate_resource_parameter(nil, _conn) do
    # Resource parameter is required for MCP OAuth 2.1
    Logger.warning("Missing required resource parameter")
    {:error, :missing_resource}
  end

  def validate_resource_parameter(_, _conn) do
    {:error, :invalid_resource_format}
  end

  @doc """
  Extract and validate the resource parameter from request parameters.

  Handles both query parameters and form-encoded body parameters.
  """
  @spec extract_and_validate_resource(map(), Plug.Conn.t()) :: :ok | {:error, atom()}
  def extract_and_validate_resource(params, conn) do
    case Map.get(params, "resource") do
      resource when is_binary(resource) ->
        validate_resource_parameter(resource, conn)

      nil ->
        # Check if it's in a different format (e.g., from form data)
        case Map.get(params, :resource) do
          resource when is_binary(resource) ->
            validate_resource_parameter(resource, conn)

          _ ->
            {:error, :missing_resource}
        end

      _ ->
        {:error, :invalid_resource_format}
    end
  end

  @doc """
  Get the expected resource identifier for this MCP server.

  This can be used by clients to construct proper resource parameters.
  """
  @spec get_expected_resource(Plug.Conn.t()) :: String.t()
  def get_expected_resource(conn) do
    ProtectedResourceMetadata.get_canonical_resource_uri(conn)
  end

  @doc """
  Validate that a token was issued by an authorized authorization server.

  Checks that the token's issuer is in the list of configured authorization servers.
  """
  @spec validate_token_issuer(map()) :: :ok | {:error, atom()}
  def validate_token_issuer(token_claims) do
    issuer = Map.get(token_claims, "iss")
    authorized_issuers = get_authorized_issuers()

    if issuer && issuer in authorized_issuers do
      Logger.debug("Token issuer validation successful: #{issuer}")
      :ok
    else
      Logger.warning(
        "Token issuer validation failed. " <>
          "Got: #{inspect(issuer)}, Authorized: #{inspect(authorized_issuers)}"
      )

      {:error, :unauthorized_issuer}
    end
  end

  # Private helper functions

  defp extract_audience_claim(token_claims) do
    # RFC 8707 Section 2 - audience can be string or array
    case Map.get(token_claims, "aud") do
      aud when is_binary(aud) -> [aud]
      aud when is_list(aud) -> aud
      _ -> []
    end
  end

  defp validate_audience_matches_resource(audience_list, canonical_uri)
       when is_list(audience_list) do
    # Check if any audience value matches our canonical URI
    # Allow exact match or parent URI match
    Enum.any?(audience_list, fn aud ->
      ProtectedResourceMetadata.validate_resource_parameter(canonical_uri, aud)
    end)
  end

  defp validate_audience_matches_resource(_, _), do: false

  defp get_authorized_issuers do
    # Get list of authorization servers from configuration
    config = Application.get_env(:aegis, Aegis.MCP.OAuth.ProtectedResourceMetadata, [])

    case Keyword.get(config, :authorization_servers) do
      servers when is_list(servers) and length(servers) > 0 ->
        servers

      _ ->
        # Fallback to OAuth config
        keycloak_base_url = Config.keycloak_base_url()
        realm = Config.keycloak_realm()
        ["#{keycloak_base_url}/realms/#{realm}"]
    end
  end
end
