defmodule Aegis.MCP.OAuth.JWTService do
  @moduledoc """
  Pure JWT validation service for Keycloak tokens.

  Focused solely on JWT validation logic without token management
  or refresh concerns. Uses the JWKSService for key fetching.
  """

  require Logger
  alias Aegis.MCP.OAuth.{Config, JWKSService}

  @type validation_result :: {:ok, map()} | {:error, atom()}

  @doc """
  Validate JWT token and extract claims with optional token refresh and scope validation.

  When allow_refresh is true (default), will automatically attempt to refresh
  expired tokens. When false, simply returns error on expiration.

  Options:
  - allow_refresh: boolean (default: true) - attempt token refresh on expiration
  - required_scopes: list of scopes that must be present in the token (default: [])
  """
  @spec validate_token(String.t(), keyword()) :: validation_result()
  def validate_token(jwt_token, opts \\ [])

  def validate_token(jwt_token, opts) when is_binary(jwt_token) do
    allow_refresh = Keyword.get(opts, :allow_refresh, true)
    required_scopes = Keyword.get(opts, :required_scopes, [])
    Logger.debug("JWT validation starting for token (#{String.length(jwt_token)} chars)")

    with {:ok, header, payload, _signature} <- parse_jwt_structure(jwt_token),
         {:ok, claims} <- decode_payload(payload),
         {:ok, public_key} <- fetch_public_key_for_token(header),
         :ok <- verify_signature(jwt_token, public_key),
         validation_result <- validate_claims_with_refresh(claims, allow_refresh, required_scopes) do
      case validation_result do
        :ok ->
          Logger.info("JWT validation successful for subject: #{claims["sub"]}")
          {:ok, claims}

        {:ok, :token_refreshed, new_access_token} ->
          Logger.info("JWT: Using refreshed token for current request")
          # Recursively validate the new token, but disable further refresh attempts
          validate_token(new_access_token, allow_refresh: false, required_scopes: required_scopes)

        {:error, reason} ->
          Logger.warning("JWT validation failed: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, reason} = error ->
        Logger.warning("JWT validation failed: #{inspect(reason)}")
        error
    end
  end

  def validate_token(_, _), do: {:error, :invalid_token_format}

  @doc """
  Extract specific claims from validated JWT without full validation.

  Useful when you already have a validated token and just need to extract claims.
  Does NOT perform validation - use validate_token/1 for security-critical operations.
  """
  @spec extract_claims(String.t()) :: {:ok, map()} | {:error, atom()}
  def extract_claims(jwt_token) when is_binary(jwt_token) do
    with {:ok, _header, payload, _signature} <- parse_jwt_structure(jwt_token),
         {:ok, claims} <- decode_payload(payload) do
      {:ok, claims}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def extract_claims(_), do: {:error, :invalid_token_format}

  @doc """
  Check if a token is expired without full validation.

  Useful for determining if token refresh is needed.
  """
  @spec token_expired?(String.t()) :: boolean()
  def token_expired?(jwt_token) when is_binary(jwt_token) do
    case extract_claims(jwt_token) do
      {:ok, claims} -> claims_expired?(claims)
      {:error, _} -> true
    end
  end

  @doc """
  Extract client information from validated JWT claims.

  Looks up the OAuth token using the OAuth client ID (azp claim) to find
  the associated MCP client, rather than using the user ID directly.
  """
  @spec extract_client_info(map()) :: {:ok, map()} | {:error, atom()}
  def extract_client_info(claims) do
    alias Aegis.MCP.OAuth.ClientLookup
    ClientLookup.from_jwt_claims(claims)
  end

  # Parse JWT into header, payload, signature parts
  defp parse_jwt_structure(jwt_token) do
    case String.split(jwt_token, ".") do
      [header_b64, payload_b64, signature_b64] ->
        Logger.debug("JWT structure valid (3 parts)")

        with {:ok, header_json} <- base64_decode(header_b64, "header"),
             {:ok, header} <- Jason.decode(header_json),
             {:ok, payload_json} <- base64_decode(payload_b64, "payload") do
          {:ok, header, payload_json, signature_b64}
        else
          {:error, reason} ->
            Logger.error("Failed to parse JWT structure: #{inspect(reason)}")
            {:error, :malformed_jwt}
        end

      parts ->
        Logger.error("Invalid JWT structure: #{length(parts)} parts (expected 3)")
        {:error, :invalid_jwt_structure}
    end
  end

  # Decode base64url part
  defp base64_decode(encoded, part_name) do
    decoded = Base.url_decode64!(encoded, padding: false)
    Logger.debug("Successfully decoded JWT #{part_name}")
    {:ok, decoded}
  rescue
    error ->
      Logger.error("Failed to decode JWT #{part_name}: #{inspect(error)}")
      {:error, :"invalid_#{part_name}_encoding"}
  end

  # Decode JSON payload to claims map
  defp decode_payload(payload_json) do
    case Jason.decode(payload_json) do
      {:ok, claims} ->
        Logger.debug("JWT claims decoded successfully")
        Logger.debug("JWT claims keys: #{inspect(Map.keys(claims))}")
        {:ok, claims}

      {:error, error} ->
        Logger.error("Failed to decode claims JSON: #{inspect(error)}")
        {:error, :invalid_claims_json}
    end
  end

  # Fetch public key using JWKS service
  defp fetch_public_key_for_token(header) do
    kid = Map.get(header, "kid")
    Logger.debug("Fetching public key for kid: #{inspect(kid)}")

    case kid do
      nil ->
        Logger.error("Missing 'kid' in JWT header")
        {:error, :missing_key_id}

      kid ->
        case JWKSService.fetch_key_by_id(kid) do
          {:ok, public_key} ->
            Logger.debug("Public key fetched successfully")
            {:ok, public_key}

          {:error, reason} ->
            Logger.error("Failed to fetch public key: #{inspect(reason)}")
            {:error, :key_fetch_failed}
        end
    end
  end

  # Verify JWT signature using JOSE
  defp verify_signature(jwt_token, public_key) do
    Logger.debug("Verifying JWT signature")

    try do
      # Create JWK from PEM
      jwk = JOSE.JWK.from_pem(public_key)

      # Verify the JWT
      case JOSE.JWT.verify(jwk, jwt_token) do
        {true, _payload, _jws} ->
          Logger.debug("JWT signature verification successful")
          :ok

        {false, _payload, _jws} ->
          Logger.error("JWT signature verification failed")
          {:error, :invalid_signature}
      end
    rescue
      error ->
        Logger.error("JWT signature verification error: #{inspect(error)}")
        {:error, :signature_verification_error}
    end
  end

  # Validate all JWT claims with optional token refresh and scope validation
  defp validate_claims_with_refresh(claims, allow_refresh, required_scopes) do
    Logger.debug("Validating JWT claims")

    cond do
      not has_required_claims?(claims) ->
        {:error, :missing_required_claims}

      claims_expired?(claims) ->
        handle_expired_token(claims, allow_refresh)

      invalid_issuer?(claims) ->
        {:error, :invalid_issuer}

      missing_or_invalid_audience?(claims) ->
        {:error, :invalid_audience}

      not has_required_scopes?(claims, required_scopes) ->
        {:error, :insufficient_scope}

      true ->
        Logger.debug("All JWT claims validation passed")
        :ok
    end
  end

  defp handle_expired_token(claims, true = _allow_refresh) do
    alias Aegis.MCP.OAuth

    # Attempt to refresh the token before failing
    case OAuth.TokenRefresh.attempt_token_refresh(claims) do
      {:ok, new_access_token} ->
        Logger.info("JWT: Token was expired but successfully refreshed")
        {:ok, :token_refreshed, new_access_token}

      {:error, reason} ->
        Logger.warning("JWT: Token expired and refresh failed: #{inspect(reason)}")
        {:error, :token_expired}
    end
  end

  defp handle_expired_token(_claims, false = _allow_refresh) do
    # Refresh not allowed (to prevent infinite recursion)
    Logger.warning("JWT: Token expired and refresh not allowed")
    {:error, :token_expired}
  end

  # Check for required JWT claims
  defp has_required_claims?(claims) do
    required_claims = ["iss", "sub", "exp", "iat"]
    missing_claims = Enum.filter(required_claims, &(not Map.has_key?(claims, &1)))

    if missing_claims == [] do
      Logger.debug("All required JWT claims present")
      true
    else
      Logger.error("Missing required JWT claims: #{inspect(missing_claims)}")
      false
    end
  end

  @doc """
  Check if JWT claims indicate an expired token.

  Takes a map of JWT claims and returns true if the token is expired,
  false if it's still valid, accounting for configurable clock skew.
  """
  @spec claims_expired?(map()) :: boolean()
  def claims_expired?(claims) do
    case Map.get(claims, "exp") do
      nil ->
        Logger.error("Missing 'exp' claim")
        true

      exp when is_integer(exp) ->
        now = System.system_time(:second)
        # Add configurable clock skew buffer for time differences between servers
        clock_skew_buffer = Config.jwt_clock_skew_buffer()
        is_expired = now > exp + clock_skew_buffer

        if is_expired do
          Logger.error("Token expired: #{exp} < #{now}")
        else
          Logger.debug("Token not expired: #{exp} > #{now}")
        end

        is_expired

      exp ->
        Logger.error("Invalid 'exp' claim format: #{inspect(exp)}")
        true
    end
  end

  # Check if issuer is valid
  defp invalid_issuer?(claims) do
    keycloak_base_url = Config.keycloak_base_url()
    keycloak_realm = Config.keycloak_realm()
    expected_issuer = "#{keycloak_base_url}/realms/#{keycloak_realm}"
    actual_issuer = Map.get(claims, "iss")

    case {actual_issuer, expected_issuer} do
      {nil, _} ->
        Logger.error("Missing 'iss' claim")
        true

      {actual, expected} when actual == expected ->
        Logger.debug("JWT issuer valid: #{actual}")
        false

      {actual, expected} ->
        Logger.error("Invalid JWT issuer: #{actual} != #{expected}")
        true
    end
  end

  # Validate JWT audience claim per RFC 8707 Section 2
  #
  # SECURITY CRITICAL: Audience validation prevents "confused deputy" attacks
  # and token passthrough vulnerabilities.
  #
  # This MCP hub MUST ONLY accept tokens that were specifically issued for it
  # as indicated by the audience claim. Tokens issued for other MCP servers,
  # even from the same authorization server, MUST be rejected.
  #
  # Per MCP OAuth specification:
  # - Tokens received from MCP clients MUST NOT be forwarded to upstream servers
  # - When accessing upstream MCP servers, the hub MUST obtain separate tokens
  #   using OAuth client credentials flow with the upstream server as the audience
  defp missing_or_invalid_audience?(claims) do
    case Map.get(claims, "aud") do
      nil ->
        Logger.warning("Missing required 'aud' claim - token not bound to resource")
        true

      aud when is_binary(aud) ->
        not validate_single_audience(aud)

      aud when is_list(aud) ->
        # RFC 8707 allows audience as array - check if any match our server
        not Enum.any?(aud, &validate_single_audience/1)

      _ ->
        Logger.error("Invalid 'aud' claim format: #{inspect(Map.get(claims, "aud"))}")
        true
    end
  end

  # Validate a single audience value against our MCP server URI
  defp validate_single_audience(audience) do
    expected_resource_uris = Config.expected_resource_uris()

    case Enum.find(expected_resource_uris, fn uri ->
           audience == uri or String.starts_with?(uri, audience <> "/")
         end) do
      nil ->
        Logger.warning(
          "Token audience '#{audience}' does not match expected MCP server URIs: #{inspect(expected_resource_uris)}"
        )

        false

      _matched_uri ->
        Logger.debug("JWT audience validation successful for '#{audience}'")
        true
    end
  end

  @doc """
  Extract scopes from JWT claims.

  Per OAuth 2.0 specification, scope claim can be either:
  - A space-separated string of scopes
  - An array of scope strings

  Returns a list of scopes.
  """
  @spec extract_scopes(map()) :: [String.t()]
  def extract_scopes(claims) do
    case Map.get(claims, "scope") do
      scope when is_binary(scope) ->
        String.split(scope, " ", trim: true)

      scope when is_list(scope) ->
        scope

      _ ->
        []
    end
  end

  @doc """
  Check if JWT claims contain all required scopes.

  Returns true if all required scopes are present in the token,
  false otherwise.
  """
  @spec has_required_scopes?(map(), [String.t()]) :: boolean()
  def has_required_scopes?(_claims, []), do: true

  def has_required_scopes?(claims, required_scopes) when is_list(required_scopes) do
    token_scopes = extract_scopes(claims)

    missing_scopes = required_scopes -- token_scopes

    if missing_scopes == [] do
      Logger.debug("JWT: All required scopes present: #{inspect(required_scopes)}")
      true
    else
      Logger.warning(
        "JWT: Missing required scopes: #{inspect(missing_scopes)}. " <>
          "Token has: #{inspect(token_scopes)}, Required: #{inspect(required_scopes)}"
      )

      false
    end
  end
end
