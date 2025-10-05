defmodule Aegis.MCP.OAuth.HubTokenService do
  @moduledoc """
  JWT token generation and validation service for hub-issued tokens.

  Issues JWT tokens for clients authenticating directly with the hub
  (as opposed to tokens issued by external authorization servers like Keycloak).
  """

  require Logger
  alias Aegis.MCP.OAuth.Config

  # 1 hour
  @token_expiry_seconds 3600
  @issuer "aegis_hub"

  @doc """
  Generate a JWT access token for a hub client.

  Issues a signed JWT with client information and scopes.
  """
  @spec generate_access_token(map(), list(String.t())) :: {:ok, String.t()} | {:error, atom()}
  def generate_access_token(client, scopes) do
    now = System.system_time(:second)

    claims = %{
      # Standard JWT claims
      "iss" => @issuer,
      "sub" => client.id,
      "aud" => "aegis_hub",
      "exp" => now + @token_expiry_seconds,
      "iat" => now,
      "nbf" => now,
      "jti" => generate_jti(),

      # Hub-specific claims
      "client_id" => client.oauth_client_id,
      "scope" => Enum.join(scopes, " "),
      "auth_type" => "oauth_client_credentials",
      "token_type" => "access_token"
    }

    token = sign_jwt(claims)

    Logger.debug(
      "Hub JWT generated for client #{client.oauth_client_id} with scopes: #{inspect(scopes)}"
    )

    {:ok, token}
  rescue
    error ->
      Logger.error("Failed to generate hub JWT: #{inspect(error)}")
      {:error, :token_generation_failed}
  end

  @doc """
  Validate a hub-issued JWT token and extract claims.

  Verifies signature, expiration, and hub-specific claims.
  """
  @spec validate_access_token(String.t()) :: {:ok, map()} | {:error, atom()}
  def validate_access_token(jwt_token) when is_binary(jwt_token) do
    Logger.debug("Validating hub JWT token")

    with {:ok, claims} <- verify_jwt(jwt_token),
         :ok <- validate_hub_claims(claims) do
      Logger.debug("Hub JWT validation successful for subject: #{claims["sub"]}")
      {:ok, claims}
    else
      {:error, reason} = error ->
        Logger.warning("Hub JWT validation failed: #{inspect(reason)}")
        error
    end
  end

  def validate_access_token(_), do: {:error, :invalid_token_format}

  @doc """
  Get the token expiry time in seconds.
  """
  @spec token_expiry_seconds() :: pos_integer()
  def token_expiry_seconds, do: @token_expiry_seconds

  @doc """
  Check if a token is a hub-issued token (vs external like Keycloak).

  Quick check without full validation.
  """
  @spec hub_token?(String.t()) :: boolean()
  def hub_token?(jwt_token) when is_binary(jwt_token) do
    case extract_claims_unsafe(jwt_token) do
      {:ok, claims} -> claims["iss"] == @issuer
      {:error, _} -> false
    end
  end

  def hub_token?(_), do: false

  # Private functions

  defp sign_jwt(claims) do
    jwk = get_signing_key()
    JOSE.JWT.sign(jwk, %{"alg" => "HS256"}, claims) |> JOSE.JWS.compact() |> elem(1)
  end

  defp verify_jwt(jwt_token) do
    jwk = get_signing_key()

    case JOSE.JWT.verify(jwk, jwt_token) do
      {true, %JOSE.JWT{fields: claims}, _jws} ->
        {:ok, claims}

      {false, _jwt, _jws} ->
        {:error, :invalid_signature}
    end
  rescue
    error ->
      Logger.error("JWT verification failed: #{inspect(error)}")
      {:error, :verification_failed}
  end

  defp validate_hub_claims(claims) do
    with :ok <- validate_claims_structure(claims),
         :ok <- validate_issuer_and_audience(claims),
         :ok <- validate_timing_claims(claims) do
      validate_subject_claim(claims)
    end
  end

  defp validate_claims_structure(claims) do
    if is_map(claims), do: :ok, else: {:error, :invalid_claims}
  end

  defp validate_issuer_and_audience(claims) do
    cond do
      claims["iss"] != @issuer -> {:error, :invalid_issuer}
      claims["aud"] != "aegis_hub" -> {:error, :invalid_audience}
      true -> :ok
    end
  end

  defp validate_timing_claims(claims) do
    now = System.system_time(:second)

    cond do
      not is_integer(claims["exp"]) -> {:error, :missing_expiration}
      claims["exp"] <= now -> {:error, :token_expired}
      not is_integer(claims["iat"]) -> {:error, :missing_issued_at}
      claims["iat"] > now + 60 -> {:error, :token_not_yet_valid}
      true -> :ok
    end
  end

  defp validate_subject_claim(claims) do
    if is_binary(claims["sub"]), do: :ok, else: {:error, :missing_subject}
  end

  defp extract_claims_unsafe(jwt_token) do
    # Extract claims without signature verification - ONLY for quick checks
    with [_header, payload, _signature] <- String.split(jwt_token, "."),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} <- Jason.decode(json) do
      {:ok, claims}
    else
      [_ | _] -> {:error, :invalid_structure}
      [] -> {:error, :invalid_structure}
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_json}
      :error -> {:error, :invalid_encoding}
    end
  rescue
    _ -> {:error, :extraction_failed}
  end

  defp generate_jti do
    # Generate a unique JWT ID
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp get_signing_key do
    # Use the same secret as the hub's token signing secret
    secret = Config.token_signing_secret()
    JOSE.JWK.from_oct(secret)
  end
end
