defmodule Aegis.MCP.OAuth.JWKSService do
  @moduledoc """
  Service for fetching and caching JWKS (JSON Web Key Set) from Keycloak.

  Separated from JWT validation to provide a focused service for key management
  with proper caching, error handling, and telemetry.
  """

  require Logger
  alias Aegis.MCP.OAuth.{Config, Errors}

  @doc """
  Fetch public key by key ID (kid).

  Returns the PEM-formatted public key for JWT signature verification.
  Uses caching to minimize requests to the JWKS endpoint.
  """
  @spec fetch_key_by_id(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def fetch_key_by_id(kid) when is_binary(kid) do
    case get_cached_keys() do
      {:ok, keys} ->
        fetch_key_from_cache_or_refresh(keys, kid)

      {:error, reason} ->
        {:error, reason}
    end
  end

  def fetch_key_by_id(_), do: {:error, :invalid_key_id}

  defp fetch_key_from_cache_or_refresh(keys, kid) do
    case find_key_by_id(keys, kid) do
      {:ok, key} ->
        {:ok, key}

      {:error, :not_found} ->
        refresh_and_find_key(kid)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp refresh_and_find_key(kid) do
    case refresh_keys_cache() do
      {:ok, fresh_keys} -> find_key_by_id(fresh_keys, kid)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Refresh the JWKS cache by fetching fresh keys from Keycloak.

  This is called automatically when a key is not found in cache,
  or can be called manually to force a cache refresh.
  """
  @spec refresh_keys_cache() :: {:ok, [map()]} | {:error, atom()}
  def refresh_keys_cache do
    jwks_url = Config.jwks_endpoint()

    case fetch_jwks(jwks_url) do
      {:ok, keys} ->
        # Cache the keys with timestamp
        timestamp = System.system_time(:second)
        :ets.insert(:jwks_cache, {:keys, keys, timestamp})
        Logger.debug("JWKS cache refreshed with #{length(keys)} keys")
        {:ok, keys}

      {:error, reason} ->
        Errors.log_error(reason, "jwks_cache_refresh")
        {:error, reason}
    end
  end

  @doc """
  Get cache statistics for monitoring and debugging.
  """
  @spec cache_stats() :: map()
  def cache_stats do
    case :ets.lookup(:jwks_cache, :keys) do
      [{:keys, keys, timestamp}] ->
        age_seconds = System.system_time(:second) - timestamp
        ttl_seconds = Config.jwks_cache_ttl()

        %{
          keys_count: length(keys),
          age_seconds: age_seconds,
          ttl_seconds: ttl_seconds,
          expired: age_seconds > ttl_seconds,
          cache_hit: true
        }

      [] ->
        %{
          keys_count: 0,
          age_seconds: nil,
          ttl_seconds: Config.jwks_cache_ttl(),
          expired: true,
          cache_hit: false
        }
    end
  end

  # Get keys from cache if not expired
  defp get_cached_keys do
    case :ets.lookup(:jwks_cache, :keys) do
      [{:keys, keys, timestamp}] ->
        age_seconds = System.system_time(:second) - timestamp
        ttl_seconds = Config.jwks_cache_ttl()

        if age_seconds < ttl_seconds do
          Logger.debug("JWKS cache hit (age: #{age_seconds}s)")
          {:ok, keys}
        else
          Logger.debug("JWKS cache expired (age: #{age_seconds}s, ttl: #{ttl_seconds}s)")
          refresh_keys_cache()
        end

      [] ->
        Logger.debug("JWKS cache empty")
        refresh_keys_cache()
    end
  rescue
    # Handle case where ETS table doesn't exist
    ArgumentError ->
      Logger.error("JWKS cache table not initialized")
      {:error, :cache_not_initialized}
  end

  # Fetch JWKS from Keycloak endpoint
  defp fetch_jwks(url) do
    Logger.debug("Fetching JWKS from: #{url}")

    case Req.get(url, Config.http_options()) do
      {:ok, %{status: 200, body: %{"keys" => keys}}} when is_list(keys) ->
        Logger.info("Fetched #{length(keys)} keys from JWKS endpoint")
        {:ok, keys}

      {:ok, %{status: 200, body: body}} ->
        Logger.error("JWKS response missing 'keys' field: #{inspect(body)}")
        {:error, :invalid_jwks_response}

      {:ok, %{status: status}} ->
        Logger.error("JWKS request failed with HTTP #{status}")
        {:error, :jwks_fetch_failed}

      {:error, reason} ->
        Logger.error("JWKS request failed: #{inspect(reason)}")
        {:error, :network_error}
    end
  end

  # Find a specific key by its ID in the key set
  defp find_key_by_id(keys, kid) do
    case Enum.find(keys, fn key -> key["kid"] == kid end) do
      nil ->
        Logger.debug("Key ID '#{kid}' not found in JWKS")
        {:error, :not_found}

      key ->
        convert_jwk_to_pem(key)
    end
  end

  # Convert JWK to PEM format for JOSE
  defp convert_jwk_to_pem(%{"kty" => "RSA"} = jwk) do
    Logger.debug("Converting RSA JWK to PEM format for kid: #{jwk["kid"]}")

    try do
      jose_jwk = JOSE.JWK.from_map(jwk)
      {_kty, public_key} = JOSE.JWK.to_public_key(jose_jwk)
      pem_entry = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)
      pem_binary = :public_key.pem_encode([pem_entry])

      {:ok, pem_binary}
    rescue
      error ->
        Logger.error("JWK to PEM conversion failed for kid #{jwk["kid"]}: #{inspect(error)}")
        {:error, :key_conversion_failed}
    end
  end

  defp convert_jwk_to_pem(%{"kty" => kty} = key) do
    Logger.error("Unsupported key type '#{kty}' for kid #{key["kid"]}")
    {:error, :unsupported_key_type}
  end

  defp convert_jwk_to_pem(key) do
    Logger.error("Invalid JWK format: #{inspect(key)}")
    {:error, :invalid_jwk_format}
  end
end
