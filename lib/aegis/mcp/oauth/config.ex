defmodule Aegis.MCP.OAuth.Config do
  @moduledoc """
  Centralized OAuth 2.0 configuration module.

  Provides a single source of truth for all OAuth-related configuration,
  including Keycloak endpoints, token settings, and security policies.

  This module replaces scattered Application.get_env/3 calls throughout
  the OAuth implementation with validated, centralized configuration.
  """

  require Logger

  @doc """
  Get the Keycloak base URL.
  Required for token exchange and validation.
  """
  @spec keycloak_base_url() :: String.t()
  def keycloak_base_url do
    Application.fetch_env!(:aegis, :keycloak_base_url)
  end

  @doc """
  Get the Keycloak realm.
  """
  @spec keycloak_realm() :: String.t()
  def keycloak_realm do
    Application.get_env(:aegis, :keycloak_realm, "aegis-mcp")
  end

  @doc """
  Get the complete Keycloak token endpoint URL.
  """
  @spec token_endpoint() :: String.t()
  def token_endpoint do
    "#{keycloak_base_url()}/realms/#{keycloak_realm()}/protocol/openid-connect/token"
  end

  @doc """
  Get the JWKS endpoint URL for fetching public keys.
  """
  @spec jwks_endpoint() :: String.t()
  def jwks_endpoint do
    "#{keycloak_base_url()}/realms/#{keycloak_realm()}/protocol/openid-connect/certs"
  end

  @doc """
  Get the expected JWT issuer.
  """
  @spec jwt_issuer() :: String.t()
  def jwt_issuer do
    "#{keycloak_base_url()}/realms/#{keycloak_realm()}"
  end

  @doc """
  Get the token signing secret for internal Hub tokens.
  Fails fast if not configured in production.
  """
  @spec token_signing_secret() :: String.t()
  def token_signing_secret do
    Application.fetch_env!(:aegis, :token_signing_secret)
  end

  @doc """
  Get the Hub's canonical server URI.
  Used for audience validation and issuer claims.
  """
  @spec hub_server_uri() :: String.t()
  def hub_server_uri do
    Application.get_env(:aegis, :canonical_server_uri) ||
      "https://#{server_host()}"
  end

  @doc """
  Get the server host configuration.
  """
  @spec server_host() :: String.t()
  def server_host do
    Application.get_env(:aegis, :server_host, "localhost")
  end

  @doc """
  Get the server port configuration.
  """
  @spec server_port() :: pos_integer()
  def server_port do
    Application.get_env(:aegis, :server_port, 4000)
  end

  @doc """
  Get the Hub's service account ID for token delegation.
  """
  @spec hub_service_id() :: String.t()
  def hub_service_id do
    Application.get_env(:aegis, :hub_service_id, "aegis-hub")
  end

  @doc """
  Get token expiration time in minutes for different token types.
  """
  @spec token_expiry_minutes(atom()) :: pos_integer()
  def token_expiry_minutes(token_type) do
    case token_type do
      :delegation -> 15
      :access -> 60
      # 24 hours
      :refresh -> 1440
      _ -> 15
    end
  end

  @doc """
  Get the expected resource URIs for audience validation.
  These are the URIs that this MCP server accepts tokens for.
  """
  @spec expected_resource_uris() :: [String.t()]
  def expected_resource_uris do
    base_urls = [
      hub_server_uri(),
      "https://#{server_host()}",
      "http://#{server_host()}:#{server_port()}"
    ]

    base_urls
    |> Enum.reject(&is_nil/1)
    |> Enum.flat_map(fn base_url ->
      [
        base_url,
        "#{base_url}/mcp"
      ]
    end)
    |> Enum.uniq()
  end

  @doc """
  Get the default OAuth callback URL for proxy endpoints.
  Returns the configured callback URL or raises in production if not set.
  """
  @spec default_callback_url() :: String.t()
  def default_callback_url do
    case Application.get_env(:aegis, :oauth_default_callback_url) do
      nil ->
        env = Application.get_env(:aegis, :environment, :dev)

        case env do
          :prod ->
            raise "OAuth default callback URL must be configured in production via :oauth_default_callback_url"

          _ ->
            # Development fallback - MCP Inspector's callback URL
            "http://localhost:6274/oauth/callback/debug"
        end

      url when is_binary(url) ->
        url
    end
  end

  @doc """
  Get OAuth client connection timeout in milliseconds.
  """
  @spec connection_timeout() :: pos_integer()
  def connection_timeout do
    Application.get_env(:aegis, :oauth_connection_timeout, 5000)
  end

  @doc """
  Get OAuth client receive timeout in milliseconds.
  """
  @spec receive_timeout() :: pos_integer()
  def receive_timeout do
    Application.get_env(:aegis, :oauth_receive_timeout, 10_000)
  end

  @doc """
  Get JWKS cache TTL in seconds.
  """
  @spec jwks_cache_ttl() :: pos_integer()
  def jwks_cache_ttl do
    # 1 hour
    Application.get_env(:aegis, :jwks_cache_ttl, 3600)
  end

  @doc """
  Get JWT clock skew buffer in seconds.
  Used to account for clock differences between servers during token validation.
  """
  @spec jwt_clock_skew_buffer() :: pos_integer()
  def jwt_clock_skew_buffer do
    # Default to 10 seconds for better security (reduced from previous 30s)
    Application.get_env(:aegis, :jwt_clock_skew_buffer, 10)
  end

  @doc """
  Validate that all required OAuth configuration is present.
  Should be called during application startup.
  """
  @spec validate_config!() :: :ok | no_return()
  def validate_config! do
    required_configs = [
      {:keycloak_base_url, &keycloak_base_url/0},
      {:token_signing_secret, &token_signing_secret/0}
    ]

    Enum.each(required_configs, fn {name, getter_fn} ->
      try do
        value = getter_fn.()

        if is_binary(value) and String.trim(value) != "" do
          Logger.debug("OAuth Config: #{name} is configured")
        else
          raise "OAuth configuration #{name} is empty or invalid: #{inspect(value)}"
        end
      rescue
        error ->
          Logger.error("OAuth Configuration Error: #{name} - #{inspect(error)}")
          reraise "Missing or invalid OAuth configuration: #{name}", __STACKTRACE__
      end
    end)

    # Validate environment-specific settings
    validate_environment_config!()

    Logger.info("OAuth configuration validation completed successfully")
    :ok
  end

  # Validate environment-specific OAuth configuration
  defp validate_environment_config! do
    env = Application.get_env(:aegis, :environment, :dev)

    case env do
      :prod ->
        secret = token_signing_secret()

        if String.length(secret) < 32 do
          raise "OAuth token signing secret must be at least 32 characters in production"
        end

      :test ->
        # Test environment allows relaxed settings
        :ok

      :dev ->
        # Development environment allows relaxed settings
        :ok

      _ ->
        Logger.warning("Unknown environment #{env} - using development settings")
    end
  end

  @doc """
  Get HTTP request options for OAuth API calls.
  """
  @spec http_options() :: keyword()
  def http_options do
    []
  end

  @doc """
  Get configuration for OAuth token refresh operations.
  """
  @spec refresh_config() :: map()
  def refresh_config do
    %{
      max_retries: 3,
      retry_delay_ms: 1000,
      jitter_ms: 500
    }
  end
end
