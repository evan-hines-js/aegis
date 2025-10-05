defmodule Aegis.MCP.OAuth.ClientLookup do
  @moduledoc """
  MCP client lookup operations for OAuth flows.

  Centralizes client lookup logic used across token refresh,
  JWT validation, and token proxy operations.
  """

  require Logger
  alias Aegis.MCP.Client

  @doc """
  Look up MCP client by OAuth client ID (from authorization server).

  Returns the active MCP client associated with the OAuth client ID.
  """
  @spec by_oauth_client_id(String.t()) :: {:ok, map()} | {:error, atom()}
  def by_oauth_client_id(oauth_client_id) when is_binary(oauth_client_id) do
    case Client.get_by_oauth_client_id(oauth_client_id) do
      {:ok, %{active: true} = client} ->
        Logger.debug("Found active MCP client for OAuth client ID: #{oauth_client_id}")
        {:ok, client}

      {:ok, %{active: false}} ->
        Logger.warning("MCP client found but inactive: #{oauth_client_id}")
        {:error, :client_inactive}

      {:error, _} ->
        Logger.debug("No MCP client found for OAuth client ID: #{oauth_client_id}")
        {:error, :client_not_found}
    end
  end

  def by_oauth_client_id(_), do: {:error, :invalid_client_id}

  @doc """
  Look up MCP client from OAuth token records by Keycloak client ID.

  This is used when we have a Keycloak client ID and need to find the
  associated MCP client through the OAuth token mapping.
  """
  @spec by_oauth_token(String.t()) :: {:ok, map()} | {:error, atom()}
  def by_oauth_token(keycloak_client_id) when is_binary(keycloak_client_id) do
    case Aegis.MCP.get_oauth_token_by_keycloak_client(keycloak_client_id) do
      {:ok, [oauth_token | _]} when oauth_token.client != nil ->
        validate_client_status(oauth_token.client)

      {:ok, []} ->
        Logger.debug("No OAuth tokens found for Keycloak client: #{keycloak_client_id}")
        {:error, :oauth_token_not_found}

      {:error, reason} ->
        Logger.error("Failed to lookup OAuth token: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def by_oauth_token(_), do: {:error, :invalid_client_id}

  @doc """
  Find OAuth token with refresh token for a given Keycloak client ID.

  Returns the first active OAuth token that has a refresh token available.
  """
  @spec find_token_with_refresh(String.t()) :: {:ok, map()} | {:error, atom()}
  def find_token_with_refresh(keycloak_client_id) do
    with {:ok, tokens} <- get_oauth_tokens(keycloak_client_id),
         {:ok, loaded_tokens} <- load_refresh_tokens(tokens) do
      find_active_with_refresh(loaded_tokens)
    end
  end

  @doc """
  Extract MCP client from JWT claims.

  Looks up the OAuth token using the client ID claim (azp) to find
  the associated MCP client.
  """
  @spec from_jwt_claims(map()) :: {:ok, map()} | {:error, atom()}
  def from_jwt_claims(claims) do
    oauth_client_id = Map.get(claims, "azp")
    subject = Map.get(claims, "sub")

    case oauth_client_id do
      nil ->
        Logger.error("JWT: Missing 'azp' (OAuth client ID) claim for client lookup")
        {:error, :missing_client_id}

      oauth_client_id ->
        Logger.debug("JWT: Looking up MCP client for OAuth client ID: #{oauth_client_id}")

        case by_oauth_client_id(oauth_client_id) do
          {:ok, mcp_client} ->
            Logger.debug(
              "JWT: Found MCP client #{mcp_client.id} for OAuth client #{oauth_client_id}"
            )

            {:ok, mcp_client}

          {:error, :client_not_found} ->
            Logger.warning("JWT: No MCP client found for OAuth client ID: #{oauth_client_id}")
            Logger.warning("JWT: Subject was: #{subject}")
            {:error, :client_not_found}

          {:error, reason} ->
            Logger.error("JWT: Failed to lookup MCP client: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  # Private functions

  defp validate_client_status(%{active: true} = client) do
    Logger.debug("Found active MCP client: #{client.id}")
    {:ok, client}
  end

  defp validate_client_status(%{active: false}) do
    Logger.warning("MCP client is inactive")
    {:error, :client_inactive}
  end

  defp get_oauth_tokens(keycloak_client_id) do
    case Aegis.MCP.get_oauth_token_by_keycloak_client(keycloak_client_id) do
      {:ok, tokens} when is_list(tokens) and length(tokens) > 0 ->
        {:ok, tokens}

      {:ok, []} ->
        {:error, :no_oauth_tokens_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp load_refresh_tokens(oauth_tokens) do
    case Ash.load(oauth_tokens, :refresh_token) do
      {:ok, loaded_tokens} ->
        {:ok, loaded_tokens}

      {:error, reason} ->
        Logger.error("Failed to load refresh_token field: #{inspect(reason)}")
        {:error, :refresh_token_load_failed}
    end
  end

  defp find_active_with_refresh(loaded_tokens) do
    case Enum.find(loaded_tokens, &has_refresh_token?/1) do
      nil -> {:error, :no_refresh_token_available}
      token -> {:ok, token}
    end
  end

  defp has_refresh_token?(token) do
    token.refresh_token != nil and token.active == true
  end
end
