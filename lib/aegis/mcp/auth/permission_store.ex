defmodule Aegis.MCP.PermissionStore do
  @moduledoc """
  Database operations for MCP client permissions.

  Handles all database interactions for permission management,
  keeping authorization logic separate from data access patterns.
  """

  require Logger
  require Ash.Query
  alias Aegis.MCP
  alias Aegis.MCP.{ApiKeyUtils, AuthorizationErrors, PatternMatcher}

  @type permission_map :: %{
          resource_type: String.t(),
          server_name: String.t(),
          resource_pattern: String.t(),
          action: String.t()
        }
  @type permissions_result :: AuthorizationErrors.permissions_result()
  @type client_result :: AuthorizationErrors.client_result()

  @doc """
  Validate that a client exists and is active.

  FIXED: PRODUCTION CI ISSUE #3 - JWT CLIENT LOOKUP
  ✅ Updated JWT validation to use OAuth token mapping (see jwt_validator.ex)
  ✅ Now uses 'azp' claim (Keycloak client ID) instead of 'sub' claim (user ID)
  ✅ Correctly looks up oauth_tokens table to find associated MCP client

  REMAINING CI SETUP NEEDED:
  - Ensure OAuth token records exist in database for Keycloak clients
  - Verify OAuth registration flow creates proper client -> token mappings
  - Check that oauth_tokens.keycloak_client_id matches JWT 'azp' claim values
  """
  @spec validate_client(String.t()) :: client_result()
  def validate_client(client_id) do
    case MCP.Client
         |> Ash.Query.for_read(:read)
         |> Ash.Query.filter(id == ^client_id)
         |> Ash.read_one() do
      {:ok, %{active: true} = client} ->
        {:ok, client}

      {:ok, %{active: false}} ->
        {:error, :client_inactive}

      {:ok, nil} ->
        Logger.warning(
          "PRODUCTION CI ISSUE #3: Client ID #{client_id} from JWT not found in MCP clients table"
        )

        {:error, :client_not_found}

      {:error, reason} ->
        normalized_error = AuthorizationErrors.normalize_error(reason)
        {:error, normalized_error}
    end
  end

  @doc """
  Get all permissions for a client from the database.

  Returns normalized permission maps ready for authorization checks.
  """
  @spec get_client_permissions(String.t()) :: permissions_result()
  def get_client_permissions(client_id) do
    query =
      MCP.Client
      |> Ash.Query.for_read(:read)
      |> Ash.Query.filter(id == ^client_id)
      |> Ash.Query.load(:permissions)

    case Ash.read_one(query) do
      {:ok, %{active: true, permissions: permissions}} ->
        permission_list = build_permission_maps(permissions)
        {:ok, permission_list}

      {:ok, %{active: false}} ->
        {:error, :client_inactive}

      {:ok, nil} ->
        {:error, :client_not_found}

      {:error, reason} ->
        normalized_error = AuthorizationErrors.normalize_error(reason)

        Logger.error(
          "Failed to get client permissions for #{client_id}: #{inspect(reason)} -> #{normalized_error}"
        )

        {:error, normalized_error}
    end
  end

  @doc """
  Check if a client has a specific permission by querying the join table.

  Optimized for single permission checks rather than bulk operations.
  """
  @spec check_permission(String.t(), atom(), String.t(), String.t(), atom()) ::
          AuthorizationErrors.authorization_result()
  def check_permission(client_id, resource_type, server_name, resource_pattern, action) do
    query =
      MCP.ClientPermission
      |> Ash.Query.for_read(:read)
      |> Ash.Query.filter(client_id == ^client_id)
      |> Ash.Query.load([:permission])

    case Ash.read(query) do
      {:ok, client_permissions} ->
        permissions = Enum.map(client_permissions, & &1.permission)

        if has_matching_permission?(
             permissions,
             resource_type,
             server_name,
             resource_pattern,
             action
           ) do
          {:ok, :authorized}
        else
          Logger.info(
            "Permission denied for client #{client_id}: #{resource_type}/#{server_name}/#{resource_pattern}:#{action}"
          )

          {:error, :permission_denied}
        end

      {:error, reason} ->
        normalized_error = AuthorizationErrors.normalize_error(reason)

        Logger.error(
          "Failed to query permissions for client #{client_id}: #{inspect(reason)} -> #{normalized_error}"
        )

        {:error, normalized_error}
    end
  end

  @doc """
  Validate a JWT token and extract client information.

  Returns client information extracted from JWT claims if valid.
  """
  @spec validate_jwt_token(String.t()) :: AuthorizationErrors.jwt_client_result()
  def validate_jwt_token(jwt_token) when is_binary(jwt_token) do
    Logger.debug("Starting JWT validation for token (#{String.length(jwt_token)} chars)")

    alias Aegis.MCP.OAuth

    # Check if this is a hub-issued token or external (Keycloak) token
    if OAuth.HubTokenService.hub_token?(jwt_token) do
      validate_hub_jwt_token(jwt_token)
    else
      validate_external_jwt_token(jwt_token)
    end
  end

  # Validate hub-issued JWT tokens
  defp validate_hub_jwt_token(jwt_token) do
    alias Aegis.MCP.OAuth

    Logger.debug("Validating hub-issued JWT token")

    case OAuth.HubTokenService.validate_access_token(jwt_token) do
      {:ok, claims} ->
        Logger.debug("Hub JWT validation successful, extracting client info")

        # Extract client from hub token claims
        case extract_client_from_hub_claims(claims) do
          {:ok, client} ->
            Logger.debug("Successfully found hub client: #{client.id}")
            {:ok, client}

          {:error, reason} ->
            Logger.warning("Failed to extract client from hub JWT: #{inspect(reason)}")
            {:error, AuthorizationErrors.normalize_error(reason)}
        end

      {:error, reason} ->
        Logger.warning("Hub JWT validation failed: #{inspect(reason)}")
        {:error, AuthorizationErrors.normalize_error(reason)}
    end
  end

  # Validate external (Keycloak) JWT tokens
  defp validate_external_jwt_token(jwt_token) do
    alias Aegis.MCP.OAuth

    Logger.debug("Validating external JWT token")

    # Use OAuth JWT service for Keycloak tokens
    case OAuth.JWTService.validate_token(jwt_token) do
      {:ok, claims} ->
        Logger.debug(
          "External JWT validation successful, extracting client from claims: #{inspect(Map.keys(claims))}"
        )

        case OAuth.JWTService.extract_client_info(claims) do
          {:ok, client_info} ->
            Logger.debug("Successfully extracted client info: #{inspect(client_info)}")
            {:ok, client_info}

          {:error, reason} ->
            Logger.warning(
              "Failed to extract client from external JWT claims: #{inspect(reason)}"
            )

            {:error, AuthorizationErrors.normalize_error(reason)}
        end

      {:error, reason} ->
        Logger.warning("External JWT validation failed: #{inspect(reason)}")
        {:error, AuthorizationErrors.normalize_error(reason)}
    end
  end

  # Extract client information from hub-issued JWT claims
  defp extract_client_from_hub_claims(claims) do
    alias Aegis.MCP

    case claims["sub"] do
      client_id when is_binary(client_id) ->
        case MCP.Client.get_by_id(client_id) do
          {:ok, client} when client.active == true ->
            # Add scope information from the token
            scopes = String.split(claims["scope"] || "", " ", trim: true)
            client_with_scopes = Map.put(client, :token_scopes, scopes)
            {:ok, client_with_scopes}

          {:ok, _client} ->
            {:error, :client_inactive}

          {:error, _} ->
            {:error, :client_not_found}
        end

      _ ->
        {:error, :invalid_subject}
    end
  end

  @doc """
  Find a client by their API key hash.

  Returns the client if found and active, normalized error otherwise.
  """
  @spec find_client_by_api_key(String.t()) :: client_result()
  def find_client_by_api_key(api_key) when is_binary(api_key) do
    # Use fast lookup hash to find potential match
    api_key_lookup_hash = ApiKeyUtils.lookup_hash(api_key)

    query =
      MCP.Client
      |> Ash.Query.for_read(:read)
      |> Ash.Query.filter(api_key_lookup_hash == ^api_key_lookup_hash)

    case Ash.read_one(query) do
      {:ok, %{active: true, api_key_hash: stored_hash} = client} ->
        # Verify the API key against the stored Argon2 hash
        if ApiKeyUtils.verify_api_key(api_key, stored_hash) do
          {:ok, client}
        else
          {:error, :invalid_api_key}
        end

      {:ok, %{active: false}} ->
        {:error, :client_inactive}

      {:ok, nil} ->
        # Run fake verification to prevent timing attacks
        ApiKeyUtils.no_api_key_verify()
        {:error, :invalid_api_key}

      {:error, _} ->
        ApiKeyUtils.no_api_key_verify()
        {:error, :invalid_api_key}
    end
  end

  # Private helper functions

  defp build_permission_maps(permissions) do
    Enum.map(permissions, &build_permission_map/1)
  end

  defp build_permission_map(permission) do
    %{
      resource_type: permission.resource_type,
      server_name: permission.server_name,
      resource_pattern: permission.resource_pattern,
      action: permission.action
    }
  end

  @doc """
  Get all client IDs that have permissions to access a specific server.

  Used for cache invalidation when a server is deleted.
  """
  @spec get_clients_with_server_access(String.t()) :: {:ok, [String.t()]} | {:error, atom()}
  def get_clients_with_server_access(server_name) do
    query =
      MCP.ClientPermission
      |> Ash.Query.for_read(:read)
      |> Ash.Query.load([:permission])
      |> Ash.Query.filter(permission.server_name == ^server_name)

    case Ash.read(query) do
      {:ok, client_permissions} ->
        client_ids =
          client_permissions
          |> Enum.map(& &1.client_id)
          |> Enum.uniq()

        {:ok, client_ids}

      {:error, reason} ->
        normalized_error = AuthorizationErrors.normalize_error(reason)

        Logger.error(
          "Failed to query client permissions for server #{server_name}: #{inspect(reason)} -> #{normalized_error}"
        )

        {:error, normalized_error}
    end
  end

  defp has_matching_permission?(permissions, resource_type, server_name, resource_pattern, action) do
    Enum.any?(permissions, fn permission ->
      PatternMatcher.permission_matches?(
        permission,
        resource_type,
        server_name,
        resource_pattern,
        action
      )
    end)
  end
end
