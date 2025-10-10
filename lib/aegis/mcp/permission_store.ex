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
