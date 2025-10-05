defmodule Aegis.MCP.ClientPermissionManager do
  @moduledoc """
  Manages permission assignments for MCP clients.

  Handles permission granting, revocation, and synchronization based on
  server capabilities, extracting this logic from LiveView concerns.
  """

  require Ash.Query
  alias Aegis.MCP
  alias Aegis.MCP.PermissionDefaults

  @doc """
  Synchronize client permissions based on form selections.

  Takes a client_id and a map of server/capability selections, and ensures
  the client's permission assignments match the selections.

  ## Examples

      sync_permissions("client-123", %{
        "server1" => %{"tools" => "true", "resources" => "true"},
        "server2" => %{"prompts" => "true"}
      })
  """
  @spec sync_permissions(String.t(), map()) :: :ok
  def sync_permissions(client_id, permissions_params) when is_map(permissions_params) do
    # Clear existing permissions
    clear_client_permissions(client_id)

    # Grant new permissions based on form data
    Enum.each(permissions_params, fn {server_name, capabilities} ->
      Enum.each(capabilities, &grant_capability_if_enabled(client_id, server_name, &1))
    end)

    :ok
  end

  @doc """
  Grant permissions for a specific server capability.

  Finds or creates permissions for the server/capability combination and
  grants them to the client.
  """
  @spec grant_for_capability(String.t(), String.t(), atom()) :: :ok
  def grant_for_capability(client_id, server_name, resource_type) do
    # Find permissions that match this server and resource type
    permissions =
      MCP.list_permissions!(
        query:
          Ash.Query.filter(MCP.Permission,
            server_name: server_name,
            resource_type: resource_type
          )
      )

    # If no permissions exist for this server, create them first
    permissions =
      if Enum.empty?(permissions) do
        create_default_permissions_for_server(server_name)
        # Re-query to get the newly created permissions
        MCP.list_permissions!(
          query:
            Ash.Query.filter(MCP.Permission,
              server_name: server_name,
              resource_type: resource_type
            )
        )
      else
        permissions
      end

    # Grant each matching permission
    Enum.each(permissions, fn permission ->
      MCP.grant_permission!(client_id, permission.id)
    end)

    :ok
  end

  @doc """
  Clear all permissions for a client.

  Revokes all permission assignments for the given client.
  """
  @spec clear_permissions(String.t()) :: :ok
  def clear_permissions(client_id) do
    clear_client_permissions(client_id)
  end

  @doc """
  Grant a specific permission to a client.

  Returns {:ok, client_permission} if successful, {:error, reason} otherwise.
  """
  @spec grant_permission(String.t(), String.t()) ::
          {:ok, MCP.ClientPermission.t()} | {:error, term()}
  def grant_permission(client_id, permission_id) do
    MCP.grant_permission(client_id, permission_id)
  end

  @doc """
  Revoke a specific permission from a client.
  """
  @spec revoke_permission(String.t(), String.t()) :: :ok
  def revoke_permission(client_id, permission_id) do
    MCP.revoke_permission!(client_id, permission_id, %{})
  end

  # Private Functions

  defp clear_client_permissions(client_id) do
    client_permissions = MCP.list_permissions_for_client!(client_id)

    Enum.each(client_permissions, fn client_permission ->
      MCP.revoke_permission!(client_permission)
    end)
  end

  defp create_default_permissions_for_server(server_name) do
    PermissionDefaults.create_client_permissions(server_name)
  end

  defp grant_capability_if_enabled(client_id, server_name, {capability_str, "true"}) do
    # Convert string to atom safely using whitelist validation
    case capability_str do
      "tools" -> grant_for_capability(client_id, server_name, :tools)
      "resources" -> grant_for_capability(client_id, server_name, :resources)
      "prompts" -> grant_for_capability(client_id, server_name, :prompts)
      # Ignore invalid capabilities to prevent atom exhaustion
      _ -> :ok
    end
  end

  defp grant_capability_if_enabled(_client_id, _server_name, _other), do: :ok
end
