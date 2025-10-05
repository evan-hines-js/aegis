defmodule Aegis.MCP.PermissionDefaults do
  @moduledoc """
  Shared utilities for creating default permissions for MCP servers.

  Provides consistent default permission creation across the application.
  """

  @doc """
  Creates comprehensive default permissions for a server.

  Used when creating a new server - creates all permission types.
  """
  @spec create_comprehensive_permissions(String.t()) :: :ok
  def create_comprehensive_permissions(server_name) do
    comprehensive_permissions = [
      # Tools permissions
      %{
        resource_type: :tools,
        server_name: server_name,
        resource_pattern: "*",
        action: :list,
        description: "List all tools"
      },
      %{
        resource_type: :tools,
        server_name: server_name,
        resource_pattern: "*",
        action: :call,
        description: "Call any tool"
      },
      # Resources permissions
      %{
        resource_type: :resources,
        server_name: server_name,
        resource_pattern: "*",
        action: :list,
        description: "List all resources"
      },
      %{
        resource_type: :resources,
        server_name: server_name,
        resource_pattern: "*",
        action: :read,
        description: "Read any resource"
      },
      # Prompts permissions
      %{
        resource_type: :prompts,
        server_name: server_name,
        resource_pattern: "*",
        action: :list,
        description: "List all prompts"
      },
      %{
        resource_type: :prompts,
        server_name: server_name,
        resource_pattern: "*",
        action: :read,
        description: "Read any prompt"
      }
    ]

    Enum.each(comprehensive_permissions, &create_permission/1)
  end

  @doc """
  Creates basic client-access permissions for a server.

  Used when granting client access - creates minimal required permissions.
  """
  @spec create_client_permissions(String.t()) :: :ok
  def create_client_permissions(server_name) do
    client_permissions = [
      %{
        resource_type: :tools,
        server_name: server_name,
        resource_pattern: "*",
        action: :call,
        description: "Call any tool"
      },
      %{
        resource_type: :resources,
        server_name: server_name,
        resource_pattern: "*",
        action: :read,
        description: "Read any resource"
      },
      %{
        resource_type: :prompts,
        server_name: server_name,
        resource_pattern: "*",
        action: :read,
        description: "Read any prompt"
      }
    ]

    Enum.each(client_permissions, &create_permission/1)
  end

  # Private helper
  defp create_permission(permission_params) do
    Aegis.MCP.create_permission(permission_params)
  end
end
