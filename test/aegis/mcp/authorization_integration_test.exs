defmodule Aegis.MCP.AuthorizationIntegrationTest do
  use Aegis.DataCase, async: true
  alias Aegis.MCP.Authorization

  describe "full RBAC flow" do
    test "client with tool permission can call tool" do
      # Create a test client using the register action
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Test Client",
          description: "Test client for RBAC"
        })

      # Create a permission for calling tools
      {:ok, permission} =
        Aegis.MCP.create_permission(%{
          resource_type: :tools,
          server_name: "test-server",
          resource_pattern: "test-tool",
          action: :call
        })

      # Link client to permission
      {:ok, _client_permission} = Aegis.MCP.grant_permission(client.id, permission.id)

      # Test authorization
      result = Authorization.can_call_tool?(client.id, "test-server", "test-tool")
      assert {:ok, :authorized} = result
    end

    test "client without permission cannot call tool" do
      # Create a test client without any permissions
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Limited Client",
          description: "Client without permissions"
        })

      # Test authorization fails
      result = Authorization.can_call_tool?(client.id, "test-server", "test-tool")
      assert {:error, :permission_denied} = result
    end

    test "inactive client cannot access resources" do
      # Create an inactive client
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Inactive Client",
          description: "Inactive client"
        })

      # Make the client inactive
      {:ok, client} = Aegis.MCP.update_client(client, %{active: false})

      # Create a permission
      {:ok, permission} =
        Aegis.MCP.create_permission(%{
          resource_type: :resources,
          server_name: "*",
          resource_pattern: "*",
          action: :read
        })

      # Link client to permission
      {:ok, _client_permission} = Aegis.MCP.grant_permission(client.id, permission.id)

      # Test authorization fails due to inactive status
      result = Authorization.can_read_resource?(client.id, "any-server", "any-resource")
      assert {:error, :client_inactive} = result
    end

    test "wildcard permissions work correctly" do
      # Create a test client
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Admin Client",
          description: "Client with wildcard permissions"
        })

      # Create wildcard permissions
      {:ok, tool_permission} =
        Aegis.MCP.create_permission(%{
          resource_type: :tools,
          server_name: "*",
          resource_pattern: "*",
          action: :call
        })

      {:ok, resource_permission} =
        Aegis.MCP.create_permission(%{
          resource_type: :resources,
          server_name: "*",
          resource_pattern: "*",
          action: :read
        })

      # Link client to permissions
      {:ok, _cp1} =
        Aegis.MCP.grant_permission(
          client.id,
          tool_permission.id
        )

      {:ok, _cp2} =
        Aegis.MCP.grant_permission(
          client.id,
          resource_permission.id
        )

      # Test wildcard permissions work
      assert {:ok, :authorized} =
               Authorization.can_call_tool?(client.id, "any-server", "any-tool")

      assert {:ok, :authorized} =
               Authorization.can_read_resource?(client.id, "any-server", "any-resource")
    end

    test "specific permissions override wildcards" do
      # Create a test client
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Specific Client",
          description: "Client with specific permissions"
        })

      # Create specific server permission
      {:ok, permission} =
        Aegis.MCP.create_permission(%{
          resource_type: :tools,
          server_name: "allowed-server",
          resource_pattern: "specific-tool",
          action: :call
        })

      # Link client to permission
      {:ok, _client_permission} =
        Aegis.MCP.grant_permission(client.id, permission.id)

      # Test specific permission works
      assert {:ok, :authorized} =
               Authorization.can_call_tool?(client.id, "allowed-server", "specific-tool")

      # Test other combinations fail
      assert {:error, :permission_denied} =
               Authorization.can_call_tool?(client.id, "other-server", "specific-tool")

      assert {:error, :permission_denied} =
               Authorization.can_call_tool?(client.id, "allowed-server", "other-tool")
    end

    test "get_client_permissions returns all permissions" do
      # Create a test client
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Permission List Client",
          description: "Client for testing permission listing"
        })

      # Create multiple permissions
      {:ok, perm1} =
        Aegis.MCP.create_permission(%{
          resource_type: :tools,
          server_name: "server1",
          resource_pattern: "tool1",
          action: :call
        })

      {:ok, perm2} =
        Aegis.MCP.create_permission(%{
          resource_type: :resources,
          server_name: "*",
          resource_pattern: "*",
          action: :read
        })

      # Link client to permissions
      {:ok, _cp1} =
        Aegis.MCP.grant_permission(
          client.id,
          perm1.id
        )

      {:ok, _cp2} =
        Aegis.MCP.grant_permission(
          client.id,
          perm2.id
        )

      # Get permissions
      {:ok, permissions} = Authorization.get_client_permissions(client.id)

      assert length(permissions) == 2

      # Check that both permissions are present
      assert Enum.any?(permissions, fn p ->
               p.resource_type == :tools and p.server_name == "server1" and
                 p.resource_pattern == "tool1" and p.action == :call
             end)

      assert Enum.any?(permissions, fn p ->
               p.resource_type == :resources and p.server_name == "*" and
                 p.resource_pattern == "*" and p.action == :read
             end)
    end
  end
end
