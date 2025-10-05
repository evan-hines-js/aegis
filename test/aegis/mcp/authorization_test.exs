defmodule Aegis.MCP.AuthorizationTest do
  use Aegis.DataCase, async: false
  alias Aegis.MCP.Authorization

  describe "can_call_tool?/3" do
    test "returns system error for invalid UUID format" do
      # Invalid UUID format should return system_error
      result = Authorization.can_call_tool?("test-client", "test-server", "test-tool")
      assert {:error, :system_error} = result
    end

    test "returns client_not_found for valid UUID format but non-existent client" do
      # Valid UUID format but non-existent client should return client_not_found
      non_existent_uuid = Ash.UUIDv7.generate()
      result = Authorization.can_call_tool?(non_existent_uuid, "test-server", "test-tool")
      assert {:error, :client_not_found} = result
    end
  end

  describe "can_read_resource?/3" do
    test "returns system error for invalid UUID format" do
      result = Authorization.can_read_resource?("non-existent", "server", "resource")
      assert {:error, :system_error} = result
    end
  end

  describe "can_get_prompt?/3" do
    test "returns system error for invalid UUID format" do
      result = Authorization.can_get_prompt?("invalid-client", "server", "prompt")
      assert {:error, :system_error} = result
    end
  end

  describe "can_list?/3" do
    test "returns system error for invalid UUID format" do
      result = Authorization.can_list?("client", :tools, "server")
      assert {:error, :system_error} = result
    end

    test "rejects invalid resource types" do
      result = Authorization.can_list?("client", :invalid_type, "server")
      assert {:error, :invalid_resource_type} = result
    end
  end

  describe "validate_client/1" do
    test "returns system error for invalid UUID format" do
      result = Authorization.validate_client("non-existent-client")
      assert {:error, :system_error} = result
    end

    test "returns client_not_found for valid UUID format but non-existent client" do
      non_existent_uuid = Ash.UUIDv7.generate()
      result = Authorization.validate_client(non_existent_uuid)
      assert {:error, :client_not_found} = result
    end
  end

  describe "get_client_permissions/1" do
    test "returns error for non-existent client" do
      result = Authorization.get_client_permissions("non-existent-client")
      assert match?({:error, _}, result)
    end
  end
end
