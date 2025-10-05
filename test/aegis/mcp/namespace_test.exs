defmodule Aegis.MCP.NamespaceTest do
  use ExUnit.Case, async: true

  alias Aegis.MCP.Namespace

  describe "namespace_tool/2" do
    test "adds server name prefix to tool name" do
      tool = %{"name" => "list_files"}
      result = Namespace.namespace_tool(tool, "myserver")

      assert result["name"] == "myserver__list_files"
    end
  end

  describe "namespace_resource/2" do
    test "adds server query parameter to resource URI" do
      resource = %{"uri" => "file:///path/to/file"}
      result = Namespace.namespace_resource(resource, "myserver")

      assert result["uri"] == "file:///path/to/file?server=myserver"
    end
  end

  describe "namespace_resource_template/2" do
    test "adds server query parameter to resource template URI" do
      template = %{"uriTemplate" => "file:///{path}"}
      result = Namespace.namespace_resource_template(template, "myserver")

      assert result["uriTemplate"] == "file:///{path}?server=myserver"
    end
  end

  describe "namespace_prompt/2" do
    test "adds server name prefix to prompt name" do
      prompt = %{"name" => "git_commit"}
      result = Namespace.namespace_prompt(prompt, "myserver")

      assert result["name"] == "myserver__git_commit"
    end
  end

  describe "parse_namespaced_tool/1" do
    test "parses valid namespaced tool name" do
      assert {:ok, "myserver", "list_files"} =
               Namespace.parse_namespaced_tool("myserver__list_files")
    end

    test "returns error for invalid format" do
      assert {:error, :invalid_format} =
               Namespace.parse_namespaced_tool("invalid_format")

      assert {:error, :invalid_format} =
               Namespace.parse_namespaced_tool("__only_separator")

      assert {:error, :invalid_format} =
               Namespace.parse_namespaced_tool("server__")
    end
  end

  describe "parse_namespaced_uri/1" do
    test "parses valid namespaced URI with query parameter" do
      assert {:ok, "myserver", "file:///path/to/file"} =
               Namespace.parse_namespaced_uri("file:///path/to/file?server=myserver")
    end

    test "parses URI with existing query parameters" do
      assert {:ok, "myserver", "file:///path/to/file?existing=param"} =
               Namespace.parse_namespaced_uri(
                 "file:///path/to/file?existing=param&server=myserver"
               )
    end

    test "returns error for invalid format" do
      assert {:error, :invalid_format} =
               Namespace.parse_namespaced_uri("invalid_format")

      assert {:error, :invalid_format} =
               Namespace.parse_namespaced_uri("file:///path/to/file")

      assert {:error, :invalid_format} =
               Namespace.parse_namespaced_uri("file:///path/to/file?other=param")
    end
  end

  describe "find_server_by_name/1" do
    setup do
      # Ensure the ETS table exists for testing
      case :ets.whereis(:server_registry) do
        :undefined -> :ets.new(:server_registry, [:set, :public, :named_table])
        _ -> :ok
      end

      # Clean up any existing data
      :ets.delete_all_objects(:server_registry)
      :ok
    end

    test "finds existing server" do
      server_info = %{
        endpoint: "http://localhost:3000",
        status: :healthy,
        capabilities: %{},
        last_check: DateTime.utc_now(),
        failure_count: 0,
        auth_type: :none
      }

      cache_key = {:server, "test_server"}

      Aegis.Cache.put(:mcp_meta_cache, cache_key, server_info,
        tags: ["server:test_server", "servers"]
      )

      assert {:ok, result} = Namespace.find_server_by_name("test_server")
      assert result.name == "test_server"
      assert result.endpoint == "http://localhost:3000"
    end

    test "returns not found for non-existent server" do
      assert {:error, :not_found} = Namespace.find_server_by_name("nonexistent")
    end
  end
end
