defmodule Aegis.MCP.InputValidatorTest do
  use ExUnit.Case, async: true

  alias Aegis.MCP.InputValidator

  describe "validate_tool_call/1" do
    test "accepts valid tool call with name only" do
      params = %{"params" => %{"name" => "test_tool"}}
      assert :ok = InputValidator.validate_tool_call(params)
    end

    test "accepts valid tool call with arguments" do
      params = %{
        "params" => %{
          "name" => "test_tool",
          "arguments" => %{"arg1" => "value1", "arg2" => 42}
        }
      }

      assert :ok = InputValidator.validate_tool_call(params)
    end

    test "rejects missing params" do
      assert {:error, "Missing 'params' object"} = InputValidator.validate_tool_call(%{})
    end

    test "rejects missing name field" do
      params = %{"params" => %{}}

      assert {:error, "Missing required field: 'name'"} =
               InputValidator.validate_tool_call(params)
    end

    test "rejects non-string name" do
      params = %{"params" => %{"name" => 123}}

      assert {:error, "Field 'name' must be a string, got: number"} =
               InputValidator.validate_tool_call(params)
    end

    test "rejects name exceeding max length" do
      long_name = String.duplicate("a", 10_001)
      params = %{"params" => %{"name" => long_name}}

      assert {:error, error_msg} = InputValidator.validate_tool_call(params)
      assert error_msg =~ "exceeds maximum length"
    end

    test "rejects non-map arguments" do
      params = %{"params" => %{"name" => "tool", "arguments" => "invalid"}}

      assert {:error, "Field 'arguments' must be an object/map"} =
               InputValidator.validate_tool_call(params)
    end

    test "rejects too many arguments" do
      # Create 101 arguments
      arguments = Map.new(1..101, fn i -> {"arg#{i}", i} end)
      params = %{"params" => %{"name" => "tool", "arguments" => arguments}}

      assert {:error, error_msg} = InputValidator.validate_tool_call(params)
      assert error_msg =~ "Too many arguments"
    end

    test "rejects deeply nested arguments" do
      # Create 11 levels of nesting
      deeply_nested =
        Enum.reduce(1..11, %{}, fn _i, acc ->
          %{"nested" => acc}
        end)

      params = %{"params" => %{"name" => "tool", "arguments" => deeply_nested}}

      assert {:error, error_msg} = InputValidator.validate_tool_call(params)
      assert error_msg =~ "nested too deeply"
    end

    test "rejects oversized arguments payload" do
      # Create a payload larger than 100KB
      large_value = String.duplicate("x", 101_000)
      params = %{"params" => %{"name" => "tool", "arguments" => %{"data" => large_value}}}

      assert {:error, error_msg} = InputValidator.validate_tool_call(params)
      assert error_msg =~ "payload too large"
    end
  end

  describe "validate_resource_read/1" do
    test "accepts valid resource read" do
      params = %{"params" => %{"uri" => "server://path/to/resource"}}
      assert :ok = InputValidator.validate_resource_read(params)
    end

    test "rejects missing params" do
      assert {:error, "Missing 'params' object"} = InputValidator.validate_resource_read(%{})
    end

    test "rejects missing uri field" do
      params = %{"params" => %{}}

      assert {:error, "Missing required field: 'uri'"} =
               InputValidator.validate_resource_read(params)
    end

    test "rejects non-string uri" do
      params = %{"params" => %{"uri" => 123}}

      assert {:error, "Field 'uri' must be a string, got: number"} =
               InputValidator.validate_resource_read(params)
    end

    test "rejects uri exceeding max length" do
      long_uri = "server://" <> String.duplicate("a", 2000)
      params = %{"params" => %{"uri" => long_uri}}

      assert {:error, error_msg} = InputValidator.validate_resource_read(params)
      assert error_msg =~ "exceeds maximum length"
    end

    test "rejects empty or whitespace uri" do
      params = %{"params" => %{"uri" => "   "}}

      assert {:error, "URI cannot be empty or whitespace only"} =
               InputValidator.validate_resource_read(params)
    end

    test "rejects uri with control characters" do
      params = %{"params" => %{"uri" => "server://path\nwith\nnewlines"}}

      assert {:error, "URI contains invalid control characters"} =
               InputValidator.validate_resource_read(params)
    end
  end

  describe "validate_prompt_get/1" do
    test "accepts valid prompt get with name only" do
      params = %{"params" => %{"name" => "test_prompt"}}
      assert :ok = InputValidator.validate_prompt_get(params)
    end

    test "accepts valid prompt get with string arguments" do
      params = %{
        "params" => %{
          "name" => "test_prompt",
          "arguments" => %{"arg1" => "value1", "arg2" => "value2"}
        }
      }

      assert :ok = InputValidator.validate_prompt_get(params)
    end

    test "rejects missing params" do
      assert {:error, "Missing 'params' object"} = InputValidator.validate_prompt_get(%{})
    end

    test "rejects missing name field" do
      params = %{"params" => %{}}

      assert {:error, "Missing required field: 'name'"} =
               InputValidator.validate_prompt_get(params)
    end

    test "rejects non-string name" do
      params = %{"params" => %{"name" => 123}}

      assert {:error, "Field 'name' must be a string, got: number"} =
               InputValidator.validate_prompt_get(params)
    end

    test "rejects non-string argument values" do
      params = %{
        "params" => %{
          "name" => "prompt",
          "arguments" => %{"arg1" => "valid", "arg2" => 123}
        }
      }

      assert {:error, error_msg} = InputValidator.validate_prompt_get(params)
      assert error_msg =~ "Prompt arguments must be strings"
      assert error_msg =~ "arg2"
    end

    test "rejects non-map arguments" do
      params = %{"params" => %{"name" => "prompt", "arguments" => "invalid"}}

      assert {:error, "Field 'arguments' must be an object/map"} =
               InputValidator.validate_prompt_get(params)
    end

    test "rejects too many arguments" do
      # Create 101 arguments
      arguments = Map.new(1..101, fn i -> {"arg#{i}", "value#{i}"} end)
      params = %{"params" => %{"name" => "prompt", "arguments" => arguments}}

      assert {:error, error_msg} = InputValidator.validate_prompt_get(params)
      assert error_msg =~ "Too many arguments"
    end

    test "rejects oversized arguments payload" do
      # Create a payload larger than 100KB
      large_value = String.duplicate("x", 101_000)
      params = %{"params" => %{"name" => "prompt", "arguments" => %{"data" => large_value}}}

      assert {:error, error_msg} = InputValidator.validate_prompt_get(params)
      assert error_msg =~ "payload too large"
    end
  end
end
