defmodule Aegis.MCP.ErrorResponseTest do
  use ExUnit.Case, async: true

  alias Aegis.MCP.ErrorResponse

  describe "build_error/2" do
    test "builds standard JSON-RPC error response" do
      assert {:error, response} = ErrorResponse.build_error(-32_601, "Method not found")

      assert response.jsonrpc == "2.0"
      assert response.error.code == -32_601
      assert response.error.message == "Method not found"
      refute Map.has_key?(response, :id)
    end
  end

  describe "build_error_with_id/3" do
    test "builds error response with ID" do
      assert {:error, response} =
               ErrorResponse.build_error_with_id(-32_602, "Invalid params", 123)

      assert response.jsonrpc == "2.0"
      assert response.error.code == -32_602
      assert response.error.message == "Invalid params"
      assert response.id == 123
    end

    test "builds error response without ID when nil" do
      assert {:error, response} =
               ErrorResponse.build_error_with_id(-32_602, "Invalid params", nil)

      assert response.jsonrpc == "2.0"
      assert response.error.code == -32_602
      assert response.error.message == "Invalid params"
      refute Map.has_key?(response, :id)
    end
  end

  describe "error code constants" do
    test "parse_error returns correct code" do
      assert ErrorResponse.parse_error() == -32_700
    end

    test "invalid_request returns correct code" do
      assert ErrorResponse.invalid_request() == -32_600
    end

    test "method_not_found returns correct code" do
      assert ErrorResponse.method_not_found() == -32_601
    end

    test "invalid_params returns correct code" do
      assert ErrorResponse.invalid_params() == -32_602
    end

    test "internal_error returns correct code" do
      assert ErrorResponse.internal_error() == -32_603
    end

    test "server_error returns correct code" do
      assert ErrorResponse.server_error() == -32_000
    end
  end
end
