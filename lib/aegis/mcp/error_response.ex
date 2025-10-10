defmodule Aegis.MCP.ErrorResponse do
  @moduledoc """
  Utilities for building consistent JSON-RPC error responses.

  Centralizes error response formatting to ensure consistency across
  the MCP implementation.
  """

  @type error_code :: integer()
  @type error_message :: String.t()
  @type json_rpc_response :: map()

  # JSON-RPC 2.0 Standard Error Codes
  @parse_error -32_700
  @invalid_request -32_600
  @method_not_found -32_601
  @invalid_params -32_602
  @internal_error -32_603
  @server_error -32_000

  @doc """
  Build a JSON-RPC 2.0 error response.

  ## Examples

      iex> build_error(-32_601, "Method not found")
      {:error, %{
        jsonrpc: "2.0",
        error: %{
          code: -32_601,
          message: "Method not found"
        }
      }}

      iex> build_error(-32_601, "Method not found", 1)
      {:error, %{
        jsonrpc: "2.0",
        id: 1,
        error: %{
          code: -32_601,
          message: "Method not found"
        }
      }}
  """
  @spec build_error(error_code(), error_message(), any()) :: {:error, json_rpc_response()}
  def build_error(code, message, id \\ nil) do
    error_response = %{
      jsonrpc: "2.0",
      error: %{
        code: code,
        message: message
      }
    }

    response = if id, do: Map.put(error_response, :id, id), else: error_response
    {:error, response}
  end

  @doc """
  Build a JSON-RPC 2.0 error response with optional ID field.

  Deprecated: Use build_error/3 instead.
  """
  @spec build_error_with_id(error_code(), error_message(), any()) :: {:error, json_rpc_response()}
  def build_error_with_id(code, message, id) do
    build_error(code, message, id)
  end

  @doc """
  Build a JSON-RPC 2.0 error response for Plug/Phoenix controllers.

  Returns a tuple suitable for Phoenix controller error handling.
  """
  @spec build_controller_error(Plug.Conn.t(), atom(), error_code(), error_message()) ::
          {:error, Plug.Conn.t()}
  def build_controller_error(conn, status, code, message) do
    import Plug.Conn
    import Phoenix.Controller

    response =
      conn
      |> put_status(status)
      |> json(%{
        jsonrpc: "2.0",
        error: %{
          code: code,
          message: message
        }
      })

    {:error, response}
  end

  # Common JSON-RPC error codes
  @doc "Parse error - Invalid JSON was received by the server"
  def parse_error, do: @parse_error

  @doc "Invalid Request - The JSON sent is not a valid Request object"
  def invalid_request, do: @invalid_request

  @doc "Method not found - The method does not exist / is not available"
  def method_not_found, do: @method_not_found

  @doc "Invalid params - Invalid method parameter(s)"
  def invalid_params, do: @invalid_params

  @doc "Internal error - Internal JSON-RPC error"
  def internal_error, do: @internal_error

  @doc "Server error - Reserved for implementation-defined server-errors"
  def server_error, do: @server_error

  @doc """
  Build a JSON-RPC error response from an error map.

  Used for lifecycle and validation errors that include data.
  """
  @spec build_json_rpc_error(map()) :: json_rpc_response()
  def build_json_rpc_error(%{code: code, message: message} = error) do
    error_response = %{
      code: code,
      message: message
    }

    error_response =
      if Map.has_key?(error, :data) do
        Map.put(error_response, :data, error.data)
      else
        error_response
      end

    %{
      jsonrpc: "2.0",
      error: error_response
    }
  end
end
