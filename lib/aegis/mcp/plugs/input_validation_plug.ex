defmodule Aegis.MCP.Plugs.InputValidationPlug do
  @moduledoc """
  Plug for validating MCP request inputs early in the request pipeline.

  This plug validates incoming JSON-RPC requests against MCP specification
  requirements before they reach the handlers. It provides centralized
  validation and early error responses for invalid requests.
  """

  import Plug.Conn

  alias Aegis.MCP.{ErrorResponse, InputValidator}

  @doc """
  Initialize the plug with options.
  """
  def init(opts), do: opts

  @doc """
  Validate MCP request based on the method.

  Performs input validation for supported MCP methods:
  - tools/call
  - resources/read
  - prompts/get

  If validation fails, halts the connection and returns an error response.
  """
  def call(%{assigns: %{mcp_params: params}} = conn, _opts) do
    method = get_in(params, ["method"])

    case validate_by_method(method, params) do
      :ok ->
        conn

      {:error, reason} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(
          400,
          Jason.encode!(
            ErrorResponse.build_error(
              ErrorResponse.invalid_params(),
              "Input validation failed: #{reason}"
            )
          )
        )
        |> halt()
    end
  end

  def call(conn, _opts), do: conn

  # Private validation dispatcher

  defp validate_by_method("tools/call", params) do
    InputValidator.validate_tool_call(params)
  end

  defp validate_by_method("resources/read", params) do
    InputValidator.validate_resource_read(params)
  end

  defp validate_by_method("prompts/get", params) do
    InputValidator.validate_prompt_get(params)
  end

  # Don't validate methods we don't have validators for yet
  defp validate_by_method(_method, _params), do: :ok
end
