defmodule Aegis.MCP.Handlers.LoggingHandler do
  @moduledoc """
  Handler for MCP logging/* method calls.

  Handles log level configuration and manages per-session logging preferences.
  """

  require Logger

  alias Aegis.MCP.{
    ErrorResponse,
    RequestHelpers
  }

  @valid_log_levels ~w(debug info notice warning error critical alert emergency)

  @doc """
  Handle logging/setLevel request.

  Sets the minimum log level for the session.
  """
  @spec handle_set_level(String.t(), map()) :: {:ok, map(), atom()} | {:error, map()}
  def handle_set_level(_session_id, %{"params" => %{"level" => level}} = params)
      when level in @valid_log_levels do
    # Logging configuration is a basic capability, allow for all authenticated clients
    # Return the level as an atom so the Session can update its state
    level_atom = String.to_existing_atom(level)

    response = %{
      jsonrpc: "2.0",
      result: %{}
    }

    response = RequestHelpers.add_request_id_if_present(response, params)
    {:ok, response, level_atom}
  end

  def handle_set_level(_session_id, %{"params" => %{"level" => level}} = _params) do
    ErrorResponse.build_error(
      ErrorResponse.invalid_params(),
      "Invalid log level: #{level}. Valid levels: #{Enum.join(@valid_log_levels, ", ")}"
    )
  end

  def handle_set_level(_session_id, _params) do
    ErrorResponse.build_error(
      ErrorResponse.invalid_params(),
      "Invalid parameters. Expected: level"
    )
  end

  @doc """
  Get valid log levels for this implementation.
  """
  @spec valid_log_levels() :: [String.t()]
  def valid_log_levels, do: @valid_log_levels

  @doc """
  Check if a log level should be forwarded to a session based on its configured level.
  """
  @spec should_forward_log?(atom(), String.t()) :: boolean()
  def should_forward_log?(session_log_level, message_level) do
    log_level_priority(message_level) >= log_level_priority(Atom.to_string(session_log_level))
  end

  # Private helper functions

  # Convert log levels to numeric priorities for comparison
  # Higher numbers = more severe
  defp log_level_priority("debug"), do: 0
  defp log_level_priority("info"), do: 1
  defp log_level_priority("notice"), do: 2
  defp log_level_priority("warning"), do: 3
  defp log_level_priority("error"), do: 4
  defp log_level_priority("critical"), do: 5
  defp log_level_priority("alert"), do: 6
  defp log_level_priority("emergency"), do: 7
  # Default to info level
  defp log_level_priority(_), do: 1
end
