defmodule Aegis.MCP.SSEFormatter do
  @moduledoc """
  Server-Sent Events formatting utilities for MCP streams.

  Provides consistent formatting for SSE messages including
  event types, data encoding, and event ID management.
  """

  alias Aegis.MCP.Constants

  @type event_data :: map() | String.t()
  @type event_id :: integer() | nil
  @type sse_message :: String.t()

  @doc """
  Format a complete SSE message with event type, data, and optional ID.

  ## Examples

      iex> format_message("notification", %{test: "data"}, 1)
      "id: 1\\nevent: notification\\ndata: {\\"test\\":\\"data\\"}\\n\\n"
  """
  @spec format_message(String.t(), event_data(), event_id()) :: sse_message()
  def format_message(event_type, data, event_id \\ nil) do
    json_data = encode_data(data)
    id_line = if event_id, do: "id: #{event_id}\n", else: ""

    """
    #{id_line}event: #{event_type}
    data: #{json_data}

    """
  end

  @doc """
  Format a connected notification for new SSE streams.
  """
  @spec format_connected(String.t(), event_id()) :: sse_message()
  def format_connected(session_id, event_id) do
    data = %{
      jsonrpc: "2.0",
      method: Constants.connected_method(),
      params: %{
        sessionId: session_id,
        serverInfo: Constants.server_info()
      }
    }

    format_message(Constants.sse_connected_event(), data, event_id)
  end

  @doc """
  Format a heartbeat message to keep connections alive.
  """
  @spec format_heartbeat(String.t(), event_id()) :: sse_message()
  def format_heartbeat(session_id, event_id) do
    data = %{
      jsonrpc: "2.0",
      method: Constants.heartbeat_method(),
      params: %{
        timestamp: DateTime.utc_now(),
        sessionId: session_id
      }
    }

    format_message(Constants.sse_heartbeat_event(), data, event_id)
  end

  @doc """
  Format a list change notification.
  """
  @spec format_list_change(map(), event_id()) :: sse_message()
  def format_list_change(change, event_id) do
    data =
      case Map.get(change, :params) do
        nil ->
          %{
            jsonrpc: "2.0",
            method: change.method
          }

        params ->
          %{
            jsonrpc: "2.0",
            method: change.method,
            params: params
          }
      end

    format_message(Constants.sse_notification_event(), data, event_id)
  end

  @doc """
  Format a session-specific message.
  """
  @spec format_session_message(map(), event_id()) :: sse_message()
  def format_session_message(message, event_id) do
    format_message(Constants.sse_session_event(), message, event_id)
  end

  @doc """
  Format a response message for SSE responses.
  """
  @spec format_response(map(), event_id()) :: sse_message()
  def format_response(response, event_id \\ nil) do
    format_message(Constants.sse_response_event(), response, event_id)
  end

  @doc """
  Set SSE response headers on a Plug connection.
  """
  @spec set_sse_headers(Plug.Conn.t()) :: Plug.Conn.t()
  def set_sse_headers(conn) do
    import Plug.Conn

    conn
    |> put_resp_header("content-type", Constants.sse_content_type())
    |> put_resp_header("cache-control", Constants.sse_cache_control())
    |> put_resp_header("connection", Constants.sse_connection_type())
  end

  @doc """
  Send an SSE message chunk and handle connection errors.

  Returns {:ok, conn} on success or {:error, :closed} if connection is closed.
  """
  @spec send_chunk(Plug.Conn.t(), sse_message()) :: {:ok, Plug.Conn.t()} | {:error, :closed}
  def send_chunk(conn, message) do
    case Plug.Conn.chunk(conn, message) do
      {:ok, conn} -> {:ok, conn}
      {:error, :closed} -> {:error, :closed}
    end
  end

  @doc """
  Parse an SSE event from raw data.

  Used for parsing SSE events received from backend servers.
  """
  @spec parse_sse_event(String.t()) :: {:ok, map() | :ignore} | {:error, any()}
  def parse_sse_event(data) do
    lines = String.split(data, "\n")

    event_data =
      lines
      |> Enum.reduce(%{}, fn line, acc ->
        case String.split(line, ": ", parts: 2) do
          ["event", event_type] -> Map.put(acc, :event, event_type)
          ["data", event_data] -> Map.put(acc, :data, event_data)
          _ -> acc
        end
      end)

    case event_data do
      %{event: "notification", data: json_data} ->
        case Jason.decode(json_data) do
          {:ok, parsed} -> {:ok, parsed}
          {:error, _} = error -> error
        end

      _ ->
        {:ok, :ignore}
    end
  rescue
    exception ->
      {:error, exception}
  end

  # Private functions

  defp encode_data(data) when is_binary(data), do: data
  defp encode_data(data), do: Jason.encode!(data)
end
