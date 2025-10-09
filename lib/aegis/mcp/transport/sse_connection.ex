defmodule Aegis.MCP.SSEConnection do
  @moduledoc """
  Manages SSE connections to backend MCP servers for real-time notifications.

  Handles connection establishment, event parsing, and automatic reconnection
  for servers that support listChanged notifications via SSE.

  Includes session management to properly authenticate with MCP servers.
  """

  require Logger
  alias Aegis.MCP.{Constants, ServerClient, SSEFormatter}

  @type server :: %{name: String.t(), endpoint: String.t()}

  @doc """
  Start an SSE connection to a server in a separate process.

  Returns {:ok, pid} on success or {:error, reason} on failure.
  """
  @spec start_connection(server(), pid()) :: {:ok, pid()} | {:error, any()}
  def start_connection(server, parent) do
    pid =
      spawn_link(fn ->
        connection_loop(server, parent)
      end)

    {:ok, pid}
  rescue
    error -> {:error, error}
  end

  @doc """
  Main connection loop that handles reconnection logic.
  """
  @spec connection_loop(server(), pid()) :: no_return()
  def connection_loop(server, parent) do
    Logger.info("Starting SSE connection to #{server.name}")

    case initialize_session(server) do
      {:ok, session_id} ->
        Logger.info("Session initialized for #{server.name}: #{session_id}")

        case establish_connection(server, session_id) do
          {:ok, stream} ->
            Logger.info("SSE connection established to #{server.name}")
            handle_events(stream, server, parent, session_id)

          {:error, reason} ->
            Logger.warning(
              "Failed to establish SSE connection to #{server.name}: #{inspect(reason)}"
            )

            Process.sleep(Constants.sse_reconnect_delay())
            connection_loop(server, parent)
        end

      {:error, reason} ->
        Logger.warning("Failed to initialize session for #{server.name}: #{inspect(reason)}")
        Process.sleep(Constants.sse_reconnect_delay())
        connection_loop(server, parent)
    end
  end

  @doc """
  Handle incoming SSE events from a server connection.
  """
  @spec handle_events(any(), server(), pid(), String.t()) :: no_return()
  def handle_events(stream, server, parent, session_id) do
    receive do
      {:http, _request_ref, :stream_start, _headers} ->
        Logger.debug("SSE stream started for #{server.name}")
        handle_events(stream, server, parent, session_id)

      {:http, _request_ref, {:stream, data}} ->
        case SSEFormatter.parse_sse_event(data) do
          {:ok, event} ->
            handle_event(event, server, parent)

          {:error, reason} ->
            Logger.debug("Failed to parse SSE event from #{server.name}: #{inspect(reason)}")
        end

        handle_events(stream, server, parent, session_id)

      {:http, _request_ref, :stream_end} ->
        Logger.info("SSE stream ended for #{server.name}, reconnecting...")
        Process.sleep(1_000)
        connection_loop(server, parent)

      {:http, _request_ref, {:error, reason}} ->
        Logger.warning("SSE connection error for #{server.name}: #{inspect(reason)}")
        Process.sleep(Constants.sse_reconnect_delay())
        connection_loop(server, parent)
    after
      Constants.sse_heartbeat_timeout() ->
        Logger.warning("SSE heartbeat timeout for #{server.name}, reconnecting...")
        connection_loop(server, parent)
    end
  end

  @doc """
  Update SSE connections based on current server health and capabilities.

  Closes connections for unhealthy servers and starts new connections
  for servers that support SSE but don't have active connections.
  """
  @spec update_connections(map(), [server()]) :: map()
  def update_connections(state, sse_servers) do
    current_sse_server_names = MapSet.new(sse_servers, & &1.name)

    # Remove connections for servers that no longer support SSE or are unhealthy
    connections_to_remove =
      state.sse_connections
      |> Map.keys()
      |> Enum.reject(&MapSet.member?(current_sse_server_names, &1))

    # Close old connections
    Enum.each(connections_to_remove, fn server_name ->
      case Map.get(state.sse_connections, server_name) do
        nil ->
          :ok

        pid when is_pid(pid) ->
          Logger.info("Closing SSE connection to #{server_name}")
          Process.exit(pid, :shutdown)
      end
    end)

    # Start new connections for servers that support SSE but don't have connections
    new_connections =
      sse_servers
      |> Enum.reject(fn server -> Map.has_key?(state.sse_connections, server.name) end)
      |> Enum.reduce(state.sse_connections, fn server, acc ->
        case start_connection(server, self()) do
          {:ok, pid} ->
            Logger.info("Started SSE connection to #{server.name}")
            Map.put(acc, server.name, pid)

          {:error, reason} ->
            Logger.warning("Failed to start SSE connection to #{server.name}: #{inspect(reason)}")
            acc
        end
      end)

    # Remove old connections from map
    final_connections = Map.drop(new_connections, connections_to_remove)

    %{
      state
      | sse_servers: current_sse_server_names,
        sse_connections: final_connections
    }
  end

  # Private functions

  # Initialize an MCP session with the server before establishing SSE connection.
  defp initialize_session(server) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: %{
        protocolVersion: Constants.default_protocol_version(),
        capabilities: %{},
        clientInfo: %{
          name: "Aegis MCP Hub",
          version: "1.0.0"
        }
      }
    }

    case ServerClient.make_request(server, request_body) do
      {:ok, %{"result" => _result}, headers} ->
        extract_session_id_from_headers(headers)

      {:ok, _response, _headers} ->
        {:error, "Invalid response format from initialize"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp extract_session_id_from_headers(headers) do
    case Enum.find(headers, fn {key, _value} -> String.downcase(key) == "mcp-session-id" end) do
      {_key, session_id} -> {:ok, session_id}
      nil -> {:error, "No session ID returned from initialize"}
    end
  end

  defp establish_connection(server, session_id) do
    # Build authentication headers using the same logic as ServerClient
    auth_headers = build_auth_headers(server)

    base_headers = [
      {"accept", Constants.sse_content_type()},
      {"cache-control", Constants.sse_cache_control()},
      {"mcp-session-id", session_id}
    ]

    all_headers = base_headers ++ auth_headers

    case Req.get(server.endpoint,
           headers: all_headers,
           receive_timeout: :infinity,
           into: :self
         ) do
      {:ok, %Req.Response{status: 200} = response} ->
        {:ok, response}

      {:ok, %Req.Response{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    exception ->
      {:error, exception}
  end

  # Build authentication headers based on server auth type
  defp build_auth_headers(server) do
    case Map.get(server, :auth_type, :none) do
      :api_key ->
        case Map.get(server, :api_key) do
          nil -> []
          "" -> []
          api_key -> [{"authorization", "Bearer #{api_key}"}]
        end

      _ ->
        # :none or any other type - no authentication headers
        []
    end
  end

  defp handle_event(:ignore, _server, _parent), do: :ok

  defp handle_event(event, server, parent) do
    case event do
      %{"method" => method}
      when method in [
             "notifications/tools/list_changed",
             "notifications/resources/list_changed",
             "notifications/resources/updated",
             "notifications/prompts/list_changed",
             "notifications/roots/list_changed",
             "notifications/message",
             "notifications/progress"
           ] ->
        Logger.info("Received notification from #{server.name}: #{method}")

        # Convert to our internal format and send to parent
        change = %{
          type: "notification",
          method: method,
          params: Map.merge(Map.get(event, "params", %{}), %{server: server.name})
        }

        # Use different message types for different notifications
        message_type =
          case method do
            "notifications/resources/updated" -> {:sse_resource_updated, change}
            "notifications/message" -> {:sse_log_message, change}
            "notifications/progress" -> {:sse_progress, change}
            _ -> {:sse_list_changed, change}
          end

        send(parent, message_type)

      _ ->
        Logger.debug("Ignoring SSE event from #{server.name}: #{inspect(event)}")
    end
  end
end
