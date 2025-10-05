defmodule Aegis.MCP.Session do
  @moduledoc """
  Pure session operations using ETS as primary storage.

  All session data lives in SessionCache (ETS).
  All functions are pure - they read/write to ETS directly.
  No GenServer per session - SessionManager handles lifecycle.

  ## Architecture

  Controller → Session (pure functions) → SessionCache (ETS)
                                      ↘ Handler modules

  ## Session Data Structure

  - client_id: The MCP client this session belongs to
  - owner_node: Node where session was created
  - initialized: Whether initialize handshake completed
  - backend_sessions: Map of server_name => backend_session_id
  - resource_subscriptions: MapSet of subscribed resource URIs
  - client_capabilities: MCP capabilities provided by client
  - log_level: Logging level for this session
  - pagination_tokens: Map of hub_cursor => token_data
  - created_at: Session creation timestamp
  - last_activity: Last activity timestamp for timeout
  """

  require Logger

  alias Aegis.MCP.{
    ErrorResponse,
    PersistedSession,
    RequestHelpers,
    SessionCache,
    SessionManager
  }

  alias Aegis.MCP.Handlers.{
    InitializationHandler,
    LoggingHandler,
    ResourcesHandler
  }

  ## Session Lifecycle

  @doc """
  Create a new session.
  Delegates to SessionManager for lifecycle management.
  """
  def create_session(client_id) do
    SessionManager.create_session(client_id)
  end

  @doc """
  Terminate a session.
  Delegates to SessionManager for cleanup.
  """
  def terminate_session(session_id) do
    SessionManager.terminate_session(session_id)
  end

  @doc """
  Check if a session exists.
  """
  def exists?(session_id) do
    case SessionCache.get(session_id) do
      {:ok, _} -> true
      {:error, :not_found} -> false
    end
  end

  ## Session State Queries

  @doc """
  Get complete session data.
  Attempts lazy load from DB if not in cache (for rolling restarts).
  """
  def get_session(session_id) do
    case SessionCache.get(session_id) do
      {:ok, session_data} ->
        {:ok, session_data}

      {:error, :not_found} ->
        # Try to restore from DB (lazy loading)
        case restore_session_from_db(session_id) do
          {:ok, session_data} -> {:ok, session_data}
          {:error, _} -> {:error, :not_found}
        end
    end
  end

  @doc """
  Check if session is initialized.
  """
  def initialized?(session_id) do
    case SessionCache.get_field(session_id, :initialized) do
      {:ok, true} -> true
      _ -> false
    end
  end

  @doc """
  Get client ID for session.
  """
  def get_client_id(session_id) do
    SessionCache.get_field(session_id, :client_id)
  end

  @doc """
  Get backend sessions map.
  """
  def get_backend_sessions(session_id) do
    SessionCache.get_field(session_id, :backend_sessions)
  end

  @doc """
  Get backend session ID for a specific server.
  """
  def get_backend_session(session_id, server_name) do
    case SessionCache.get_nested(session_id, :backend_sessions, server_name) do
      {:ok, nil} -> {:error, :backend_session_not_found}
      {:ok, backend_session_id} -> {:ok, backend_session_id}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Get client capabilities for the session.
  """
  def get_client_capabilities(session_id) do
    SessionCache.get_field(session_id, :client_capabilities)
  end

  @doc """
  Get log level for the session.
  """
  def get_log_level(session_id) do
    SessionCache.get_field(session_id, :log_level)
  end

  @doc """
  Get resource subscriptions for the session.
  """
  def get_resource_subscriptions(session_id) do
    case SessionCache.get_field(session_id, :resource_subscriptions) do
      {:ok, subscriptions} -> {:ok, MapSet.to_list(subscriptions)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get a pagination token from the session.
  """
  def get_pagination_token(session_id, hub_cursor) do
    case SessionCache.get_nested(session_id, :pagination_tokens, hub_cursor) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, token_data} -> {:ok, token_data}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Get all pagination tokens for the session.
  """
  def get_all_pagination_tokens(session_id) do
    SessionCache.get_field(session_id, :pagination_tokens)
  end

  ## Session State Mutations

  @doc """
  Mark session as initialized (after MCP initialize handshake).
  """
  def mark_initialized(session_id) do
    case SessionCache.update_session(session_id, &Map.put(&1, :initialized, true)) do
      {:ok, _} ->
        Logger.debug("Session initialized: #{session_id}")
        {:ok, :initialized}

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Store backend session mapping (hub session -> backend server session).
  """
  def put_backend_session(session_id, server_name, backend_session_id) do
    case SessionCache.update_session(session_id, fn data ->
           Map.update(data, :backend_sessions, %{}, &Map.put(&1, server_name, backend_session_id))
         end) do
      {:ok, _} ->
        Logger.debug(
          "Backend session mapped: #{session_id} -> #{server_name}: #{backend_session_id}"
        )

        :ok

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Remove backend session mapping (when backend session is terminated).
  """
  def remove_backend_session(session_id, server_name) do
    case SessionCache.update_session(session_id, fn data ->
           Map.update(data, :backend_sessions, %{}, &Map.delete(&1, server_name))
         end) do
      {:ok, _} ->
        Logger.debug("Backend session removed: #{session_id} -> #{server_name}")
        :ok

      {:error, :not_found} ->
        :ok
    end
  end

  @doc """
  Store client capabilities provided during initialize.
  """
  def store_client_capabilities(session_id, capabilities) do
    case SessionCache.update_session(session_id, &Map.put(&1, :client_capabilities, capabilities)) do
      {:ok, _} -> :ok
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Add a resource subscription to the session.
  """
  def add_resource_subscription(session_id, resource_uri) do
    case SessionCache.update_session(session_id, fn data ->
           Map.update(data, :resource_subscriptions, MapSet.new(), &MapSet.put(&1, resource_uri))
         end) do
      {:ok, _} ->
        Logger.debug("Resource subscription added: #{session_id} -> #{resource_uri}")
        :ok

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Remove a resource subscription from the session.
  """
  def remove_resource_subscription(session_id, resource_uri) do
    case SessionCache.update_session(session_id, fn data ->
           Map.update(
             data,
             :resource_subscriptions,
             MapSet.new(),
             &MapSet.delete(&1, resource_uri)
           )
         end) do
      {:ok, _} ->
        Logger.debug("Resource subscription removed: #{session_id} -> #{resource_uri}")
        :ok

      {:error, :not_found} ->
        :ok
    end
  end

  @doc """
  Set log level for the session.
  """
  def set_log_level(session_id, level) do
    case SessionCache.update_session(session_id, &Map.put(&1, :log_level, level)) do
      {:ok, _} -> :ok
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Store a pagination token in the session.
  """
  def store_pagination_token(session_id, hub_cursor, token_data) do
    case SessionCache.update_session(session_id, fn data ->
           Map.update(data, :pagination_tokens, %{}, &Map.put(&1, hub_cursor, token_data))
         end) do
      {:ok, _} -> :ok
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Remove a pagination token from the session.
  """
  def remove_pagination_token(session_id, hub_cursor) do
    case SessionCache.update_session(session_id, fn data ->
           Map.update(data, :pagination_tokens, %{}, &Map.delete(&1, hub_cursor))
         end) do
      {:ok, _} -> :ok
      {:error, :not_found} -> :ok
    end
  end

  ## Session Queries

  @doc """
  List all sessions (with their data).
  """
  def list_sessions do
    SessionCache.list_all_sessions()
  end

  @doc """
  List all session IDs.
  """
  def list_session_ids do
    SessionCache.list_all_sessions()
    |> Enum.map(& &1.id)
  end

  @doc """
  Get all sessions for a specific client.
  """
  def get_sessions_for_client(client_id) do
    {:ok, SessionCache.list_sessions_for_client(client_id)}
  end

  ## Request Handling

  @doc """
  Handle an MCP protocol request.

  This is the main entry point for all MCP requests.
  Routes to appropriate handler based on method.
  Returns {:ok, response} or {:error, response}.
  """
  def handle_request(session_id, method, params) do
    case SessionCache.get(session_id) do
      {:ok, session_data} ->
        # Touch session to update last_activity if stale (throttled to avoid write overhead)
        touch_session_if_stale(session_id, session_data.last_activity)

        # Route request to appropriate handler
        route_request(session_id, method, params)

      {:error, :not_found} ->
        {:error, ErrorResponse.build_error(ErrorResponse.invalid_request(), "Session not found")}
    end
  end

  ## Private Functions

  # Touch session activity threshold (only update if older than this)
  @touch_threshold_minutes 5

  defp touch_session_if_stale(session_id, last_activity) do
    minutes_since_activity = DateTime.diff(DateTime.utc_now(), last_activity, :minute)

    if minutes_since_activity >= @touch_threshold_minutes do
      # Update session to refresh last_activity timestamp
      # This is throttled to avoid write overhead on every request
      SessionCache.update_session(session_id, & &1)
    end
  end

  defp route_request(session_id, "initialize", params) do
    # Get client_id from session
    {:ok, client_id} = get_client_id(session_id)

    init_params = Map.get(params, "params", %{})

    {:ok, response, state_updates} =
      InitializationHandler.handle_initialize(
        session_id,
        client_id,
        init_params,
        params
      )

    # Apply state updates to ETS
    apply_state_updates(session_id, state_updates)
    {:ok, response}
  end

  defp route_request(_session_id, "notifications/initialized", _params) do
    # Client confirms initialization - just acknowledge
    {:ok, nil}
  end

  defp route_request(session_id, "notifications/cancelled", params) do
    # Handle cancelled notification (e.g., cancelled tool call)
    request_id = Map.get(params, "params", %{}) |> Map.get("requestId")

    if request_id do
      Logger.info("Request cancelled: #{request_id} for session #{session_id}")
    end

    {:ok, nil}
  end

  defp route_request(session_id, "notifications/roots/list_changed", _params) do
    # Client notifying hub that their roots have changed
    Logger.info("Client roots changed notification for session #{session_id}")

    # Forward to all backend servers
    case get_backend_sessions(session_id) do
      {:ok, backend_sessions} ->
        forward_roots_notification_to_backends(backend_sessions)

      {:error, _} ->
        Logger.warning("Could not get backend sessions for session #{session_id}")
    end

    {:ok, nil}
  end

  defp route_request(session_id, "resources/subscribe", params) do
    {:ok, client_id} = get_client_id(session_id)
    {:ok, backend_sessions} = get_backend_sessions(session_id)

    ResourcesHandler.handle_subscribe(
      session_id,
      client_id,
      backend_sessions,
      params
    )
  end

  defp route_request(session_id, "resources/unsubscribe", params) do
    {:ok, client_id} = get_client_id(session_id)
    ResourcesHandler.handle_unsubscribe(session_id, client_id, params)
  end

  defp route_request(session_id, "logging/setLevel", params) do
    LoggingHandler.handle_set_level(session_id, params)
  end

  defp route_request(_session_id, "ping", params) do
    # Ping doesn't need session state, just return empty result
    response = %{jsonrpc: "2.0", result: %{}}
    response = RequestHelpers.add_request_id_if_present(response, params)
    {:ok, response}
  end

  defp route_request(_session_id, method, _params) do
    {:error,
     ErrorResponse.build_error(
       ErrorResponse.method_not_found(),
       "Unknown method: #{method}"
     )}
  end

  defp apply_state_updates(session_id, state_updates) do
    SessionCache.update_session(session_id, fn data ->
      Enum.reduce(state_updates, data, fn {field, value}, acc ->
        Map.put(acc, field, value)
      end)
    end)
  end

  defp restore_session_from_db(session_id) do
    case PersistedSession.get_by_session_id(session_id) do
      {:ok, persisted} ->
        Logger.info("Lazy loading session from DB: #{session_id}")

        # Deserialize session data
        session_data = deserialize_session_data(persisted.session_data)

        # Restore to ETS cache
        SessionCache.put(session_id, session_data)

        # Delete from DB (no longer needed)
        PersistedSession.destroy_persisted_session(persisted.id)

        # Emit telemetry
        :telemetry.execute(
          [:aegis, :session, :restored],
          %{count: 1},
          %{session_id: session_id, client_id: session_data.client_id}
        )

        {:ok, session_data}

      {:error, _reason} ->
        {:error, :not_found}
    end
  end

  defp deserialize_session_data(data) do
    %{
      client_id: data["client_id"],
      owner_node: node(),
      backend_sessions: data["backend_sessions"] || %{},
      pagination_tokens: data["pagination_tokens"] || %{},
      client_capabilities: data["client_capabilities"] || %{},
      resource_subscriptions: MapSet.new(data["resource_subscriptions"] || []),
      initialized: data["initialized"] || false,
      log_level: parse_log_level(data["log_level"]),
      created_at: parse_datetime(data["created_at"]),
      last_activity: parse_datetime(data["last_activity"])
    }
  end

  # Safely parse log level from string, preventing atom exhaustion attacks
  defp parse_log_level(nil), do: :info
  defp parse_log_level("debug"), do: :debug
  defp parse_log_level("info"), do: :info
  defp parse_log_level("notice"), do: :notice
  defp parse_log_level("warning"), do: :warning
  defp parse_log_level("error"), do: :error
  defp parse_log_level("critical"), do: :critical
  defp parse_log_level("alert"), do: :alert
  defp parse_log_level("emergency"), do: :emergency
  # Invalid log levels default to :info for safety
  defp parse_log_level(_), do: :info

  defp parse_datetime(nil), do: DateTime.utc_now()

  defp parse_datetime(iso_string) when is_binary(iso_string) do
    case DateTime.from_iso8601(iso_string) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_datetime(dt), do: dt

  # Forward roots notification to backend servers
  defp forward_roots_notification_to_backends(backend_sessions) do
    alias Aegis.MCP.ServerClient

    servers = ServerClient.get_healthy_servers()

    Logger.info("Forwarding roots notification to #{length(servers)} backend servers")
    Logger.debug("Backend sessions: #{inspect(backend_sessions)}")

    Task.start(fn ->
      Enum.each(servers, &forward_to_backend(&1, backend_sessions))
    end)

    :ok
  end

  defp forward_to_backend(server, backend_sessions) do
    alias Aegis.MCP.ServerClient

    backend_session_id = Map.get(backend_sessions, server.name)
    Logger.debug("Forwarding to #{server.name}, session: #{inspect(backend_session_id)}")

    notification_body = %{
      jsonrpc: "2.0",
      method: "notifications/roots/list_changed"
    }

    session_headers =
      if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    case ServerClient.send_notification(server, notification_body, session_headers) do
      {:ok, :sent} ->
        Logger.debug("Successfully forwarded roots notification to #{server.name}")

      {:error, :unsupported_notification} ->
        Logger.debug("Server #{server.name} doesn't support roots notifications (ignoring)")

      {:error, reason} ->
        Logger.warning(
          "Failed to forward roots notification to #{server.name}: #{inspect(reason)}"
        )
    end
  end
end
