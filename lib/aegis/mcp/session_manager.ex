defmodule Aegis.MCP.SessionManager do
  @moduledoc """
  Single GenServer managing lifecycle of ALL sessions.

  Responsibilities:
  - Session creation/deletion
  - Timeout management (periodic checks)
  - Cleanup on termination
  - Telemetry events

  Session data lives in ETS (SessionCache).
  Session operations are pure functions in Session module.
  """

  use GenServer
  require Logger

  alias Aegis.MCP.{PersistedSession, SessionCache}

  # Check for expired sessions every 5 minutes
  @timeout_check_interval :timer.minutes(5)
  # Default session timeout: 1 hour
  @default_session_timeout :timer.hours(1)
  # Clean stale persisted sessions every 15 minutes
  @stale_cleanup_interval :timer.minutes(15)

  ## Client API

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @doc """
  Create a new session.
  Returns {:ok, session_id} or {:error, reason}.
  """
  def create_session(client_id) do
    GenServer.call(__MODULE__, {:create_session, client_id})
  end

  @doc """
  Terminate a specific session.
  """
  def terminate_session(session_id) do
    GenServer.call(__MODULE__, {:terminate_session, session_id})
  end

  @doc """
  Terminate all sessions for a specific client.
  """
  def terminate_client_sessions(client_id) do
    GenServer.call(__MODULE__, {:terminate_client_sessions, client_id})
  end

  ## GenServer Callbacks

  @impl true
  def init(:ok) do
    Logger.info("SessionManager started - managing all session lifecycles")

    # Schedule periodic timeout checks
    schedule_timeout_check()
    schedule_stale_cleanup()

    state = %{
      session_count: 0
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_session, client_id}, _from, state) do
    session_id = generate_session_id()
    now = DateTime.utc_now()

    session_data = %{
      client_id: client_id,
      owner_node: node(),
      backend_sessions: %{},
      pagination_tokens: %{},
      client_capabilities: %{},
      resource_subscriptions: MapSet.new(),
      initialized: false,
      log_level: :info,
      created_at: now,
      last_activity: now
    }

    # Store in ETS
    SessionCache.put(session_id, session_data)

    Logger.debug("Session created: #{session_id} for client: #{client_id}")

    # Emit telemetry event
    :telemetry.execute(
      [:aegis, :session, :created],
      %{count: 1},
      %{session_id: session_id, client_id: client_id}
    )

    new_state = %{state | session_count: state.session_count + 1}

    {:reply, {:ok, session_id}, new_state}
  end

  @impl true
  def handle_call({:terminate_session, session_id}, _from, state) do
    case SessionCache.get(session_id) do
      {:ok, session_data} ->
        cleanup_session(session_id, session_data)
        new_state = %{state | session_count: max(0, state.session_count - 1)}
        {:reply, :ok, new_state}

      {:error, :not_found} ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:terminate_client_sessions, client_id}, _from, state) do
    session_ids = SessionCache.list_sessions_for_client(client_id)

    Enum.each(session_ids, fn session_id ->
      case SessionCache.get(session_id) do
        {:ok, session_data} -> cleanup_session(session_id, session_data)
        {:error, :not_found} -> :ok
      end
    end)

    count = length(session_ids)
    new_state = %{state | session_count: max(0, state.session_count - count)}

    Logger.info("Terminated #{count} sessions for client #{client_id}")

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_info(:timeout_check, state) do
    check_and_cleanup_expired_sessions()
    schedule_timeout_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_stale_persisted, state) do
    cleanup_stale_persisted_sessions()
    schedule_stale_cleanup()
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, _state) do
    Logger.info("SessionManager shutting down - persisting active sessions to DB")

    sessions = SessionCache.list_all_sessions()

    # Batch persist all sessions in a single DB operation
    if sessions != [] do
      persist_sessions_batch(sessions)
      Logger.info("Persisted #{length(sessions)} sessions to DB for recovery")
    end

    :ok
  end

  ## Private Functions

  defp generate_session_id do
    "sess_" <> Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
  end

  defp schedule_timeout_check do
    Process.send_after(self(), :timeout_check, @timeout_check_interval)
  end

  defp schedule_stale_cleanup do
    Process.send_after(self(), :cleanup_stale_persisted, @stale_cleanup_interval)
  end

  defp check_and_cleanup_expired_sessions do
    start_time = System.monotonic_time(:millisecond)
    now = DateTime.utc_now()
    timeout_seconds = div(@default_session_timeout, 1000)

    # PERFORMANCE: Process stream incrementally without materializing
    # Avoids 200ms GC pause with 5000+ sessions
    cleanup_count =
      SessionCache.list_all_sessions()
      |> Stream.filter(fn %{id: _session_id, data: session_data} ->
        last_activity = session_data.last_activity
        DateTime.diff(now, last_activity, :second) > timeout_seconds
      end)
      |> Enum.reduce(0, fn %{id: session_id, data: session_data}, count ->
        Logger.info("Session expired due to inactivity: #{session_id}")
        cleanup_session(session_id, session_data)
        count + 1
      end)

    duration_ms = System.monotonic_time(:millisecond) - start_time

    if cleanup_count > 0 do
      Logger.info("Cleaned up #{cleanup_count} expired sessions in #{duration_ms}ms")
    end

    :telemetry.execute(
      [:aegis, :session_manager, :cleanup],
      %{duration_ms: duration_ms, cleanup_count: cleanup_count},
      %{}
    )
  end

  defp cleanup_session(session_id, session_data) do
    Logger.info("Cleaning up session: #{session_id}")

    # Remove from ETS cache
    SessionCache.delete(session_id)

    # Emit telemetry event
    :telemetry.execute(
      [:aegis, :session, :terminated],
      %{count: 1},
      %{session_id: session_id, client_id: session_data.client_id}
    )

    # Broadcast session termination to any subscribers
    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      "mcp_session:#{session_id}",
      {:session_terminated, session_id}
    )

    :ok
  end

  defp persist_sessions_batch(sessions) do
    now = DateTime.utc_now()

    # PERFORMANCE: Batch in chunks to avoid massive allocation on shutdown
    # With 5000 sessions, single batch = 50-100MB allocation
    sessions
    |> Stream.chunk_every(500)
    |> Enum.each(fn session_chunk ->
      # Prepare inputs for this chunk
      inputs =
        Enum.map(session_chunk, fn %{id: session_id, data: session_data} ->
          serialized_data = %{
            "client_id" => session_data.client_id,
            "backend_sessions" => session_data.backend_sessions,
            "pagination_tokens" => session_data.pagination_tokens,
            "client_capabilities" => session_data.client_capabilities,
            "resource_subscriptions" => MapSet.to_list(session_data.resource_subscriptions),
            "initialized" => session_data.initialized,
            "log_level" => to_string(session_data.log_level),
            "created_at" => DateTime.to_iso8601(session_data.created_at),
            "last_activity" => DateTime.to_iso8601(session_data.last_activity)
          }

          %{
            session_id: session_id,
            client_id: session_data.client_id,
            session_data: serialized_data,
            persisted_at: now
          }
        end)

      # Batch upsert using Ash bulk create (with upsert configured in action)
      Ash.bulk_create(inputs, PersistedSession, :persist,
        return_records?: false,
        return_errors?: false
      )
    end)
  rescue
    e ->
      Logger.error("Failed to batch persist sessions: #{inspect(e)}")
      :error
  end

  defp cleanup_stale_persisted_sessions do
    case PersistedSession.list_stale_sessions() do
      {:ok, [_ | _] = stale_sessions} ->
        Logger.info("Cleaning up #{length(stale_sessions)} stale persisted sessions")

        Enum.each(stale_sessions, fn session ->
          PersistedSession.destroy_persisted_session(session.id)
        end)

      _ ->
        :ok
    end
  end
end
