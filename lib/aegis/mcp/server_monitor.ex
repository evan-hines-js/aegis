defmodule Aegis.MCP.ServerMonitor do
  @moduledoc """
  Per-server monitoring process that manages health checks, content caching, and change detection.

  ## Architecture

  Each server gets its own ServerMonitor process that:
  - Initializes and stores its own backend session
  - Monitors health by fetching content
  - Caches content and detects changes
  - Handles status transitions

  ## Key Benefits

  - **Simplified state**: Each process only manages one server
  - **Local session storage**: backend_session_id stored in process state
  - **Better isolation**: Server failures don't affect other monitors
  - **Natural lifecycle**: Process restart = session reinit
  """

  use GenServer
  require Logger

  alias Aegis.Cache

  alias Aegis.MCP.{
    Authorization,
    Constants,
    ContentTypes,
    ServerClient,
    ServerContentCache
  }

  # Monitoring interval - fixed since circuit breaker handles backoff
  @monitor_interval 5_000

  ## Public API

  def start_link(server_name) when is_binary(server_name) do
    GenServer.start_link(__MODULE__, server_name, name: via_tuple(server_name))
  end

  def start_link(server) when is_map(server) do
    GenServer.start_link(__MODULE__, server.name, name: via_tuple(server.name))
  end

  @doc "Get the server name from a monitor PID"
  def get_server_name(pid) when is_pid(pid) do
    GenServer.call(pid, :get_server_name)
  end

  @doc "Force immediate monitoring check"
  def refresh(server_name) do
    GenServer.cast(via_tuple(server_name), :refresh)
  end

  ## GenServer Callbacks

  @impl true
  def init(server_name) when is_binary(server_name) do
    Logger.info("ServerMonitor starting for #{server_name}")

    # Load server from DB
    server = load_server_from_db(server_name)

    # Schedule first monitoring cycle (will initialize then)
    Process.send_after(self(), :monitor, 1000)

    state = %{
      server: server,
      backend_session_id: nil,
      status: :unknown,
      content_snapshot: %{},
      monitor_timer: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_call(:get_server_name, _from, state) do
    {:reply, state.server.name, state}
  end

  @impl true
  def handle_info(:monitor, state) do
    new_state = perform_monitoring_cycle(state)
    final_state = schedule_next_monitor(new_state)
    {:noreply, final_state}
  end

  @impl true
  def handle_cast(:refresh, state) do
    refresh_all_content(state.server)
    {:noreply, state}
  end

  ## Private Functions - Session Management

  defp initialize_backend_session(server) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: %{
        protocolVersion: Constants.default_protocol_version(),
        capabilities: %{},
        clientInfo: %{
          name: Constants.server_name(),
          version: Constants.server_version()
        }
      }
    }

    case ServerClient.make_request(server, request_body, [], quiet: true) do
      {:ok, %{"result" => result}, headers} ->
        # Extract session ID from response headers if present
        session_id =
          case Map.get(headers, "mcp-session-id") do
            sid when is_binary(sid) ->
              Logger.debug("Initialized backend session for #{server.name}: #{sid}")
              sid

            _ ->
              Logger.debug("Server #{server.name} doesn't use sessions")
              nil
          end

        # Extract capabilities from result
        capabilities = Map.get(result, "capabilities", %{})
        {session_id, capabilities}

      {:error, reason} ->
        Logger.warning(
          "Failed to initialize backend session for #{server.name}: #{inspect(reason)}"
        )

        :failed
    end
  end

  defp cache_capabilities(server_name, capabilities) do
    protocol_version = Constants.default_protocol_version()
    cache_key = {server_name, protocol_version}

    Cache.put(:mcp_meta_cache, cache_key, capabilities,
      tags: ["server:#{server_name}:capabilities", "capabilities"]
    )

    Logger.debug("Cached capabilities for #{server_name}: #{inspect(Map.keys(capabilities))}")
  end

  ## Private Functions - Monitoring

  defp perform_monitoring_cycle(state) do
    Logger.debug("Monitoring cycle for #{state.server.name}")

    # Initialize to get fresh session + capabilities
    case initialize_backend_session(state.server) do
      {backend_session_id, capabilities} ->
        # Fetch content based on capabilities (this is our health check!)
        {status, snapshot} = fetch_server_content(state.server, backend_session_id, capabilities)

        # Cache capabilities
        cache_capabilities(state.server.name, capabilities)

        case status do
          :healthy ->
            handle_healthy_server(snapshot, %{state | backend_session_id: backend_session_id})

          :unhealthy ->
            handle_unhealthy_server(%{state | backend_session_id: backend_session_id})
        end

      :failed ->
        # Failed to initialize - server is unhealthy
        handle_unhealthy_server(state)
    end
  end

  defp fetch_server_content(server, backend_session_id, capabilities) do
    # Determine which content types to fetch based on capabilities
    content_types = get_supported_content_types(capabilities)

    if Enum.empty?(content_types) do
      # No supported content types - server is unhealthy
      {:unhealthy, %{}}
    else
      results =
        Enum.map(content_types, fn content_type ->
          {method, result_key} = ContentTypes.content_type_to_method_and_key(content_type)
          items = ServerClient.fetch_list(server, method, result_key, backend_session_id)
          {content_type, items}
        end)

      # If we got any content, server is healthy
      has_content? = Enum.any?(results, fn {_, items} -> length(items) > 0 end)

      snapshot = Map.new(results)

      if has_content? do
        {:healthy, snapshot}
      else
        {:unhealthy, %{}}
      end
    end
  end

  defp get_supported_content_types(capabilities) do
    []
    |> maybe_add_if_supported(:tools, Map.has_key?(capabilities, "tools"))
    |> maybe_add_if_supported(:resources, Map.has_key?(capabilities, "resources"))
    |> maybe_add_if_supported(:prompts, Map.has_key?(capabilities, "prompts"))
  end

  defp maybe_add_if_supported(list, _type, false), do: list
  defp maybe_add_if_supported(list, type, true), do: [type | list]

  defp handle_healthy_server(snapshot, state) do
    # Update server cache status
    update_server_status(state.server.name, :healthy, 0)

    # Cache content
    cache_server_content(state.server, snapshot)

    # Detect and broadcast changes
    changes = detect_content_changes(state.server.name, state.content_snapshot, snapshot)

    if not Enum.empty?(changes) do
      broadcast_changes(changes)
    end

    # Handle status transition
    if state.status != :healthy do
      handle_server_came_online(state.server)
    end

    %{
      state
      | status: :healthy,
        content_snapshot: snapshot
    }
  end

  defp handle_unhealthy_server(state) do
    update_server_status(state.server.name, :unhealthy, 0)

    # Broadcast status change if transitioning to unhealthy
    if state.status != :unhealthy do
      Phoenix.PubSub.broadcast(
        Aegis.PubSub,
        "servers",
        {:server_status_changed, state.server.name, :unhealthy}
      )

      broadcast_server_offline(state.server.name)
    end

    %{state | status: :unhealthy}
  end

  defp handle_server_came_online(server) do
    Logger.info("Server #{server.name} came online")

    # Broadcast status change
    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      "servers",
      {:server_status_changed, server.name, :healthy}
    )

    # Invalidate permission caches (capabilities already cached from health check)
    Authorization.invalidate_permissions_for_server(server.name)

    # Broadcast that server is online
    broadcast_server_online(server.name)
  end

  ## Private Functions - Content Management

  defp cache_server_content(server, snapshot) do
    Enum.each(snapshot, fn {content_type, items} ->
      cache_key = {server.name, content_type}

      Cache.put(:mcp_meta_cache, cache_key, items,
        tags: ["server:#{server.name}", "content_type:#{content_type}"]
      )
    end)
  end

  defp detect_content_changes(server_name, old_snapshot, new_snapshot) do
    changes = []

    # Check tools
    changes =
      if Map.get(old_snapshot, :tools, []) != Map.get(new_snapshot, :tools, []) do
        [%{method: "notifications/tools/list_changed", params: %{server: server_name}} | changes]
      else
        changes
      end

    # Check resources
    changes =
      if Map.get(old_snapshot, :resources, []) != Map.get(new_snapshot, :resources, []) do
        [
          %{method: "notifications/resources/list_changed", params: %{server: server_name}}
          | changes
        ]
      else
        changes
      end

    # Check prompts
    changes =
      if Map.get(old_snapshot, :prompts, []) != Map.get(new_snapshot, :prompts, []) do
        [
          %{method: "notifications/prompts/list_changed", params: %{server: server_name}}
          | changes
        ]
      else
        changes
      end

    changes
  end

  ## Private Functions - Scheduling

  defp schedule_next_monitor(state) do
    if state.monitor_timer do
      Process.cancel_timer(state.monitor_timer)
    end

    timer_ref = Process.send_after(self(), :monitor, @monitor_interval)

    %{state | monitor_timer: timer_ref}
  end

  ## Private Functions - Broadcasting

  defp broadcast_changes(changes) do
    Logger.info("Broadcasting #{length(changes)} content changes")

    Enum.each(changes, fn change ->
      Phoenix.PubSub.broadcast(
        Aegis.PubSub,
        Constants.all_changes_topic(),
        {:list_changed, change}
      )
    end)
  end

  defp broadcast_server_online(server_name) do
    Logger.info("Server #{server_name} online - broadcasting tools list change")

    change_notification = %{
      method: "notifications/tools/list_changed",
      params: %{server: server_name}
    }

    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.all_changes_topic(),
      {:list_changed, change_notification}
    )
  end

  defp broadcast_server_offline(server_name) do
    Logger.info("Server #{server_name} offline - broadcasting tools list change")

    change_notification = %{
      method: "notifications/tools/list_changed",
      params: %{server: server_name}
    }

    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.all_changes_topic(),
      {:list_changed, change_notification}
    )
  end

  ## Private Functions - Helpers

  defp update_server_status(server_name, status, failure_count) do
    cache_key = {:server, server_name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, server_info} when not is_nil(server_info) ->
        updated_info = %{
          server_info
          | status: status,
            last_check: DateTime.utc_now(),
            failure_count: failure_count
        }

        Cache.put(:mcp_meta_cache, cache_key, updated_info,
          tags: ["server:#{server_name}", "servers"]
        )

      _ ->
        # Server not in cache yet, will be added by ServerManager
        :ok
    end
  end

  defp refresh_all_content(server) do
    Logger.info("Refreshing all content for #{server.name}")
    ServerContentCache.invalidate_server_content(server)

    supported_content_types = [:tools, :resources, :prompts]

    Enum.each(supported_content_types, fn content_type ->
      ServerContentCache.get_content(server, content_type)
    end)
  end

  defp load_server_from_db(server_name) do
    case Aegis.MCP.get_server_by_name(server_name) do
      {:ok, server} ->
        loaded_server = Ash.load!(server, [:api_key])

        %{
          name: loaded_server.name,
          endpoint: loaded_server.endpoint,
          auth_type: loaded_server.auth_type || :none,
          api_key: loaded_server.api_key,
          api_key_header: loaded_server.api_key_header,
          api_key_template: loaded_server.api_key_template
        }

      {:error, reason} ->
        Logger.error("Failed to load server #{server_name} from DB: #{inspect(reason)}")
        raise "Server #{server_name} not found in database"
    end
  end

  defp via_tuple(server_name) do
    {:via, Registry, {Aegis.MCP.ServerMonitorRegistry, server_name}}
  end
end
