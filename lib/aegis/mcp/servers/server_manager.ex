defmodule Aegis.MCP.ServerManager do
  @moduledoc """
  Manages MCP server lifecycle and synchronization.

  Periodically syncs server configurations from database to registry and spawns
  per-server monitoring processes via ServerMonitorSupervisor.
  """

  use GenServer
  require Logger

  alias Aegis.Cache

  alias Aegis.MCP.{
    Authorization,
    CapabilityAggregator,
    Constants,
    ServerContentCache,
    ServerMonitorSupervisor,
    Session
  }

  @db_sync_interval :timer.minutes(5)

  def start_link(init_arg) do
    GenServer.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    Logger.info("ServerManager starting")

    # Subscribe to server changes
    Phoenix.PubSub.subscribe(Aegis.PubSub, "server_changes")

    # Trigger initial sync (registry is empty, so all servers will be added)
    send(self(), :db_sync)

    {:ok, %{}}
  end

  # Public API

  def add_server(name, endpoint) do
    GenServer.call(__MODULE__, {:add_server, name, endpoint})
  end

  def remove_server(name) do
    GenServer.call(__MODULE__, {:remove_server, name})
  end

  def get_server(name) do
    cache_key = {:server, name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, server_info} when not is_nil(server_info) -> {:ok, server_info}
      {:ok, nil} -> {:error, :not_found}
      {:error, _} -> {:error, :not_found}
    end
  end

  # GenServer callbacks

  @impl true
  def handle_call({:add_server, name, endpoint}, _from, state) do
    server_info = %{
      endpoint: endpoint,
      status: :unknown,
      capabilities: %{},
      last_check: nil,
      failure_count: 0
    }

    cache_key = {:server, name}

    Cache.put(:mcp_meta_cache, cache_key, server_info, tags: ["server:#{name}", "servers"])

    Logger.info("Added server #{name} at #{endpoint}")

    {:reply, :ok, state}
  end

  def handle_call({:remove_server, name}, _from, state) do
    # Broadcast server-specific capabilities change BEFORE removing from registry
    # so clients who had access can receive the deletion notification
    broadcast_server_capabilities_changed(name)

    # Invalidate permission caches for clients that had access to this server
    # This prevents SSE notifications from being sent for a new server with the same name
    Authorization.invalidate_permissions_for_server(name)

    cache_key = {:server, name}
    Cache.delete(:mcp_meta_cache, cache_key)
    Logger.info("Removed server #{name}")

    # Clear capabilities cache for this server
    clear_server_capabilities(name)

    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:db_sync, state) do
    sync_servers_from_database()
    schedule_db_sync()
    {:noreply, state}
  end

  def handle_info({:server_created, server}, state) do
    Logger.info("Received server_created event for #{server.name}")

    # Load sensitive fields to avoid NotLoaded errors
    loaded_server = Ash.load!(server, [:api_key])

    # Load cached capabilities if available
    cached_capabilities = load_cached_capabilities(loaded_server.name)

    server_info = %{
      endpoint: loaded_server.endpoint,
      auth_type: loaded_server.auth_type || :none,
      api_key: loaded_server.api_key,
      status: :unknown,
      capabilities: cached_capabilities,
      last_check: nil,
      failure_count: 0
    }

    cache_key = {:server, server.name}

    Cache.put(:mcp_meta_cache, cache_key, server_info, tags: ["server:#{server.name}", "servers"])

    # Start monitoring the new server for health checks
    start_server_monitoring(loaded_server)

    {:noreply, state}
  end

  def handle_info({:server_updated, server}, state) do
    Logger.info("Received server_updated event for #{server.name}")

    # Load sensitive fields to avoid NotLoaded errors
    loaded_server = Ash.load!(server, [:api_key])
    cache_key = {:server, server.name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, current_info} when not is_nil(current_info) ->
        updated_info = %{
          current_info
          | endpoint: loaded_server.endpoint,
            auth_type: loaded_server.auth_type || :none,
            api_key: loaded_server.api_key
        }

        Cache.put(:mcp_meta_cache, cache_key, updated_info,
          tags: ["server:#{server.name}", "servers"]
        )

      _ ->
        # Server doesn't exist in registry, add it
        # Load cached capabilities if available
        cached_capabilities = load_cached_capabilities(loaded_server.name)

        server_info = %{
          endpoint: loaded_server.endpoint,
          auth_type: loaded_server.auth_type || :none,
          api_key: loaded_server.api_key,
          status: :unknown,
          capabilities: cached_capabilities,
          last_check: nil,
          failure_count: 0
        }

        Cache.put(:mcp_meta_cache, cache_key, server_info,
          tags: ["server:#{server.name}", "servers"]
        )

        # Start monitoring the new server for health checks
        start_server_monitoring(loaded_server)
    end

    {:noreply, state}
  end

  def handle_info({:server_deleted, server}, state) do
    Logger.info("Received server_deleted event for #{server.name}")

    # Stop monitoring process for this server
    ServerMonitorSupervisor.stop_monitor(server.name)

    # Broadcast server-specific capabilities change BEFORE removing from registry
    # so clients who had access can receive the deletion notification
    broadcast_server_capabilities_changed(server.name)

    # Invalidate permission caches for clients that had access to this server
    # This prevents SSE notifications from being sent for a new server with the same name
    Authorization.invalidate_permissions_for_server(server.name)

    # Remove from registry
    cache_key = {:server, server.name}
    Cache.delete(:mcp_meta_cache, cache_key)

    # Clear from content cache
    ServerContentCache.invalidate_server_content(server)

    # Clear capabilities cache for this server
    clear_server_capabilities(server.name)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:update_capabilities, state) do
    Logger.debug("ServerManager capabilities updated - broadcasting tools list change")
    broadcast_capabilities_changed()
    {:noreply, state}
  end

  # Private functions

  defp schedule_db_sync do
    Process.send_after(self(), :db_sync, @db_sync_interval)
  end

  defp sync_servers_from_database do
    # Get cached server names (no DB query)
    cached_names = MapSet.new(list_cached_server_names())

    # Get servers from database (single DB query)
    db_servers = Aegis.MCP.list_servers!(load: [:api_key])
    db_names = MapSet.new(db_servers, & &1.name)

    # Add servers that are in DB but missing from cache
    Enum.each(db_servers, fn server ->
      unless MapSet.member?(cached_names, server.name) do
        add_server_to_cache(server)
      end
    end)

    # Remove servers that are in cache but not in DB (deleted servers)
    stale_names = MapSet.difference(cached_names, db_names)

    Enum.each(stale_names, fn server_name ->
      Logger.info("Removing stale server from cache: #{server_name} (not in database)")
      cache_key = {:server, server_name}
      Cache.delete(:mcp_meta_cache, cache_key)

      # Broadcast deletion to notify clients
      Phoenix.PubSub.broadcast(
        Aegis.PubSub,
        Constants.all_changes_topic(),
        {:list_changed,
         %{method: "notifications/tools/list_changed", params: %{server: server_name}}}
      )
    end)
  end

  defp add_server_to_cache(server) do
    # Load cached capabilities if available
    cached_capabilities = load_cached_capabilities(server.name)

    server_info = %{
      endpoint: server.endpoint,
      auth_type: server.auth_type || :none,
      api_key: server.api_key,
      status: :unknown,
      capabilities: cached_capabilities,
      last_check: nil,
      failure_count: 0
    }

    cache_key = {:server, server.name}

    Cache.put(:mcp_meta_cache, cache_key, server_info, tags: ["server:#{server.name}", "servers"])

    Logger.info("Discovered new server from database: #{server.name} at #{server.endpoint}")

    # Start monitoring the new server for health checks
    start_server_monitoring(server)

    # Broadcast new server discovery
    broadcast_server_discovered(server.name)
  end

  defp list_cached_server_names do
    case Cachex.stream(:mcp_meta_cache) do
      {:ok, stream} ->
        stream
        |> Stream.filter(fn
          {:entry, {:server, _name}, _metadata, _timestamp, _ttl} -> true
          _ -> false
        end)
        |> Stream.map(fn {:entry, {:server, name}, _metadata, _timestamp, _ttl} -> name end)
        |> Enum.to_list()

      {:error, _} ->
        []
    end
  end

  defp broadcast_server_discovered(server_name) do
    Logger.info("New server #{server_name} discovered - will broadcast when online")

    # Note: We'll broadcast when it comes online during health check
    # This avoids double-broadcasting
  end

  defp clear_server_capabilities(server_name) do
    # Clear from unified cache using tag-based invalidation (more comprehensive)
    Cache.invalidate_by_tag(:mcp_meta_cache, "server:#{server_name}")

    Logger.info("Cleared capabilities cache for server #{server_name}")
  end

  defp broadcast_capabilities_changed do
    Logger.info("Broadcasting capabilities changed notification")

    change_notification = %{
      method: "notifications/tools/list_changed"
    }

    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.all_changes_topic(),
      {:list_changed, change_notification}
    )
  end

  defp broadcast_server_capabilities_changed(server_name) do
    Logger.info("Broadcasting capabilities changed notification for server: #{server_name}")

    change_notification = %{
      method: "notifications/tools/list_changed",
      params: %{
        server: server_name
      }
    }

    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.all_changes_topic(),
      {:list_changed, change_notification}
    )
  end

  def notify_client_permissions_changed(client_id) do
    Logger.info("Notifying client #{client_id} of permission changes")

    change_notification = %{
      method: "notifications/tools/list_changed"
    }

    # Send to all active sessions for this client
    {:ok, sessions} = Session.get_sessions_for_client(client_id)

    if sessions == [] do
      Logger.debug("No active sessions found for client #{client_id}")
    else
      Enum.each(sessions, fn session_id ->
        Phoenix.PubSub.broadcast(
          Aegis.PubSub,
          "mcp_session:#{session_id}",
          {:list_changed, change_notification}
        )
      end)

      Logger.info(
        "Sent permission change notifications to #{length(sessions)} sessions for client #{client_id}"
      )
    end
  end

  defp start_server_monitoring(server) do
    monitor_server = %{
      name: server.name,
      endpoint: server.endpoint
    }

    ServerMonitorSupervisor.start_monitor(monitor_server)
  end

  defp load_cached_capabilities(server_name) do
    # Load from in-memory cache first, then DB cache
    # Won't call out to MCP servers, but may query DB
    protocol_version = Constants.default_protocol_version()
    cache_key = {server_name, protocol_version}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, capabilities} when not is_nil(capabilities) and capabilities != %{} ->
        Logger.debug("Loaded in-memory cached capabilities for #{server_name} during sync")
        capabilities

      _ ->
        # Try loading from DB cache
        case CapabilityAggregator.load_capabilities_from_db(server_name) do
          %{} = db_capabilities when map_size(db_capabilities) > 0 ->
            Logger.debug("Loaded DB cached capabilities for #{server_name} during sync")

            # Populate in-memory cache for next time
            Cache.put(:mcp_meta_cache, cache_key, db_capabilities,
              tags: ["server:#{server_name}:capabilities", "capabilities"]
            )

            db_capabilities

          _ ->
            # No cached capabilities available - health check will fetch them
            %{}
        end
    end
  end
end
