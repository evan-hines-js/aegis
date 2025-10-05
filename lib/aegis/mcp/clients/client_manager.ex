defmodule Aegis.MCP.ClientManager do
  @moduledoc """
  Handles client change events and cache invalidation.

  Listens to PubSub for client changes and invalidates caches accordingly.
  Client statistics are provided by ClientStats module using pure functions.
  """

  use GenServer
  require Logger

  require Ash.Query

  alias Aegis.MCP.{Authorization, ClientStats, Constants, Session}

  def start_link(init_arg) do
    GenServer.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    Logger.info("ClientManager starting")

    # Subscribe to client changes
    Phoenix.PubSub.subscribe(Aegis.PubSub, "client_changes")

    {:ok, %{}}
  end

  # Public API

  @doc """
  Get client counts (delegated to ClientStats).
  """
  def get_client_counts do
    ClientStats.get_client_counts()
  end

  # GenServer callbacks

  @impl true
  def handle_info({:client_created, _client}, state) do
    ClientStats.invalidate_counts()
    {:noreply, state}
  end

  def handle_info({:client_updated, _client}, state) do
    ClientStats.invalidate_counts()
    {:noreply, state}
  end

  def handle_info({:client_deleted, _client}, state) do
    ClientStats.invalidate_counts()
    {:noreply, state}
  end

  def handle_info({:api_key_regenerated, client, old_api_key_hash}, state) do
    Logger.info("API key regenerated for client: #{client.name} (#{client.id})")
    ClientStats.invalidate_counts()
    invalidate_client_caches_and_sessions(client.id, old_api_key_hash)
    {:noreply, state}
  end

  # Private functions

  defp invalidate_client_caches_and_sessions(client_id, old_api_key_hash) do
    Logger.info("Invalidating caches and sessions for client: #{client_id}")

    # 1. Invalidate permission cache for this client
    Authorization.invalidate_client_permissions(client_id)

    # 2. Invalidate the specific old API key cache entry
    if old_api_key_hash do
      :ets.delete(Constants.permission_cache_table(), {:api_key, old_api_key_hash})
      Logger.debug("Cleared API key cache for hash: #{String.slice(old_api_key_hash, 0, 8)}...")
    end

    # 3. Terminate all active sessions for this client
    terminate_client_sessions(client_id)

    Logger.info("Cache and session invalidation completed for client: #{client_id}")
  end

  defp terminate_client_sessions(client_id) do
    # Get all active sessions for this client and terminate them
    {:ok, session_ids} = Session.get_sessions_for_client(client_id)

    Enum.each(session_ids, fn session_id ->
      Session.terminate_session(session_id)
      Logger.debug("Terminated session #{session_id} for client #{client_id}")
    end)

    if length(session_ids) > 0 do
      Logger.info("Terminated #{length(session_ids)} sessions for client #{client_id}")
    end
  end
end
