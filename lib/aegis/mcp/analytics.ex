defmodule Aegis.MCP.Analytics do
  @moduledoc """
  Tracks MCP usage analytics for smart pagination ranking.

  Subscribes to usage events and maintains ETS counters for:
  - Per-client tool/resource/prompt usage counts
  - Global usage statistics
  - Last-used timestamps

  Uses atomic ETS counters for lock-free concurrent updates.
  """

  use GenServer
  require Logger

  alias Aegis.MCP.Constants
  alias Phoenix.PubSub

  @usage_stats_table :usage_stats
  @global_stats_table :global_stats

  # Client API

  @doc """
  Start the Analytics GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get usage statistics for a specific client and item.

  Returns `{count, last_used_timestamp}` or `nil` if no usage data exists.
  """
  @spec get_usage_stats(String.t(), String.t()) :: {integer(), integer()} | nil
  def get_usage_stats(client_id, tool_identifier) do
    case :ets.lookup(@usage_stats_table, {client_id, tool_identifier}) do
      [{_key, {count, timestamp}}] -> {count, timestamp}
      [] -> nil
    end
  end

  @doc """
  Get all usage statistics for a client.

  Returns a map of `%{tool_identifier => {count, timestamp}}`.
  """
  @spec get_client_usage(String.t()) :: %{String.t() => {integer(), integer()}}
  def get_client_usage(client_id) do
    @usage_stats_table
    |> :ets.match({{client_id, :"$1"}, :"$2"})
    |> Enum.into(%{}, fn [tool_id, stats] -> {tool_id, stats} end)
  end

  @doc """
  Get global usage count for a tool/resource/prompt.

  Returns the count or 0 if no usage data exists.
  """
  @spec get_global_usage(String.t()) :: integer()
  def get_global_usage(tool_identifier) do
    case :ets.lookup(@global_stats_table, tool_identifier) do
      [{_key, count}] -> count
      [] -> 0
    end
  end

  @doc """
  Get all global usage statistics.

  Returns a map of `%{tool_identifier => count}`.
  """
  @spec get_all_global_usage() :: %{String.t() => integer()}
  def get_all_global_usage do
    @global_stats_table
    |> :ets.tab2list()
    |> Enum.into(%{})
  end

  # GenServer callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables with read_concurrency for fast lookups
    :ets.new(@usage_stats_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])

    :ets.new(@global_stats_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Subscribe to usage events
    :ok = PubSub.subscribe(Aegis.PubSub, Constants.usage_topic())

    Logger.info("Analytics GenServer started, subscribed to usage events")

    {:ok, %{}}
  end

  @impl true
  def handle_info(
        {:usage_event,
         %{
           client_id: client_id,
           server_name: server_name,
           item_name: item_name,
           timestamp: timestamp
         }},
        state
      ) do
    # Create namespaced tool identifier (server_name__item_name)
    tool_identifier = "#{server_name}__#{item_name}"

    # Update per-client usage stats
    update_client_usage(client_id, tool_identifier, timestamp)

    # Update global usage stats
    update_global_usage(tool_identifier)

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    # Ignore unknown messages
    {:noreply, state}
  end

  # Private helper functions

  defp update_client_usage(client_id, tool_identifier, timestamp) do
    key = {client_id, tool_identifier}
    timestamp_int = DateTime.to_unix(timestamp, :second)

    # Try to update counter atomically
    # Position 1 in tuple is count, position 2 is timestamp
    try do
      :ets.update_counter(@usage_stats_table, key, {1, 1}, {key, {0, timestamp_int}})

      # Update timestamp separately (non-atomic, eventual consistency)
      # Read current count and update both
      case :ets.lookup(@usage_stats_table, key) do
        [{^key, {count, _old_timestamp}}] ->
          :ets.insert(@usage_stats_table, {key, {count, timestamp_int}})

        [] ->
          # Race condition: entry was deleted, re-insert
          :ets.insert(@usage_stats_table, {key, {1, timestamp_int}})
      end
    rescue
      ArgumentError ->
        # Table doesn't exist or invalid format, log and continue
        Logger.warning("Failed to update client usage stats for #{key}")
    end
  end

  defp update_global_usage(tool_identifier) do
    try do
      :ets.update_counter(@global_stats_table, tool_identifier, 1, {tool_identifier, 0})
    rescue
      ArgumentError ->
        Logger.warning("Failed to update global usage stats for #{tool_identifier}")
    end
  end
end
