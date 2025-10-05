defmodule Aegis.MCP.ClientStats do
  @moduledoc """
  Pure functions for client statistics and counts.

  Uses cached database queries with automatic invalidation via PubSub.
  """

  require Logger
  alias Aegis.Cache

  @cache_ttl :timer.minutes(5)

  @doc """
  Get client counts (total and active).

  Results are cached for 5 minutes. Cache is invalidated when clients change.
  """
  def get_client_counts do
    Cache.fetch_or_cache(
      :rbac_cache,
      :client_counts,
      fn ->
        total_clients =
          try do
            Aegis.MCP.list_clients!() |> length()
          rescue
            _ -> 0
          end

        active_clients =
          try do
            Aegis.MCP.list_clients!(filter: [active: true]) |> length()
          rescue
            _ -> 0
          end

        counts = %{total: total_clients, active: active_clients}
        Logger.debug("Client counts fetched: #{inspect(counts)}")
        {:ok, counts}
      end,
      ttl: @cache_ttl,
      tags: ["client_counts"]
    )
    |> case do
      {:ok, counts} -> counts
      {:error, _} -> %{total: 0, active: 0}
    end
  end

  @doc """
  Invalidate the cached client counts.

  Call this when client data changes (create, update, delete).
  """
  def invalidate_counts do
    Logger.debug("Invalidating client counts cache")
    Cache.delete(:rbac_cache, :client_counts)
  end
end
