defmodule Aegis.Cache do
  @moduledoc """
  Distributed cache wrapper around Cachex.

  Provides basic caching with distributed invalidation via PubSub.
  No complex features like quorum, versioning, or conflict resolution.

  ## Cache Tables

  - `:rbac_cache` - Permissions and client auth data (5 min TTL, 10k entry limit)
  - `:mcp_meta_cache` - Server content (tools, resources, prompts) (no TTL, 10k entry limit)
  - `:mcp_sessions` - Active MCP sessions (no TTL, 300k entry limit)
  - `:circuit_breaker_cache` - Circuit breaker counters (10 min TTL, 1k entry limit)

  ## Cache Eviction Policies

  ### TTL-Based Eviction
  - **RBAC Cache**: 5-minute TTL for permissions and client data
  - **MCP Meta Cache**: No automatic TTL (manual invalidation only)
  - **MCP Sessions**: No TTL (SessionManager handles inactive cleanup every 5 min)
  - TTL is refreshed on cache writes, not on reads

  ### Size-Based Eviction
  - RBAC and Meta caches have a 10,000 entry limit
  - Sessions cache has a 300,000 entry limit (safety net only)
  - When limit is reached, Cachex uses LRW (Least Recently Written) eviction
  - Eviction happens automatically on writes when cache is full
  - Primary session cleanup handled by SessionManager, not cache eviction

  ### Manual Invalidation
  - Tag-based invalidation for bulk operations (O(1) via ETS tag index)
  - Single-key deletion for targeted invalidation
  - Clear-all for maintenance operations

  ## Distributed Invalidation

  All invalidation operations (delete, invalidate_by_tag, clear) are broadcast
  to all cluster nodes via Phoenix.PubSub, ensuring cache consistency across
  the distributed system.

  ## Usage

      # Get unwrapped value
      {:ok, perms} = Cache.get(:rbac_cache, {:permissions, "client-id"})

      # Put with optional TTL
      Cache.put(:rbac_cache, key, value, ttl: :timer.minutes(5))

      # Delete single key (broadcasts to all nodes)
      Cache.delete(:mcp_meta_cache, key)

      # Tag-based invalidation (broadcasts to all nodes)
      Cache.invalidate_by_tag(:mcp_meta_cache, "server:my-server")

      # Clear entire cache (broadcasts to all nodes)
      Cache.clear(:rbac_cache)
  """

  use Supervisor
  require Logger

  alias Phoenix.PubSub

  @pubsub Aegis.PubSub
  @tables [:rbac_cache, :mcp_meta_cache, :mcp_sessions, :circuit_breaker_cache]

  # Client API

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get value from cache, unwrapping from internal format.

  Returns {:ok, value} if found (unwrapped), {:ok, nil} if not found, or {:error, reason}.
  """
  @spec get(atom(), term()) :: {:ok, term()} | {:error, term()}
  def get(table, key) do
    start_time = System.monotonic_time()

    result =
      case Cachex.get(table, key) do
        {:ok, nil} ->
          {:ok, nil}

        {:ok, %{value: value}} ->
          {:ok, value}

        # Backwards compat - if not wrapped, return as-is
        {:ok, value} ->
          {:ok, value}

        {:error, reason} ->
          {:error, reason}
      end

    duration = System.monotonic_time() - start_time
    hit_or_miss = if elem(result, 1) == nil, do: :miss, else: :hit

    :telemetry.execute(
      [:aegis, :cache, :get],
      %{duration: duration},
      %{table: table, result: hit_or_miss}
    )

    result
  end

  @doc """
  Put value in cache with optional TTL and tags.

  ## Options
    * `:ttl` - Time to live in milliseconds (default: no expiration)
    * `:tags` - List of tags for group invalidation (default: [])

  ## Examples

      Cache.put(:rbac_cache, key, value)
      Cache.put(:rbac_cache, key, value, ttl: :timer.minutes(5), tags: ["client:123"])
  """
  @spec put(atom(), term(), term(), keyword()) :: :ok | {:error, term()}
  def put(table, key, value, opts \\ []) do
    ttl = Keyword.get(opts, :ttl)
    tags = Keyword.get(opts, :tags, [])

    # Wrap value with tags for invalidation support
    wrapped_value = %{value: value, tags: tags}

    cachex_opts = if ttl, do: [ttl: ttl], else: []

    case Cachex.put(table, key, wrapped_value, cachex_opts) do
      {:ok, true} ->
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Fetch from cache or execute function if not cached.

  Implements the cache-aside pattern: checks cache first, and if not found or error,
  executes the fetch function and caches the result.

  ## Options
    * `:ttl` - Time to live in milliseconds (default: no expiration)
    * `:tags` - List of tags for group invalidation (default: [])

  ## Examples

      # Fetch permissions with caching
      Cache.fetch_or_cache(
        :rbac_cache,
        {:permissions, client_id},
        fn -> fetch_permissions(client_id) end,
        ttl: :timer.minutes(5),
        tags: ["client:\#{client_id}"]
      )

      # Fetch server content with caching
      Cache.fetch_or_cache(
        :mcp_meta_cache,
        {server_name, :tools},
        fn -> ServerClient.fetch_list(server, "tools/list", "tools") end,
        tags: ["server:\#{server_name}"]
      )
  """
  @spec fetch_or_cache(atom(), term(), (-> {:ok, term()} | {:error, term()}), keyword()) ::
          {:ok, term()} | {:error, term()}
  def fetch_or_cache(table, key, fetch_fn, opts \\ []) when is_function(fetch_fn, 0) do
    case get(table, key) do
      {:ok, nil} ->
        fetch_and_cache(table, key, fetch_fn, opts)

      {:ok, value} ->
        {:ok, value}

      {:error, _reason} ->
        # Cache error - fetch from source
        fetch_and_cache(table, key, fetch_fn, opts)
    end
  end

  defp fetch_and_cache(table, key, fetch_fn, opts) do
    case fetch_fn.() do
      {:ok, value} ->
        put(table, key, value, opts)
        {:ok, value}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Delete key from cache and broadcast to other nodes.
  """
  @spec delete(atom(), term()) :: :ok
  def delete(table, key) do
    Cachex.del(table, key)

    # Broadcast to other nodes
    PubSub.broadcast(@pubsub, cache_channel(table), {:cache_delete, key})

    :ok
  end

  @doc """
  Invalidate all cache entries with a specific tag.

  PERFORMANCE: Processes stream incrementally without materializing.
  Avoids GC pause with large caches (10k+ entries).
  """
  @spec invalidate_by_tag(atom(), String.t()) :: :ok
  def invalidate_by_tag(table, tag) do
    # Process stream incrementally - don't materialize into list
    case Cachex.stream(table) do
      {:ok, stream} ->
        deleted_count =
          stream
          |> Stream.filter(&entry_has_tag?(&1, tag))
          |> Stream.map(&extract_key/1)
          |> Stream.each(&Cachex.del(table, &1))
          |> Enum.count()

        Logger.debug("Invalidated #{deleted_count} entries with tag: #{tag} from #{table}")

      {:error, reason} ->
        Logger.error("Failed to scan cache #{table} for tag #{tag}: #{inspect(reason)}")
    end

    # Broadcast to other nodes
    PubSub.broadcast(@pubsub, cache_channel(table), {:cache_invalidate_tag, tag})

    :ok
  end

  @doc """
  Clear entire cache table and broadcast to other nodes.
  """
  @spec clear(atom()) :: :ok
  def clear(table) do
    Cachex.clear(table)

    # Broadcast to other nodes
    PubSub.broadcast(@pubsub, cache_channel(table), :cache_clear_all)

    :ok
  end

  @doc """
  Get cache statistics.
  """
  @spec stats(atom()) :: map()
  def stats(table) do
    case Cachex.stats(table) do
      {:ok, %{hits: hits, misses: misses}} ->
        total = hits + misses
        hit_rate = if total > 0, do: hits / total, else: 0.0

        %{
          table: table,
          size: Cachex.size!(table),
          hits: hits,
          misses: misses,
          hit_rate: hit_rate
        }

      _ ->
        %{table: table, size: Cachex.size!(table)}
    end
  end

  # Supervisor Callbacks

  @impl true
  def init(_opts) do
    # Create Cachex children specs with table-specific configurations
    cachex_children =
      Enum.map(@tables, fn table ->
        config = cache_config(table)

        Supervisor.child_spec(
          {Cachex, config},
          id: {Cachex, table}
        )
      end)

    # Start the GenServer for PubSub handling
    pubsub_handler = {Aegis.Cache.PubSubHandler, @tables}

    children = cachex_children ++ [pubsub_handler]

    Supervisor.init(children, strategy: :one_for_one)
  end

  # Configure cache settings per table
  defp cache_config(:mcp_sessions) do
    [
      name: :mcp_sessions,
      # High limit as safety net to prevent unbounded growth
      # Uses LRW (Least Recently Written - default) which only updates on writes
      # Primary cleanup handled by SessionManager (checks every 5 min)
      limit: 300_000,
      stats: true
    ]
  end

  defp cache_config(:circuit_breaker_cache) do
    [
      name: :circuit_breaker_cache,
      # Low limit since circuit breakers are per endpoint
      limit: 1_000,
      stats: true
    ]
  end

  defp cache_config(:rbac_cache) do
    [
      name: :rbac_cache,
      # Higher limit for permissions/auth cache
      # Uses default LRW policy (only updates on writes, not reads)
      limit: 50_000,
      stats: true
    ]
  end

  defp cache_config(table) do
    [name: table, limit: 10_000, stats: true]
  end

  # Private Functions

  defp cache_channel(table), do: "cache:#{table}"

  defp entry_has_tag?({:entry, _key, %{tags: tags}, _timestamp, _ttl}, tag), do: tag in tags
  defp entry_has_tag?({:entry, _key, _metadata, _timestamp, _ttl}, _tag), do: false

  defp extract_key({:entry, key, _metadata, _timestamp, _ttl}), do: key
end

defmodule Aegis.Cache.PubSubHandler do
  @moduledoc false
  use GenServer
  require Logger

  alias Phoenix.PubSub

  @pubsub Aegis.PubSub

  def start_link(tables) do
    GenServer.start_link(__MODULE__, tables, name: __MODULE__)
  end

  @impl true
  def init(tables) do
    # Subscribe to PubSub channels for distributed invalidation
    Enum.each(tables, fn table ->
      PubSub.subscribe(@pubsub, cache_channel(table))
    end)

    Logger.info("Cache.PubSubHandler started, subscribed to #{length(tables)} cache channels")

    {:ok, %{tables: tables}}
  end

  @impl true
  def handle_info({:cache_delete, key}, state) do
    # Received delete from another node - don't need to broadcast again
    Enum.each(state.tables, fn table ->
      Cachex.del(table, key)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info({:cache_invalidate_tag, tag}, state) do
    # Received tag invalidation from another node
    Enum.each(state.tables, &invalidate_table_by_tag(&1, tag))
    {:noreply, state}
  end

  @impl true
  def handle_info(:cache_clear_all, state) do
    # Received clear all from another node
    Enum.each(state.tables, fn table ->
      Cachex.clear(table)
    end)

    {:noreply, state}
  end

  defp invalidate_table_by_tag(table, tag) do
    case Cachex.stream(table) do
      {:ok, stream} ->
        # Process incrementally - Stream.each + Enum.count avoids materialization
        stream
        |> Stream.filter(&entry_has_tag?(&1, tag))
        |> Stream.map(&extract_key/1)
        |> Stream.each(&Cachex.del(table, &1))
        |> Stream.run()

      _ ->
        :ok
    end
  end

  defp entry_has_tag?({:entry, _key, %{tags: tags}, _timestamp, _ttl}, tag), do: tag in tags
  defp entry_has_tag?({:entry, _key, _metadata, _timestamp, _ttl}, _tag), do: false

  defp extract_key({:entry, key, _metadata, _timestamp, _ttl}), do: key

  defp cache_channel(table), do: "cache:#{table}"
end
