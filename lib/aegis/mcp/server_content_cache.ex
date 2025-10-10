defmodule Aegis.MCP.ServerContentCache do
  @moduledoc """
  Caches tools, resources, and prompts from MCP servers.

  Provides intelligent caching with SSE monitoring for supported servers
  and polling fallback for others. Handles cache invalidation based on
  server notifications.
  """

  require Logger
  alias Aegis.Cache
  alias Aegis.MCP.{CapabilityAggregator, ContentTypes, ServerClient}

  @type server :: %{name: String.t(), endpoint: String.t()}
  @type content_type :: :tools | :resources | :prompts | :resource_templates
  @type cache_result :: {:ok, list()} | {:error, term()}

  @doc """
  Gets cached content for a server and content type.

  If not cached, fetches from the server and caches the result.
  """
  @spec get_content(server(), content_type()) :: cache_result()
  def get_content(server, content_type) do
    cache_key = {server.name, content_type}

    Cache.fetch_or_cache(
      :mcp_meta_cache,
      cache_key,
      fn -> fetch_content_from_server(server, content_type) end,
      tags: ["server:#{server.name}", "content_type:#{content_type}"]
    )
  end

  @doc """
  Forces a refresh of content for a server and content type.
  """
  @spec refresh_content(server(), content_type()) :: cache_result()
  def refresh_content(server, content_type) do
    Logger.debug("Refreshing #{content_type} for #{server.name}")
    cache_key = {server.name, content_type}

    with {:ok, content} <- fetch_content_from_server(server, content_type) do
      Cache.put(:mcp_meta_cache, cache_key, content,
        tags: ["server:#{server.name}", "content_type:#{content_type}"]
      )

      {:ok, content}
    end
  end

  @doc """
  Invalidates cached content for a server and content type.
  """
  @spec invalidate_content(server(), content_type()) :: :ok
  def invalidate_content(server, content_type) do
    cache_key = {server.name, content_type}
    Cache.delete(:mcp_meta_cache, cache_key)
    :ok
  end

  @doc """
  Invalidates all cached content for a server.
  """
  @spec invalidate_server_content(server()) :: :ok
  def invalidate_server_content(server) do
    Cache.invalidate_by_tag(:mcp_meta_cache, "server:#{server.name}")
    :ok
  end

  @doc """
  Invalidates all cached content for all servers.

  Useful when client permissions change and we need to ensure fresh content
  is fetched for the next request.

  NOTE: This only clears content cache entries, not ServerRegistry or other cache data.
  """
  @spec invalidate_all_content :: :ok
  def invalidate_all_content do
    # Clear only content-related cache entries, not the entire table
    content_tags = [
      "content_type:tools",
      "content_type:resources",
      "content_type:prompts",
      "content_type:resource_templates"
    ]

    Enum.each(content_tags, fn tag ->
      Cache.invalidate_by_tag(:mcp_meta_cache, tag)
    end)

    :ok
  end

  @doc """
  Gets all cached content for servers that support a specific capability.
  """
  @spec get_content_for_capability(String.t(), content_type()) :: list()
  def get_content_for_capability(capability_type, content_type) do
    servers =
      ServerClient.get_healthy_servers()
      |> CapabilityAggregator.servers_with_capability(capability_type)

    servers
    |> Task.async_stream(&get_content(&1, content_type),
      max_concurrency: 10,
      timeout: 5000
    )
    |> Enum.flat_map(fn
      {:ok, {:ok, content}} -> content
      _ -> []
    end)
  end

  @doc """
  Checks if a server's content is stale and needs refreshing.
  """
  @spec content_stale?(server(), content_type(), non_neg_integer() | nil) :: boolean()
  def content_stale?(server, content_type, _max_age_ms \\ nil) do
    cache_key = {server.name, content_type}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, nil} ->
        true

      {:ok, _content} ->
        false

      {:error, _} ->
        true
    end
  end

  @doc """
  Preloads content for all healthy servers.
  """
  @spec preload_all_content() :: :ok
  def preload_all_content do
    servers = ServerClient.get_healthy_servers()
    content_types = ContentTypes.all_content_types()

    Logger.info("Preloading content for #{length(servers)} servers")

    servers
    |> Task.async_stream(
      fn server ->
        content_types
        |> Enum.each(&get_content(server, &1))
      end,
      max_concurrency: 5,
      timeout: 10_000
    )
    |> Stream.run()

    :ok
  end

  @doc """
  Gets comprehensive cache statistics.
  """
  @spec get_cache_stats() :: map()
  def get_cache_stats do
    # Get unified cache stats for MCP metadata cache
    cache_stats = Cache.stats(:mcp_meta_cache)

    # Get server health info
    healthy_servers = ServerClient.get_healthy_servers()

    %{
      overview: %{
        total_cache_entries: cache_stats.size,
        total_servers: length(healthy_servers)
      },
      cache_stats: cache_stats,
      healthy_servers: length(healthy_servers)
    }
  end

  # Private functions

  defp fetch_content_from_server(server, content_type) do
    # Check if server supports this content type before trying to fetch
    required_capability = ContentTypes.content_type_to_capability(content_type)

    if CapabilityAggregator.supports_capability?(server, required_capability) do
      {method, result_key} = ContentTypes.content_type_to_method_and_key(content_type)

      content = ServerClient.fetch_list(server, method, result_key)
      {:ok, content}
    else
      Logger.debug(
        "Server #{server.name} does not support #{required_capability}, skipping #{content_type}"
      )

      {:ok, []}
    end
  end
end
