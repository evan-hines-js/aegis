defmodule Aegis.MCP.CapabilityAggregator do
  @moduledoc """
  Aggregates and manages capabilities from multiple MCP servers.

  Handles capability caching, merging, and the listChanged forcing logic.
  """

  require Logger
  alias Aegis.Cache
  alias Aegis.MCP.{ProtocolDiscovery, ServerClient}

  @doc "Aggregate capabilities from all healthy servers"
  def aggregate_capabilities do
    servers = ServerClient.get_healthy_servers()
    aggregate_capabilities(servers)
  end

  @doc "Aggregate capabilities from a specific list of servers"
  def aggregate_capabilities(servers) when is_list(servers) do
    Logger.info("Aggregating capabilities from #{length(servers)} servers")

    aggregated_capabilities =
      servers
      |> Enum.map(&get_server_capabilities/1)
      |> Enum.reduce(%{}, &merge_capabilities/2)

    Logger.info("Aggregated capabilities: #{inspect(aggregated_capabilities)}")

    if map_size(aggregated_capabilities) == 0 do
      %{}
    else
      aggregated_capabilities
    end
  end

  @doc "Get or fetch capabilities for a specific server with caching"
  def get_server_capabilities(server) do
    case ProtocolDiscovery.get_protocol_version(server) do
      {:ok, protocol_version} ->
        get_server_capabilities(server, protocol_version)

      {:error, reason} ->
        Logger.warning(
          "Failed to discover protocol version for #{server.name}: #{inspect(reason)}"
        )

        %{}
    end
  end

  @doc "Get capabilities for a specific server with known protocol version from cache"
  def get_server_capabilities(server, protocol_version) do
    cache_key = {server.name, protocol_version}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, capabilities} when not is_nil(capabilities) ->
        Logger.debug(
          "Using cached capabilities for #{server.name} with protocol #{protocol_version}"
        )

        capabilities

      _ ->
        # Cache miss - ServerMonitor will populate this during health checks
        Logger.debug(
          "No cached capabilities for #{server.name} yet (will be populated by health check)"
        )

        %{}
    end
  end

  # Private functions

  defp merge_capabilities(server_capabilities, aggregated) do
    merged =
      Map.merge(aggregated, server_capabilities, fn _key, existing, new ->
        # For nested maps like tools: %{listChanged: false}, merge them
        case {existing, new} do
          {%{} = existing_map, %{} = new_map} ->
            Map.merge(existing_map, new_map)

          {_, new_value} ->
            new_value
        end
      end)

    # Always force listChanged: true for all capability categories
    force_list_changed_capabilities(merged)
  end

  defp force_list_changed_capabilities(capabilities) do
    capabilities
    |> maybe_force_list_changed("tools")
    |> maybe_force_list_changed("resources")
    |> maybe_force_list_changed("prompts")
  end

  defp maybe_force_list_changed(capabilities, key) when is_map(capabilities) do
    case Map.get(capabilities, key) do
      nil ->
        capabilities

      value when is_map(value) ->
        Map.put(capabilities, key, Map.put(value, "listChanged", true))

      _ ->
        capabilities
    end
  end

  # Database helpers for hybrid caching

  @doc "Load capabilities from database cache (does not call MCP servers)"
  def load_capabilities_from_db(server_name) do
    case Aegis.MCP.get_server_by_name(server_name) do
      {:ok, server} -> server.capabilities || %{}
      {:error, _} -> %{}
    end
  rescue
    _ -> %{}
  end

  @doc "Filter servers that support a specific capability"
  def servers_with_capability(servers, capability_type) do
    Enum.filter(servers, fn server ->
      supports_capability?(server, capability_type)
    end)
  end

  @doc "Check if a server supports a specific capability"
  def supports_capability?(server, capability_type) do
    # Check capabilities across all supported protocol versions
    alias Aegis.MCP.Constants

    Constants.supported_protocol_versions()
    |> Enum.any?(&has_capability_for_version?(server, &1, capability_type))
  end

  defp has_capability_for_version?(server, protocol_version, capability_type) do
    cache_key = {server.name, protocol_version}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, capabilities} when not is_nil(capabilities) ->
        capability_present?(Map.get(capabilities, capability_type))

      _ ->
        false
    end
  end

  defp capability_present?(%{}), do: true
  defp capability_present?(_), do: false
end
