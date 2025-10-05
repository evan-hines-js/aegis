defmodule Aegis.MCP.ResourceFilter do
  @moduledoc """
  Shared utilities for filtering MCP resources (tools, resources, prompts) based on permissions.

  PERFORMANCE: Provides both list-based and per-item filter functions.
  Per-item functions are optimized for Stream pipelines to reduce allocations.
  """

  alias Aegis.MCP.{Namespace, PatternMatcher}

  @doc """
  Filter resources by permissions, checking both server access and resource patterns.
  """
  def filter_by_permissions(items, permissions, resource_type, name_extractor) do
    Enum.filter(items, fn item ->
      item_has_permission?(item, permissions, resource_type, name_extractor)
    end)
  end

  @doc """
  Check if a single item passes permission check (optimized for Stream.filter).
  """
  def item_has_permission?(item, permissions, resource_type, name_extractor) do
    case extract_server_and_name(item, name_extractor, resource_type) do
      {:ok, server_name, resource_name} ->
        has_permission?(permissions, resource_type, server_name, resource_name)

      {:error, _} ->
        false
    end
  end

  @doc """
  Extract accessible servers from permissions for a given resource type.
  """
  def get_accessible_servers(permissions, resource_type) do
    permissions
    |> Enum.filter(fn permission ->
      permission.resource_type == resource_type
    end)
    |> Enum.map(& &1.server_name)
    |> Enum.uniq()
  end

  @doc """
  Filter items by accessible servers.
  """
  def filter_by_servers(items, accessible_servers, name_extractor, resource_type) do
    if "*" in accessible_servers do
      items
    else
      Enum.filter(items, &item_accessible?(&1, accessible_servers, name_extractor, resource_type))
    end
  end

  @doc """
  Check if a single item is accessible (optimized for Stream.filter).
  """
  def item_accessible?(item, accessible_servers, name_extractor, resource_type) do
    case extract_server_name(item, name_extractor, resource_type) do
      {:ok, server_name} -> server_name in accessible_servers
      {:error, _} -> false
    end
  end

  # Private functions

  defp extract_server_and_name(item, name_extractor, resource_type) do
    case name_extractor.(item) do
      name when is_binary(name) ->
        parse_namespaced_name(name, resource_type)

      _ ->
        {:error, :invalid_name}
    end
  end

  defp extract_server_name(item, name_extractor, resource_type) do
    case extract_server_and_name(item, name_extractor, resource_type) do
      {:ok, server_name, _resource_name} -> {:ok, server_name}
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_namespaced_name(name, :resources) do
    # Resources use URI format with "://" separator
    Namespace.parse_namespaced_uri(name)
  end

  defp parse_namespaced_name(name, _resource_type) do
    # Tools and prompts use name format with "__" separator
    Namespace.parse_namespaced_tool(name)
  end

  defp has_permission?(permissions, resource_type, server_name, resource_name) do
    Enum.any?(permissions, fn permission ->
      permission.resource_type == resource_type and
        server_matches?(permission.server_name, server_name) and
        resource_matches?(permission.resource_pattern, resource_name)
    end)
  end

  defp server_matches?(permission_server, actual_server) do
    permission_server == "*" or permission_server == actual_server
  end

  defp resource_matches?(permission_pattern, actual_resource) do
    PatternMatcher.resource_matches?(permission_pattern, actual_resource)
  end
end
