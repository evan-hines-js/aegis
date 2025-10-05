defmodule Aegis.MCP.PatternMatcher do
  @moduledoc """
  Utilities for pattern matching in RBAC authorization.

  Handles wildcard matching for server names and resource patterns
  used throughout the permission system.
  """

  @doc """
  Check if a server name matches a permission pattern.

  ## Examples

      iex> PatternMatcher.server_matches?("*", "any-server")
      true

      iex> PatternMatcher.server_matches?("github-server", "github-server")
      true

      iex> PatternMatcher.server_matches?("github-server", "other-server")
      false
  """
  @spec server_matches?(String.t(), String.t()) :: boolean()
  def server_matches?("*", _server_name), do: true
  def server_matches?(permission_server, server_name), do: permission_server == server_name

  @doc """
  Check if a resource pattern matches a permission pattern.

  ## Examples

      iex> PatternMatcher.resource_matches?("*", "any-resource")
      true

      iex> PatternMatcher.resource_matches?("create_issue", "create_issue")
      true

      iex> PatternMatcher.resource_matches?("create_issue", "delete_issue")
      false
  """
  @spec resource_matches?(String.t(), String.t()) :: boolean()
  def resource_matches?("*", _resource_pattern), do: true

  def resource_matches?(permission_pattern, resource_pattern),
    do: permission_pattern == resource_pattern

  @doc """
  Check if a permission entry matches the given criteria.

  ## Examples

      iex> permission = %{resource_type: :tools, server_name: "*", resource_pattern: "*", action: :call}
      iex> PatternMatcher.permission_matches?(permission, :tools, "any-server", "any-tool", :call)
      true
  """
  @spec permission_matches?(map(), atom(), String.t(), String.t(), atom()) :: boolean()
  def permission_matches?(permission, resource_type, server_name, resource_pattern, action) do
    permission.resource_type == resource_type and
      permission.action == action and
      server_matches?(permission.server_name, server_name) and
      resource_matches?(permission.resource_pattern, resource_pattern)
  end

  @doc """
  Validate server name and resource pattern combination for permissions.

  Returns :ok if valid, {:error, reason} if invalid.
  """
  @spec validate_permission_pattern(String.t(), String.t()) :: :ok | {:error, String.t()}
  def validate_permission_pattern(server_name, resource_pattern) do
    cond do
      server_name == "*" and resource_pattern != "*" ->
        {:error, "When server_name is '*', resource_pattern must also be '*'"}

      is_binary(server_name) and String.contains?(server_name, ["*", "?"]) and
          server_name != "*" ->
        {:error, "server_name can only be '*' or an exact server name"}

      true ->
        :ok
    end
  end
end
