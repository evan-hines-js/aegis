defmodule Aegis.MCP.Authorization do
  @moduledoc """
  High-level authorization interface for MCP client permission checking.

  Provides a clean, focused API for authorization decisions while delegating
  data access to PermissionStore and caching to PermissionCache.

  ## Examples

      # Basic permission checks
      {:ok, :authorized} = Authorization.can_call_tool?(client_id, "server", "tool")
      {:error, :permission_denied} = Authorization.can_read_resource?(client_id, "server", "resource")

      # Client validation and authentication
      {:ok, client} = Authorization.authenticate_client(api_key)
      {:ok, client} = Authorization.validate_client(client_id)

      # Permission management
      {:ok, permissions} = Authorization.get_client_permissions(client_id)
      :ok = Authorization.invalidate_client_permissions(client_id)
  """

  require Logger

  alias Aegis.Cache

  alias Aegis.MCP.{
    ApiKeyUtils,
    AuthorizationErrors,
    Namespace,
    PatternMatcher,
    PermissionStore
  }

  @type authorization_result :: AuthorizationErrors.authorization_result()
  @type client_result :: AuthorizationErrors.client_result()
  @type permissions_result :: AuthorizationErrors.permissions_result()

  # Core authorization checks

  @doc """
  Check if a client can call a specific tool.

  Options:
  - `:jwt_claims` - JWT claims for OAuth scope validation
  """
  @spec can_call_tool?(String.t(), String.t(), String.t(), keyword()) :: authorization_result()
  def can_call_tool?(client_id, server_name, tool_name, opts \\ []) do
    check_permission(client_id, :tools, server_name, tool_name, :call, opts)
  end

  @doc """
  Check client permission before allowing Hub to access backend on their behalf.

  This is the OAuth-compliant solution to Confused Deputy attacks:
  1. Hub validates client permission BEFORE using its own credentials
  2. Hub uses standard OAuth Client Credentials with backend
  3. Backend receives standard OAuth token (no changes required)

  This follows RFC 6749 by ensuring the Hub (authorization server intermediary)
  validates permissions before accessing resources on behalf of clients.

  ## SECURITY CRITICAL: Token Passthrough Prevention

  When the Hub makes requests to upstream MCP servers on behalf of a client:

  **FORBIDDEN (Token Passthrough):**
  ```
  Client --[token A]--> Hub --[token A]--> Upstream Server
  ```
  This is a security violation. Token A was issued for the Hub, not the upstream server.

  **REQUIRED (Separate Tokens):**
  ```
  Client --[token A]--> Hub
  Hub validates token A audience = Hub
  Hub checks client permissions
  Hub --[token B]--> Upstream Server
  ```
  Token B is obtained via OAuth client credentials flow with upstream server as audience.

  See RFC 8707 and MCP Security Best Practices for details.

  ## OAuth Scope Validation

  When called with JWT claims (OAuth authentication), this function also validates
  that the token contains the required OAuth scopes for the operation.
  """
  @spec check_permission(String.t(), atom(), String.t(), String.t(), atom(), keyword()) ::
          authorization_result()
  def check_permission(
        client_id,
        resource_type,
        server_name,
        resource_pattern,
        action,
        opts \\ []
      ) do
    jwt_claims = Keyword.get(opts, :jwt_claims)

    # OAuth-compliant authorization check at the Hub level
    with {:ok, _client} <- validate_client(client_id),
         :ok <- validate_oauth_scopes(jwt_claims, resource_type, action),
         {:ok, permissions} <- get_client_permissions(client_id),
         true <-
           has_matching_permission?(
             permissions,
             resource_type,
             server_name,
             resource_pattern,
             action
           ) do
      {:ok, :authorized}
    else
      false ->
        Logger.info(
          "Permission denied for client #{client_id}: #{resource_type}/#{server_name}/#{resource_pattern}:#{action}"
        )

        {:error, :permission_denied}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Check if a client can read a specific resource.

  Options:
  - `:jwt_claims` - JWT claims for OAuth scope validation
  """
  @spec can_read_resource?(String.t(), String.t(), String.t(), keyword()) ::
          authorization_result()
  def can_read_resource?(client_id, server_name, resource_uri, opts \\ []) do
    check_permission(client_id, :resources, server_name, resource_uri, :read, opts)
  end

  @doc """
  Check if a client can get a specific prompt.

  Options:
  - `:jwt_claims` - JWT claims for OAuth scope validation
  """
  @spec can_get_prompt?(String.t(), String.t(), String.t(), keyword()) :: authorization_result()
  def can_get_prompt?(client_id, server_name, prompt_name, opts \\ []) do
    check_permission(client_id, :prompts, server_name, prompt_name, :read, opts)
  end

  @doc """
  Check if a client can list resources of a specific type.
  """
  @spec can_list?(String.t(), atom(), String.t()) :: authorization_result()
  def can_list?(client_id, resource_type, server_name \\ "*")

  def can_list?(client_id, :tools, server_name) do
    check_permission(client_id, :tools, server_name, "*", :call)
  end

  def can_list?(client_id, resource_type, server_name)
      when resource_type in [:resources, :prompts] do
    check_permission(client_id, resource_type, server_name, "*", :read)
  end

  def can_list?(_client_id, resource_type, _server_name) do
    Logger.warning("Invalid resource type for listing: #{inspect(resource_type)}")
    {:error, :invalid_resource_type}
  end

  @doc """
  Check list permissions with proper wildcard handling.

  For list operations, always allow valid clients to list, but the actual filtering
  is done at the content level. This allows clients with no permissions to receive
  an empty list instead of an authorization error.
  """
  @spec check_list_permission(String.t(), atom(), String.t()) :: authorization_result()
  def check_list_permission(client_id, resource_type, _server_name \\ "*") do
    # First validate the client exists and is active
    case validate_client(client_id) do
      {:ok, _client} ->
        # For list operations, always allow valid/active clients to proceed
        # The actual permission filtering happens at the content level
        Logger.debug(
          "List permission granted for client #{client_id}: #{resource_type} (filtering will be applied)"
        )

        {:ok, :authorized}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Client management

  @doc """
  Validate that a client exists and is active using cache.
  """
  @spec validate_client(String.t()) :: client_result()
  def validate_client(client_id) do
    # Use cached client data to avoid DB hit on every request
    get_cached_client(client_id, &PermissionStore.validate_client/1)
  end

  @doc """
  Authenticate a client using their API key.
  """
  @spec authenticate_client(String.t()) :: client_result()
  def authenticate_client(api_key) when is_binary(api_key) do
    get_cached_client_by_api_key(api_key, &PermissionStore.find_client_by_api_key/1)
  end

  def authenticate_client(_), do: {:error, :invalid_api_key}

  @doc """
  Authenticate a client using a bearer token (API key only).

  Only API keys starting with 'ak_' are supported.
  """
  @spec authenticate_bearer_token(String.t()) :: client_result()
  def authenticate_bearer_token(token) when is_binary(token) do
    if String.starts_with?(token, "ak_") do
      authenticate_client(token)
    else
      {:error, :invalid_token}
    end
  end

  def authenticate_bearer_token(_), do: {:error, :invalid_token}

  @doc """
  Validate that a token belongs to the expected client without logging authentication events.

  This function is used for session validation where we need to verify that the
  provided token matches the expected client_id from the session. It uses the
  same cached lookup as authentication but does not log authentication events.

  Only API keys are supported. Returns {:ok, client_id} if the token is valid and belongs
  to the expected client, {:error, reason} otherwise.
  """
  @spec validate_token_for_client(String.t(), String.t()) ::
          {:ok, String.t()} | {:error, AuthorizationErrors.authorization_error()}
  def validate_token_for_client(token, expected_client_id)
      when is_binary(token) and is_binary(expected_client_id) do
    if String.starts_with?(token, "ak_") do
      validate_api_key_for_client(token, expected_client_id)
    else
      {:error, :invalid_token}
    end
  end

  def validate_token_for_client(_, _), do: {:error, :invalid_token}

  # Permission management

  @doc """
  Get all permissions for a client using intelligent caching.
  """
  @spec get_client_permissions(String.t()) :: permissions_result()
  def get_client_permissions(client_id) do
    start_time = System.monotonic_time()
    result = get_cached_permissions(client_id, &PermissionStore.get_client_permissions/1)
    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :authorization, :get_permissions],
      %{duration: duration},
      %{client_id: client_id}
    )

    result
  end

  @doc """
  Check multiple permissions for a client in a single operation.

  More efficient than multiple individual permission checks as it fetches
  permissions once and checks all requested permissions in memory.
  """
  @spec check_multiple_permissions(String.t(), [
          {atom(), String.t(), String.t(), atom()}
        ]) :: {:ok, [{boolean(), atom(), String.t(), String.t(), atom()}]} | {:error, term()}
  def check_multiple_permissions(client_id, permission_checks) do
    with {:ok, _client} <- validate_client(client_id),
         {:ok, permissions} <- get_client_permissions(client_id) do
      results = check_permissions_against_list(permission_checks, permissions)
      {:ok, results}
    end
  end

  defp check_permissions_against_list(permission_checks, permissions) do
    Enum.map(permission_checks, fn {resource_type, server_name, resource_pattern, action} ->
      has_permission =
        Enum.any?(permissions, fn permission ->
          PatternMatcher.permission_matches?(
            permission,
            resource_type,
            server_name,
            resource_pattern,
            action
          )
        end)

      {has_permission, resource_type, server_name, resource_pattern, action}
    end)
  end

  @doc """
  Force refresh of permissions for a client.
  """
  @spec refresh_client_permissions(String.t()) :: permissions_result()
  def refresh_client_permissions(client_id) do
    Logger.debug("Refreshing permissions for client #{client_id}")
    cache_key = {:permissions, client_id}

    case PermissionStore.get_client_permissions(client_id) do
      {:ok, permissions} ->
        Cache.put(:rbac_cache, cache_key, permissions,
          tags: ["client:#{client_id}", "permissions"]
        )

        {:ok, permissions}

      {:error, reason} ->
        normalized_error = AuthorizationErrors.normalize_error(reason)

        Logger.warning(
          "Failed to refresh permissions for client #{client_id}: #{normalized_error}"
        )

        {:error, normalized_error}
    end
  end

  @doc """
  Invalidate cached permissions for a client.
  """
  @spec invalidate_client_permissions(String.t()) :: :ok
  def invalidate_client_permissions(client_id) do
    cache_key = {:permissions, client_id}
    Cache.delete(:rbac_cache, cache_key)
    # Also invalidate using tags for more comprehensive clearing
    Cache.invalidate_by_tag(:rbac_cache, "client:#{client_id}")
    Logger.debug("Invalidated cached permissions for client #{client_id}")
    :ok
  end

  @doc """
  Invalidate all cached permissions.
  """
  @spec invalidate_all_permissions() :: :ok
  def invalidate_all_permissions do
    Cache.clear(:rbac_cache)
    Logger.info("Invalidated all cached permissions")
    :ok
  end

  @doc """
  Invalidate permission caches for all clients that have access to a specific server.

  This is important when a server is deleted to prevent cached permissions from
  causing SSE notifications to be sent for a new server with the same name.
  """
  @spec invalidate_permissions_for_server(String.t()) :: :ok
  def invalidate_permissions_for_server(server_name) do
    case PermissionStore.get_clients_with_server_access(server_name) do
      {:ok, client_ids} ->
        Enum.each(client_ids, &invalidate_client_permissions/1)

        Logger.info(
          "Invalidated permission caches for #{length(client_ids)} clients with access to server #{server_name}"
        )

        :ok

      {:error, reason} ->
        Logger.warning("Failed to get clients for server #{server_name}: #{inspect(reason)}")
        :ok
    end
  end

  @doc """
  Helper to log authorization attempts for auditing.
  """
  @spec log_authorization_attempt(
          String.t(),
          atom(),
          String.t(),
          String.t(),
          atom(),
          authorization_result()
        ) :: :ok
  def log_authorization_attempt(
        client_id,
        resource_type,
        server_name,
        resource_pattern,
        action,
        result
      ) do
    level =
      case result do
        {:ok, :authorized} -> :info
        {:error, _} -> :warning
      end

    # Only log authorization failures/denials, not successful authorizations
    case result do
      {:ok, :authorized} ->
        Logger.debug(
          "Authorization granted: client=#{client_id} server=#{server_name} resource=#{resource_type}/#{resource_pattern} action=#{action}"
        )

      {:error, reason} ->
        Logger.log(
          level,
          "Authorization denied: client=#{client_id} server=#{server_name} resource=#{resource_type}/#{resource_pattern} action=#{action} reason=#{reason}"
        )
    end
  end

  # Internal function for cache integration - delegates to PermissionStore
  @doc false
  def get_client_permissions_from_db(client_id) do
    PermissionStore.get_client_permissions(client_id)
  end

  # Private helper functions

  # Validate API key belongs to expected client without logging
  defp validate_api_key_for_client(api_key, expected_client_id) do
    result = get_cached_client_by_api_key(api_key, &PermissionStore.find_client_by_api_key/1)

    case result do
      {:ok, client} when client.id == expected_client_id -> {:ok, client.id}
      # Wrong client
      {:ok, _client} -> {:error, :invalid_api_key}
      {:error, reason} -> {:error, reason}
    end
  end

  # Check if permissions contain a matching permission using pattern matching
  defp has_matching_permission?(permissions, resource_type, server_name, resource_pattern, action) do
    Enum.any?(permissions, fn permission ->
      PatternMatcher.permission_matches?(
        permission,
        resource_type,
        server_name,
        resource_pattern,
        action
      )
    end)
  end

  # Validate OAuth scopes if JWT claims are present
  # OAuth removed - API key authentication only
  defp validate_oauth_scopes(_jwt_claims, _resource_type, _action) do
    :ok
  end

  @doc """
  Get list of servers a client has access to.

  Returns a list of server structs from the namespace registry.
  """
  @spec get_accessible_servers(String.t()) :: [map()]
  def get_accessible_servers(client_id) do
    case get_client_permissions(client_id) do
      {:ok, permissions} ->
        permissions
        |> extract_unique_server_names()
        |> fetch_server_details()

      {:error, _reason} ->
        []
    end
  end

  defp extract_unique_server_names(permissions) do
    permissions
    |> Enum.map(& &1.server_name)
    |> Enum.filter(&(&1 != "*"))
    |> Enum.uniq()
  end

  defp fetch_server_details(server_names) do
    server_names
    |> Enum.flat_map(&fetch_server_by_name/1)
    |> Enum.filter(&server_healthy?/1)
  end

  defp fetch_server_by_name(name) do
    case Namespace.find_server_by_name(name) do
      {:ok, server} -> [server]
      {:error, _} -> []
    end
  end

  defp server_healthy?(server) do
    circuit_breaker_allows?(server) && cache_health_allows?(server)
  end

  defp circuit_breaker_allows?(server) do
    alias Aegis.MCP.CircuitBreaker

    case CircuitBreaker.allow_request?(server.endpoint) do
      :allow -> true
      {:deny, _reason} -> false
    end
  end

  defp cache_health_allows?(server) do
    cache_key = {:server, server.name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, cached_info} when not is_nil(cached_info) ->
        Map.get(cached_info, :status, :unknown) != :unhealthy

      _ ->
        # If no cache info, allow the request (server might be new)
        true
    end
  end

  # Cache helper functions (replaces PermissionCache module)

  defp get_cached_permissions(client_id, fetch_fn) when is_function(fetch_fn, 1) do
    cache_key = {:permissions, client_id}

    Cache.fetch_or_cache(
      :rbac_cache,
      cache_key,
      fn ->
        case fetch_fn.(client_id) do
          {:ok, permissions} ->
            {:ok, permissions}

          {:error, reason} ->
            normalized_error = AuthorizationErrors.normalize_error(reason)

            Logger.warning(
              "Failed to fetch permissions for client #{client_id}: #{normalized_error}"
            )

            {:error, normalized_error}
        end
      end,
      tags: ["client:#{client_id}", "permissions"]
    )
  end

  defp get_cached_client_by_api_key(api_key, fetch_fn) when is_function(fetch_fn, 1) do
    api_key_lookup_hash = ApiKeyUtils.lookup_hash(api_key)
    cache_key = {:api_key, api_key_lookup_hash}

    Cache.fetch_or_cache(
      :rbac_cache,
      cache_key,
      fn ->
        case fetch_fn.(api_key) do
          {:ok, client} ->
            {:ok, client}

          {:error, reason} ->
            normalized_error = AuthorizationErrors.normalize_error(reason)
            Logger.warning("Failed to fetch client for API key: #{normalized_error}")
            {:error, normalized_error}
        end
      end,
      tags: ["api_keys"]
    )
  end

  defp get_cached_client(client_id, fetch_fn) when is_function(fetch_fn, 1) do
    cache_key = {:client, client_id}

    Cache.fetch_or_cache(
      :rbac_cache,
      cache_key,
      fn -> fetch_fn.(client_id) end
      # No TTL - rely on explicit invalidation
    )
  end
end
