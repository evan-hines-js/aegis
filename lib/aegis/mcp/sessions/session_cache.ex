defmodule Aegis.MCP.SessionCache do
  @moduledoc """
  Cachex-based session store.

  Stores complete session state:
  - client_id: Client identifier
  - owner_node: Node where session process lives
  - backend_sessions: Map of server_name => backend_session_id
  - pagination_tokens: Map of hub_cursor => token_data
  - client_capabilities: Client MCP capabilities
  - resource_subscriptions: Set of subscribed resource URIs
  - initialized: Whether MCP handshake completed
  - log_level: Session logging level
  - created_at: Session creation timestamp
  - last_activity: Last activity timestamp

  Cleanup handled by SessionManager (checks every 5 minutes).
  Cachex limit (300k) acts as safety net to prevent unbounded growth.
  """

  require Logger
  alias Aegis.Cache

  @table_name :mcp_sessions
  # No TTL - rely on SessionManager for inactive session cleanup
  @session_ttl nil

  @type session_data :: %{
          client_id: String.t(),
          owner_node: node(),
          backend_sessions: map(),
          pagination_tokens: map(),
          client_capabilities: map(),
          resource_subscriptions: MapSet.t(),
          initialized: boolean(),
          log_level: atom(),
          created_at: DateTime.t(),
          last_activity: DateTime.t()
        }

  ## Client API

  @doc """
  Store complete session data in cache.
  Called by Session GenServer on all state changes.
  """
  @spec put(String.t(), session_data()) :: :ok
  def put(session_id, session_data) when is_map(session_data) do
    Cache.put(@table_name, session_id, session_data, ttl: @session_ttl)
  end

  @doc """
  Get complete session data from cache.
  Returns {:ok, session_data} or {:error, :not_found}
  """
  @spec get(String.t()) :: {:ok, session_data()} | {:error, :not_found}
  def get(session_id) do
    case Cache.get(@table_name, session_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, session_data} -> {:ok, session_data}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Update session data using a custom update function.
  Automatically updates last_activity timestamp.

  ## Examples

      # Update a field
      update_session(session_id, fn data -> Map.put(data, :initialized, true) end)

      # Update nested map
      update_session(session_id, fn data ->
        Map.update(data, :backend_sessions, %{}, &Map.put(&1, server_name, session_id))
      end)

      # Add to set
      update_session(session_id, fn data ->
        Map.update(data, :resource_subscriptions, MapSet.new(), &MapSet.put(&1, uri))
      end)
  """
  @spec update_session(String.t(), (session_data() -> session_data())) ::
          {:ok, session_data()} | {:error, :not_found}
  def update_session(session_id, update_fn) when is_function(update_fn, 1) do
    case get(session_id) do
      {:ok, session_data} ->
        updated_data =
          session_data
          |> update_fn.()
          |> Map.put(:last_activity, DateTime.utc_now())

        put(session_id, updated_data)
        {:ok, updated_data}

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Delete session from cache.
  Called by Session GenServer when session terminates.
  """
  @spec delete(String.t()) :: :ok
  def delete(session_id) do
    Cache.delete(@table_name, session_id)
  end

  @doc """
  List all session IDs for a given client.
  """
  @spec list_sessions_for_client(String.t()) :: [String.t()]
  def list_sessions_for_client(client_id) do
    case Cachex.stream(@table_name) do
      {:ok, stream} ->
        stream
        |> Stream.filter(fn {:entry, _key, metadata, _timestamp, _ttl} ->
          match?(%{value: %{client_id: ^client_id}}, metadata)
        end)
        |> Stream.map(fn {:entry, key, _metadata, _timestamp, _ttl} -> key end)
        |> Enum.to_list()

      {:error, _reason} ->
        []
    end
  end

  @doc """
  List all active sessions with their data.
  """
  @spec list_all_sessions() :: [%{id: String.t(), data: session_data()}]
  def list_all_sessions do
    case Cachex.stream(@table_name) do
      {:ok, stream} ->
        stream
        |> Stream.map(fn {:entry, key, %{value: data}, _timestamp, _ttl} ->
          %{id: key, data: data}
        end)
        |> Enum.to_list()

      {:error, _reason} ->
        []
    end
  end

  @doc """
  Get specific field from session data without loading everything.
  """
  @spec get_field(String.t(), atom()) :: {:ok, any()} | {:error, :not_found}
  def get_field(session_id, field) do
    case get(session_id) do
      {:ok, session_data} -> {:ok, Map.get(session_data, field)}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  @doc """
  Get nested value from map field.
  """
  @spec get_nested(String.t(), atom(), any()) :: {:ok, any()} | {:error, :not_found}
  def get_nested(session_id, map_field, key) do
    case get(session_id) do
      {:ok, session_data} ->
        nested_map = Map.get(session_data, map_field, %{})
        {:ok, Map.get(nested_map, key)}

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end
end
