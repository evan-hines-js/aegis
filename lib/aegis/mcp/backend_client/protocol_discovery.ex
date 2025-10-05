defmodule Aegis.MCP.ProtocolDiscovery do
  @moduledoc """
  Discovers the best MCP protocol version supported by a server.

  This module automatically determines which protocol version to use
  when communicating with MCP servers by attempting to initialize
  with different protocol versions, starting from the most recent.
  """

  require Logger
  alias Aegis.Cache
  alias Aegis.MCP.{Constants, ServerClient}

  @type server :: %{name: String.t(), endpoint: String.t()}
  @type discovery_result :: {:ok, String.t()} | {:error, term()}

  @doc """
  Discovers the best supported protocol version for a server.

  Attempts to initialize with each supported protocol version,
  starting from the most recent, until one succeeds.

  Returns the first version that successfully initializes.
  """
  @spec discover_protocol_version(server()) :: discovery_result()
  def discover_protocol_version(server) do
    supported_versions = Constants.supported_protocol_versions()

    Logger.debug("Discovering protocol version for server #{server.name}")
    Logger.debug("Trying versions: #{inspect(supported_versions)}")

    try_versions(server, supported_versions)
  end

  @doc """
  Gets the cached protocol version for a server, or discovers it if not cached.

  Uses ETS cache keyed by server name to avoid repeated discovery attempts.
  """
  @spec get_protocol_version(server()) :: discovery_result()
  def get_protocol_version(server) do
    # Check if server is healthy before attempting discovery
    # This prevents multiple slow connection attempts to known-down servers
    cache_key = {:server, server.name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, server_info} when not is_nil(server_info) ->
        case Map.get(server_info, :status, :unknown) do
          :unhealthy ->
            Logger.debug("Skipping protocol discovery for unhealthy server #{server.name}")
            {:error, :server_unhealthy}

          :healthy ->
            # Server is healthy, proceed with discovery
            get_cached_or_discover(server)

          :unknown ->
            # Server status unknown, attempt discovery anyway
            Logger.info("Server #{server.name} status unknown, attempting protocol discovery")
            get_cached_or_discover(server)
        end

      _ ->
        # Server not in cache, attempt discovery anyway
        Logger.info("Server #{server.name} not in cache, attempting protocol discovery")
        get_cached_or_discover(server)
    end
  end

  defp get_cached_or_discover(server) do
    cache_key = {:protocol_version, server.name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, version} when not is_nil(version) ->
        Logger.debug("Using cached protocol version #{version} for #{server.name}")
        {:ok, version}

      {:ok, nil} ->
        discover_and_cache(server, cache_key)

      {:error, _} ->
        discover_and_cache(server, cache_key)
    end
  end

  defp discover_and_cache(server, cache_key) do
    case discover_protocol_version(server) do
      {:ok, version} = result ->
        Cache.put(:mcp_meta_cache, cache_key, version,
          tags: ["server:#{server.name}:capabilities", "protocol_version"]
        )

        result

      error ->
        error
    end
  end

  @doc """
  Clears the cached protocol version for a server.

  Useful when a server is updated or when you want to re-discover the protocol version.
  """
  @spec clear_cached_version(server()) :: :ok
  def clear_cached_version(server) do
    cache_key = {:protocol_version, server.name}
    Cache.delete(:mcp_meta_cache, cache_key)
    :ok
  end

  # Private functions

  defp try_versions(_server, []) do
    {:error, :no_supported_version}
  end

  defp try_versions(server, [version | remaining_versions]) do
    Logger.debug("Trying protocol version #{version} for server #{server.name}")

    case attempt_initialize(server, version) do
      {:ok, _response} ->
        Logger.info("Server #{server.name} supports protocol version #{version}")
        {:ok, version}

      {:error, reason} ->
        Logger.debug("Version #{version} failed for #{server.name}: #{inspect(reason)}")
        try_versions(server, remaining_versions)
    end
  end

  defp attempt_initialize(server, protocol_version) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: %{
        protocolVersion: protocol_version,
        capabilities: %{},
        clientInfo: %{
          name: Constants.server_name(),
          version: Constants.server_version()
        }
      }
    }

    case make_request(server, request_body) do
      {:ok, %{"result" => result}} ->
        {:ok, result}

      {:ok, %{"error" => error}} ->
        {:error, {:mcp_error, error}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp make_request(server, request_body) do
    case ServerClient.make_request(server, request_body) do
      {:ok, body, _headers} -> {:ok, body}
      {:error, reason} -> {:error, reason}
    end
  end
end
