defmodule Aegis.MCP.Handlers.InitializationHandler do
  @moduledoc """
  Handler for MCP initialization and lifecycle management.

  Handles initialization requests, capability negotiation, and session setup.
  """

  require Logger

  alias Aegis.MCP.{
    Authorization,
    CapabilityAggregator,
    Constants,
    ErrorResponse,
    RequestHelpers,
    ServerClient
  }

  alias Aegis.Cache

  @doc """
  Handle initialize request.

  Validates parameters, negotiates protocol version, and sets up session with backend servers.
  Returns state updates for the Session to apply.

  ## Stateless Mode

  By default, always returns a stateful session (needed for SSE notifications).
  Clients can opt-in to stateless mode by setting the `allow_stateless_mode` option to `true`.
  Stateless mode only works if ALL backends are session-less.
  """
  @spec handle_initialize(String.t() | nil, String.t(), map(), map(), keyword()) ::
          {:ok, map(), map() | :stateless} | {:error, map()}
  def handle_initialize(session_id, client_id, init_params, params, opts \\ []) do
    Logger.info(
      "Handling initialize request with params: #{inspect(params)} for session: #{session_id}"
    )

    # Validate initialize parameters
    with :ok <- validate_initialize_params(init_params),
         {:ok, negotiated_version} <-
           negotiate_protocol_version(init_params["protocolVersion"]) do
      handle_valid_initialize_request(
        negotiated_version,
        init_params,
        params,
        session_id,
        client_id,
        opts
      )
    else
      {:error, {:error, %{} = error_response}} ->
        Logger.warning("Initialize request validation failed: #{inspect(error_response)}")
        response = RequestHelpers.add_request_id_if_present(error_response, params)
        {:error, response}
    end
  end

  @doc """
  Handle notifications/initialized notification.

  Marks the session as fully initialized.
  """
  @spec handle_initialized_notification() :: {:notification, :ok}
  def handle_initialized_notification do
    Logger.info("Client initialized notification received")
    {:notification, :ok}
  end

  # Private helper functions

  defp handle_valid_initialize_request(
         protocol_version,
         init_params,
         params,
         session_id,
         client_id,
         opts
       ) do
    Logger.info("Found client #{client_id} for session #{session_id}")

    # Extract client capabilities for Streamable HTTP client features
    client_capabilities = Map.get(init_params, "capabilities", %{})

    # Get servers this client has access to
    accessible_servers = Authorization.get_accessible_servers(client_id)

    # Initialize all accessible backend servers and collect their session IDs
    backend_sessions_list =
      initialize_backend_servers(accessible_servers, protocol_version, session_id)

    # Convert backend sessions list to map
    backend_sessions =
      backend_sessions_list
      |> Enum.filter(fn {_server_name, session_id} -> session_id != nil end)
      |> Enum.into(%{})

    # Determine if client should be stateful or stateless
    session_mode = determine_session_mode(backend_sessions, accessible_servers, opts)

    # Get capabilities based on client permissions
    enhanced_capabilities =
      if Enum.empty?(accessible_servers) do
        # Client has no permissions - show hardcoded full MCP schema for dynamic updates
        build_default_capabilities(client_capabilities, session_mode)
      else
        # Client has permissions - show actual accessible server capabilities
        build_enhanced_capabilities(accessible_servers, client_capabilities, session_mode)
      end

    # Build proper MCP initialize response
    response =
      build_initialize_response(
        protocol_version,
        enhanced_capabilities,
        Constants.server_info(),
        params
      )

    case session_mode do
      :stateless ->
        Logger.info(
          "Client #{client_id} initialized in stateless mode (all backends session-less)"
        )

        {:ok, response, :stateless}

      :stateful ->
        Logger.info("Client #{client_id} initialized in stateful mode (session required)")
        response_with_session = Map.put(response, "_session_id", session_id)

        {:ok, response_with_session,
         %{
           client_capabilities: client_capabilities,
           backend_sessions: backend_sessions,
           initialized: true
         }}
    end
  end

  # Determine if a client should operate in stateless or stateful mode.
  #
  # Stateless mode: Pure proxy, no hub session
  # Stateful mode: Hub manages session state, tracks backend sessions
  #
  # Rules:
  # - Default: Stateful (needed for SSE notifications, even with session-less backends)
  # - Stateless opt-in: Client explicitly allows + all backends are session-less + has accessible servers
  defp determine_session_mode(backend_sessions, accessible_servers, opts) do
    allow_stateless = Keyword.get(opts, :allow_stateless_mode, false)

    cond do
      # At least one backend returned mcp-session-id → always stateful
      map_size(backend_sessions) > 0 ->
        :stateful

      # No accessible servers → stateful (need SSE for permission update notifications)
      Enum.empty?(accessible_servers) ->
        :stateful

      # Client opted in AND all backends are session-less → stateless
      allow_stateless ->
        :stateless

      # Default: stateful (needed for SSE notifications)
      true ->
        :stateful
    end
  end

  defp initialize_backend_servers(servers, protocol_version, _hub_session_id) do
    servers
    |> Task.async_stream(
      fn server ->
        case initialize_backend_server(server, protocol_version) do
          {:ok, session_id} ->
            {server.name, session_id}

          # Backend doesn't use sessions
          {:error, :no_session} ->
            {server.name, nil}

          {:error, reason} ->
            Logger.warning(
              "Failed to initialize backend server #{server.name}: #{inspect(reason)}"
            )

            {server.name, nil}
        end
      end,
      max_concurrency: 10,
      timeout: 5000
    )
    |> Enum.map(fn
      {:ok, result} ->
        result

      {:error, reason} ->
        Logger.warning("Backend server initialization failed: #{inspect(reason)}")
        nil
    end)
    |> Enum.filter(&(&1 != nil))
  end

  defp initialize_backend_server(server, protocol_version) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: %{
        protocolVersion: protocol_version,
        capabilities: %{},
        clientInfo: %{
          name: "Aegis MCP Hub",
          version: "1.0.0"
        }
      }
    }

    case ServerClient.make_request(server, request_body, [], quiet: true) do
      {:ok, %{"result" => %{"capabilities" => capabilities}} = _result, headers} ->
        # Store capabilities in unified cache so we don't need to fetch them separately
        cache_key = {server.name, protocol_version}

        Cache.put(:mcp_meta_cache, cache_key, capabilities,
          tags: ["server:#{server.name}:capabilities", "capabilities"]
        )

        Logger.debug("Cached capabilities for #{server.name}: #{inspect(capabilities)}")

        # Extract session ID from response headers if present
        case Map.get(headers, "mcp-session-id") do
          session_id when is_binary(session_id) -> {:ok, session_id}
          _ -> {:error, :no_session}
        end

      {:ok, %{"result" => _result}, headers} ->
        # Server responded but didn't include capabilities - this is fine
        Logger.debug("Server #{server.name} initialized but returned no capabilities")

        # Extract session ID from response headers if present
        case Map.get(headers, "mcp-session-id") do
          session_id when is_binary(session_id) -> {:ok, session_id}
          _ -> {:error, :no_session}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_enhanced_capabilities(accessible_servers, client_capabilities, session_mode) do
    # Start with base server capabilities from accessible backend servers only
    base_capabilities = CapabilityAggregator.aggregate_capabilities(accessible_servers)

    # Add client features we can proxy
    enhanced_capabilities =
      base_capabilities
      |> maybe_add_roots_capability(client_capabilities)
      |> maybe_add_sampling_capability(client_capabilities)
      |> maybe_add_elicitation_capability(client_capabilities)
      |> maybe_add_logging_capability(session_mode)

    enhanced_capabilities
  end

  defp build_default_capabilities(client_capabilities, session_mode) do
    # Hardcoded full MCP schema - no architecture leakage
    base_capabilities = %{
      tools: %{listChanged: true},
      resources: %{listChanged: true},
      prompts: %{listChanged: true}
    }

    # Add client features we can proxy + hub features
    enhanced_capabilities =
      base_capabilities
      |> maybe_add_roots_capability(client_capabilities)
      |> maybe_add_sampling_capability(client_capabilities)
      |> maybe_add_elicitation_capability(client_capabilities)
      |> maybe_add_logging_capability(session_mode)
      |> Map.put(:_defaultCapabilities, true)

    enhanced_capabilities
  end

  defp maybe_add_roots_capability(capabilities, client_capabilities) do
    if Map.has_key?(client_capabilities, "roots") do
      # Client supports roots - we can proxy this feature
      roots_cap = Map.get(client_capabilities, "roots", %{})
      put_in(capabilities, [:roots], roots_cap)
    else
      capabilities
    end
  end

  defp maybe_add_sampling_capability(capabilities, client_capabilities) do
    if Map.has_key?(client_capabilities, "sampling") do
      # Client supports sampling - we can proxy this feature
      sampling_cap = Map.get(client_capabilities, "sampling", %{})
      put_in(capabilities, [:sampling], sampling_cap)
    else
      capabilities
    end
  end

  defp maybe_add_elicitation_capability(capabilities, client_capabilities) do
    if Map.has_key?(client_capabilities, "elicitation") do
      # Client supports elicitation - we can proxy this feature
      elicitation_cap = Map.get(client_capabilities, "elicitation", %{})
      put_in(capabilities, [:elicitation], elicitation_cap)
    else
      capabilities
    end
  end

  defp maybe_add_logging_capability(capabilities, session_mode) do
    # Aegis provides MCP logging protocol support only in stateful mode
    # Stateless mode cannot support logging/setLevel since it requires session state
    case session_mode do
      :stateful ->
        put_in(capabilities, [:logging], %{})

      :stateless ->
        capabilities
    end
  end

  # Lifecycle helper functions (moved from deleted Lifecycle module)

  defp validate_initialize_params(params) when is_map(params) do
    # Basic validation - params should have protocolVersion
    if Map.has_key?(params, "protocolVersion") do
      :ok
    else
      {:error,
       ErrorResponse.build_error(ErrorResponse.invalid_params(), "Missing protocolVersion")}
    end
  end

  defp negotiate_protocol_version(client_version) when is_binary(client_version) do
    supported = ["2025-03-26", "2025-06-18"]

    if client_version in supported do
      {:ok, client_version}
    else
      # Use latest supported version
      {:ok, "2025-06-18"}
    end
  end

  defp negotiate_protocol_version(_), do: {:ok, "2025-06-18"}

  defp build_initialize_response(protocol_version, capabilities, server_info, params) do
    response = %{
      jsonrpc: "2.0",
      result: %{
        protocolVersion: protocol_version,
        capabilities: capabilities,
        serverInfo: server_info
      }
    }

    RequestHelpers.add_request_id_if_present(response, params)
  end
end
