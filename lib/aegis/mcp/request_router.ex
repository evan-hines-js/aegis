defmodule Aegis.MCP.RequestRouter do
  @moduledoc """
  High-performance request router that bypasses GenServer for stateless requests.

  Routes requests directly to handlers with data from ETS cache, avoiding
  GenServer bottleneck for read-only operations like tools/list, resources/list.

  Only routes to Session GenServer for stateful operations (initialize, subscribe).
  """

  require Logger
  alias Aegis.MCP.{ErrorResponse, Session, SessionCache}

  alias Aegis.MCP.Handlers.{
    ClientFeaturesHandler,
    PromptsHandler,
    ResourcesHandler,
    ToolsHandler
  }

  @stateless_methods ~w(
    tools/list
    tools/call
    resources/list
    resources/read
    resources/templates/list
    prompts/list
    prompts/get
  )

  @stateful_methods ~w(
    initialize
    resources/subscribe
    logging/setLevel
    ping
  )

  @client_feature_methods ~w(
    roots/list
    sampling/createMessage
    elicitation/create
  )

  @doc """
  Route MCP request - stateless requests bypass GenServer.
  """
  def route_request(session_id, method, params) do
    cond do
      method in @stateless_methods ->
        handle_stateless_request(session_id, method, params)

      method in @stateful_methods ->
        # Delegate to Session GenServer for stateful operations
        Session.handle_request(session_id, method, params)

      method in @client_feature_methods ->
        # Route to client feature handler for server-to-client requests
        handle_client_feature_request(session_id, method, params)

      true ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.method_not_found(),
           "Unknown method: #{method}",
           Map.get(params, "id")
         )}
    end
  end

  # Handle stateless requests by reading from ETS cache
  defp handle_stateless_request(session_id, method, params) do
    case SessionCache.get(session_id) do
      {:ok, %{client_id: client_id, backend_sessions: backend_sessions}} ->
        route_to_handler(session_id, client_id, backend_sessions, method, params)

      {:error, :not_found} ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.invalid_request(),
           "Session not found or expired"
         )}
    end
  end

  @doc false
  # Route request to appropriate handler.
  # Used by both stateful mode (with session_id) and stateless mode (session_id = nil).
  # Stateless mode is useful for serverless clients (Lambda, Workers) that make
  # one-off requests without maintaining sessions.
  @spec route_to_handler(
          String.t() | nil,
          String.t(),
          map(),
          String.t(),
          map()
        ) ::
          {:ok, map()} | {:error, map()}
  def route_to_handler(session_id, client_id, backend_sessions, method, params) do
    start_time = System.monotonic_time()

    empty_pagination_tokens = %{}

    result =
      case method do
        "tools/list" ->
          ToolsHandler.handle_list(
            session_id,
            client_id,
            empty_pagination_tokens,
            params
          )

        "tools/call" ->
          ToolsHandler.handle_call(
            session_id,
            client_id,
            backend_sessions,
            params
          )

        "resources/list" ->
          ResourcesHandler.handle_list(
            session_id,
            client_id,
            empty_pagination_tokens,
            params
          )

        "resources/read" ->
          ResourcesHandler.handle_read(
            session_id,
            client_id,
            backend_sessions,
            params
          )

        "resources/templates/list" ->
          ResourcesHandler.handle_templates_list(
            session_id,
            client_id,
            empty_pagination_tokens,
            params
          )

        "prompts/list" ->
          PromptsHandler.handle_list(
            session_id,
            client_id,
            empty_pagination_tokens,
            params
          )

        "prompts/get" ->
          PromptsHandler.handle_get(
            session_id,
            client_id,
            backend_sessions,
            params
          )
      end

    duration = System.monotonic_time() - start_time
    status = if match?({:ok, _}, result), do: :success, else: :error

    :telemetry.execute(
      [:aegis, :mcp, :request],
      %{duration: duration},
      %{method: method, client_id: client_id, status: status}
    )

    result
  end

  # Handle server-to-client requests (roots, sampling, elicitation)
  defp handle_client_feature_request(session_id, method, params) do
    case method do
      "roots/list" ->
        ClientFeaturesHandler.handle_roots_list(session_id, params)

      "sampling/createMessage" ->
        ClientFeaturesHandler.handle_sampling_create_message(session_id, params)

      "elicitation/create" ->
        ClientFeaturesHandler.handle_elicitation_create(session_id, params)
    end
  end
end
