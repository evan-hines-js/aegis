defmodule AegisWeb.MCPController do
  use AegisWeb, :controller
  require Logger

  alias Aegis.MCP.Handlers.InitializationHandler

  alias Aegis.MCP.{
    Constants,
    ErrorHandler,
    ErrorResponse,
    HeaderValidation,
    RequestRouter,
    Session,
    SessionCache
  }

  alias AegisWeb.MCP.{
    BatchHandler,
    NotificationHandler,
    ResponseHandler,
    SSEHandler
  }

  plug AegisWeb.RateLimitPlug when action in [:index, :info, :sse_stream, :delete]

  @doc """
  Handle OPTIONS requests for MCP endpoints.
  """
  def options(conn, _params) do
    send_resp(conn, 200, "")
  end

  def info(conn, _params) do
    server_info = Constants.server_info()

    conn
    |> put_resp_content_type(Constants.json_content_type())
    |> json(%{
      name: server_info.name,
      version: server_info.version,
      protocol: "mcp",
      status: "running"
    })
  end

  # Handle JSON-RPC notification (no id field).
  # Notifications are fire-and-forget messages that don't expect responses.
  # Always returns 202 Accepted regardless of processing outcome.
  def index(conn, %{"jsonrpc" => "2.0", "method" => method} = params)
      when not is_map_key(params, "id") do
    Logger.info("MCP Notification: method=#{method}")

    # Process notification but always return 202
    case HeaderValidation.validate_session(conn, method) do
      {:ok, session_id} ->
        NotificationHandler.handle_notification(conn, params, session_id)

      {:error, _reason} ->
        # Still return 202 for notifications even if session validation fails
        conn
        |> put_status(202)
        |> put_resp_content_type("application/json")
        |> json(%{"status" => "accepted"})
    end
  end

  # Handle batch of JSON-RPC messages (array format).
  # Processes multiple requests/responses/notifications in a single HTTP call.
  def index(conn, params) when is_list(params) do
    Logger.info("MCP Batch Request: #{length(params)} messages")

    case HeaderValidation.validate_session(conn, "batch") do
      {:ok, session_id} ->
        BatchHandler.handle_batch_request(conn, params, session_id)

      {:error, reason} ->
        Logger.warning("Batch request validation failed: #{inspect(reason)}")
        send_error_response(conn, :bad_request, "Invalid session for batch request")
    end
  end

  # Handle single JSON-RPC response from client.
  # Processes responses to server-initiated requests in bidirectional communication.
  def index(conn, %{"jsonrpc" => "2.0", "id" => _request_id} = params)
      when not is_map_key(params, "method") do
    Logger.info("MCP Client Response: #{inspect(params)}")

    case HeaderValidation.validate_session(conn, "client_response") do
      {:ok, session_id} ->
        ResponseHandler.handle_client_response(conn, params, session_id)

      {:error, reason} ->
        Logger.warning("Client response validation failed: #{inspect(reason)}")
        send_error_response(conn, :bad_request, "Invalid session for client response")
    end
  end

  @doc """
  Handle single JSON-RPC request with a method field.

  This is the primary entry point for MCP method requests. Validates headers,
  session, and delegates to appropriate handlers based on the method.
  """
  def index(conn, %{"method" => method} = params) do
    start_time = System.monotonic_time()

    Logger.debug(
      "MCP Request: method=#{method}, client_id=#{get_in(params, ["client_id"]) || "unknown"}"
    )

    result =
      with {:ok, headers} <- validate_required_headers(conn, method),
           {:ok, request_data} <- build_request_data(headers, params, method) do
        %{method: method, params: params, content_type: content_type, session_id: session_id} =
          request_data

        process_mcp_request(conn, method, params, content_type, session_id)
      else
        error -> handle_validation_error(conn, error)
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :mcp, :http_request],
      %{duration: duration},
      %{method: method}
    )

    result
  end

  # Catch-all handler for invalid request formats.
  def index(conn, params) do
    Logger.info("MCP Request with unsupported format: #{inspect(params)}")

    {_, response} =
      ErrorResponse.build_controller_error(
        conn,
        :bad_request,
        ErrorResponse.invalid_request(),
        "Invalid request format. Expected method field."
      )

    response
  end

  # GET /mcp - SSE stream for server-to-client communication
  def sse_stream(conn, _params) do
    # First check Accept header per MCP spec
    headers = get_req_header(conn, "accept")

    if Enum.any?(headers, &String.contains?(&1, "text/event-stream")) do
      # Accept header is valid, now validate session
      case HeaderValidation.validate_session(conn, "sse_stream") do
        {:ok, nil} ->
          send_jsonrpc_error(
            conn,
            :unauthorized,
            -32_603,
            "Session required. Please initialize first."
          )

        {:ok, session_id} when is_binary(session_id) ->
          start_sse_stream(conn, session_id)

        {:error, :session_not_found} ->
          send_jsonrpc_error(conn, :unauthorized, -32_603, "Invalid or expired session")

        {:error, reason} ->
          Logger.warning("SSE stream session validation failed: #{inspect(reason)}")

          send_jsonrpc_error(
            conn,
            :bad_request,
            -32_600,
            "Invalid request: #{inspect(reason)}"
          )
      end
    else
      # Accept header missing or doesn't include text/event-stream - return 405 per spec
      conn
      |> put_status(:method_not_allowed)
      |> put_resp_header("allow", "POST")
      |> send_resp(405, "")
    end
  end

  def delete(conn, _params) do
    case get_req_header(conn, Constants.session_id_header()) do
      [session_id] ->
        terminate_session(conn, session_id)

      [] ->
        {_, response} =
          ErrorResponse.build_controller_error(
            conn,
            :bad_request,
            ErrorResponse.invalid_request(),
            "Missing #{Constants.session_id_header()} header"
          )

        response

      _ ->
        {_, response} =
          ErrorResponse.build_controller_error(
            conn,
            :bad_request,
            ErrorResponse.invalid_request(),
            "Multiple #{Constants.session_id_header()} headers not allowed"
          )

        response
    end
  end

  defp terminate_session(conn, session_id) do
    # Terminate the session GenServer
    Session.terminate_session(session_id)

    # Always return success
    send_resp(conn, 200, "")
  end

  # Private helper functions

  # Extract client_id from conn assigns
  defp extract_client_id(conn) do
    case Map.get(conn.assigns, :current_client) do
      %{id: client_id} when is_binary(client_id) ->
        {:ok, client_id}

      nil ->
        {:error, :missing_authentication}

      _ ->
        {:error, :invalid_client_data}
    end
  end

  # Validates all required headers for MCP request processing
  @spec validate_required_headers(Plug.Conn.t(), String.t()) :: {:ok, map()} | {:error, term()}
  defp validate_required_headers(conn, method) do
    with {:ok, version} <- HeaderValidation.validate_protocol_version(conn),
         {:ok, content_type} <- HeaderValidation.validate_accept_header(conn, method),
         {:ok, session_id} <- HeaderValidation.validate_session(conn, method) do
      {:ok, %{version: version, content_type: content_type, session_id: session_id}}
    end
  end

  # Builds request data structure from validated headers and parameters
  @spec build_request_data(map(), map(), String.t()) :: {:ok, map()}
  defp build_request_data(headers, params, method) do
    {:ok,
     %{
       headers: headers,
       params: params,
       method: method,
       content_type: headers.content_type,
       session_id: headers.session_id
     }}
  end

  # Sets up standard SSE headers for server-sent events streaming
  # Configures no-cache headers and session identification
  @spec setup_sse_stream(Plug.Conn.t(), String.t() | nil, String.t()) :: Plug.Conn.t()
  defp setup_sse_stream(conn, session_id, content_type \\ "text/event-stream") do
    conn =
      conn
      |> put_resp_content_type(content_type)
      |> put_resp_header("cache-control", "no-cache")
      |> put_resp_header("connection", "keep-alive")

    # Only add mcp-session-id header if we have a session
    if session_id && is_binary(session_id) do
      put_resp_header(conn, "mcp-session-id", session_id)
    else
      conn
    end
  end

  # Enhanced SSE stream setup with Last-Event-ID support for resumable streams
  @spec setup_sse_stream_with_resume(Plug.Conn.t(), String.t() | nil, String.t()) ::
          Plug.Conn.t()
  defp setup_sse_stream_with_resume(conn, session_id, content_type \\ "text/event-stream") do
    setup_sse_stream(conn, session_id, content_type)
  end

  # Centralized validation error handler using ErrorHandler for consistency.
  # Maps various validation errors to appropriate HTTP responses with
  # proper status codes and error messages.
  @spec handle_validation_error(Plug.Conn.t(), tuple()) :: Plug.Conn.t()
  defp handle_validation_error(conn, error) do
    case error do
      {:error, response} when is_map(response) ->
        conn
        |> put_status(:bad_request)
        |> json(response)

      {:error, :session_not_found} ->
        handle_session_not_found_error(conn)

      {:error, :no_api_key} ->
        handle_no_api_key_error(conn)

      {:error, :invalid_api_key} ->
        handle_invalid_api_key_error(conn)

      {:error, :client_inactive} ->
        handle_client_inactive_error(conn)

      {:error, other} ->
        ErrorHandler.log_and_return_error(:validation_error, %{error: other})
        send_jsonrpc_error(conn, :bad_request, -32_600, "Invalid request: #{inspect(other)}")
    end
  end

  defp send_error_response(conn, status, message) do
    conn
    |> put_status(status)
    |> json(%{
      jsonrpc: "2.0",
      error: %{
        code: -32_603,
        message: message
      }
    })
  end

  # New helper functions for better code organization

  @doc false
  defp handle_session_not_found_error(conn) do
    send_jsonrpc_error(conn, :unauthorized, -32_603, "Invalid or expired session")
  end

  @doc false
  defp handle_no_api_key_error(conn) do
    conn
    |> send_jsonrpc_error(
      :unauthorized,
      -32_603,
      "Authentication required. Please provide Authorization: Bearer <token> header."
    )
  end

  @doc false
  defp handle_invalid_api_key_error(conn) do
    conn
    |> send_jsonrpc_error(:unauthorized, -32_603, "Invalid API key.")
  end

  @doc false
  defp handle_client_inactive_error(conn) do
    conn
    |> send_jsonrpc_error(:unauthorized, -32_603, "Client account is inactive.")
  end

  defp process_mcp_request(conn, method, params, content_type, session_id) do
    method
    |> route_mcp_method(conn, params, session_id)
    |> handle_mcp_result(conn, content_type, method, session_id)
  end

  defp route_mcp_method("ping", _conn, params, _session_id) do
    {:ok, %{jsonrpc: "2.0", id: params["id"], result: %{}}}
  end

  defp route_mcp_method("initialize", conn, params, _session_id) do
    with {:ok, client_id} <- extract_client_id(conn),
         {:ok, response, session_mode} <- handle_initialize_request(conn, client_id, params) do
      case session_mode do
        {:stateful, session_id} ->
          {:ok, response, session_id}

        :stateless ->
          {:ok, response}
      end
    else
      {:error, reason} ->
        {:error, ErrorResponse.build_error(ErrorResponse.internal_error(), inspect(reason))}
    end
  end

  defp route_mcp_method(method, conn, params, session_id) do
    case session_id do
      nil ->
        # Stateless mode - extract client_id and route with nil session
        case extract_client_id(conn) do
          {:ok, client_id} ->
            # Call handler directly with nil session_id and empty backend_sessions
            RequestRouter.route_to_handler(nil, client_id, %{}, method, params)

          {:error, reason} ->
            {:error, ErrorResponse.build_error(ErrorResponse.invalid_request(), inspect(reason))}
        end

      session_id when is_binary(session_id) ->
        # Stateful mode
        RequestRouter.route_request(session_id, method, params)
    end
  end

  # Handle initialize and determine if client should be stateful or stateless
  defp handle_initialize_request(conn, client_id, params) do
    # Check for stateless opt-in header
    allow_stateless =
      case get_req_header(conn, "x-mcp-allow-stateless") do
        ["true"] -> true
        ["1"] -> true
        _ -> false
      end

    init_params = Map.get(params, "params", %{})
    opts = [allow_stateless_mode: allow_stateless]

    case InitializationHandler.handle_initialize(
           nil,
           client_id,
           init_params,
           params,
           opts
         ) do
      {:ok, response, :stateless} ->
        Logger.debug("Client #{client_id}: Stateless mode - no session created")
        {:ok, response, :stateless}

      {:ok, response, state_updates} when is_map(state_updates) ->
        Logger.debug("Client #{client_id}: Stateful mode - creating session")

        with {:ok, session_id} <- Session.create_session(client_id),
             :ok <- apply_state_updates(session_id, state_updates) do
          response_with_session = Map.put(response, "_session_id", session_id)
          {:ok, response_with_session, {:stateful, session_id}}
        end
    end
  end

  defp apply_state_updates(session_id, state_updates) do
    # Update session with initialization data
    SessionCache.update_session(session_id, fn session_data ->
      Map.merge(session_data, state_updates)
    end)

    :ok
  end

  defp handle_mcp_result({:ok, response, new_session_id}, conn, content_type, method, _session_id) do
    conn
    |> maybe_add_session_header(method, response, new_session_id)
    |> send_response(content_type, response, new_session_id)
  end

  defp handle_mcp_result({:ok, response}, conn, content_type, method, session_id) do
    conn
    |> maybe_add_session_header(method, response, session_id)
    |> send_response(content_type, response, session_id)
  end

  defp handle_mcp_result({:error, error_response}, conn, content_type, _method, session_id) do
    # Unwrap error tuples - the error_response might be {:error, actual_response}
    unwrapped_error = unwrap_error_response(error_response)

    case content_type do
      "text/event-stream" ->
        handle_error_via_sse(conn, unwrapped_error, session_id)

      _ ->
        # Per JSON-RPC 2.0 spec, all valid JSON-RPC requests return HTTP 200
        # The error is indicated in the response body's error field
        # Only use HTTP error codes for transport-level failures (auth, malformed JSON, etc)
        conn
        |> put_status(:ok)
        |> json(unwrapped_error)
    end
  end

  # Unwrap nested error tuples
  defp unwrap_error_response({:error, response}), do: response
  defp unwrap_error_response(response), do: response

  defp handle_error_via_sse(conn, error_response, session_id) do
    # Set up SSE headers using helper function
    conn = setup_sse_stream(conn, session_id)

    # Start chunked response and send error
    conn = send_chunked(conn, 200)

    case SSEHandler.send_event(conn, "message", error_response, 1) do
      {:ok, conn} -> conn
      {:error, _reason} -> conn
    end
  end

  defp send_response(conn, content_type, response, session_id) do
    # Remove internal session ID from response before sending to client
    clean_response = Map.delete(response, "_session_id")

    case content_type do
      "text/event-stream" ->
        # Client only accepts SSE
        handle_streamable_http_response(conn, clean_response, session_id)

      _ ->
        # Single JSON-RPC request -> JSON response
        json(conn, clean_response)
    end
  end

  # SSE formatting has been moved to SSEHandler module

  # Start SSE stream for GET /mcp endpoint
  defp start_sse_stream(conn, session_id) do
    # Check for Last-Event-ID header for resumability
    last_event_id =
      case get_req_header(conn, "last-event-id") do
        [id] -> String.to_integer(id)
        _ -> 0
      end

    # Set up SSE headers with Last-Event-ID support using helper function
    conn = setup_sse_stream_with_resume(conn, session_id)

    # Start chunked response
    conn = send_chunked(conn, 200)

    # Subscribe to session events for server-to-client communication
    SSEHandler.subscribe_to_topics(session_id)

    # If resuming, replay messages after last_event_id (would need message storage)
    # For now, just start fresh

    SSEHandler.maintain_connection(conn, session_id, last_event_id + 1)
  end

  defp maybe_add_session_header(conn, "initialize", response, _session_id) do
    case Map.get(response, "_session_id") do
      session_id when is_binary(session_id) ->
        put_resp_header(conn, Constants.session_id_header(), session_id)

      _ ->
        conn
    end
  end

  defp maybe_add_session_header(conn, _method, _response, _session_id), do: conn

  # Streamable HTTP Support

  defp handle_streamable_http_response(conn, response, session_id) do
    # Set up SSE headers using helper function
    conn = setup_sse_stream(conn, session_id)

    # Send initial response as SSE event
    conn = send_chunked(conn, 200)

    case SSEHandler.send_event(conn, "message", response, 1) do
      {:ok, conn} ->
        # Subscribe to session events for bidirectional communication
        SSEHandler.subscribe_to_topics(session_id)
        SSEHandler.maintain_connection(conn, session_id, 2)

      {:error, _reason} ->
        # Connection closed by client
        conn
    end
  end

  # SSE connection handling has been moved to AegisWeb.MCP.SSEHandler
  # for better separation of concerns and maintainability

  # Error Response Helpers

  defp send_jsonrpc_error(conn, status, code, message) do
    conn
    |> put_status(status)
    |> json(%{
      jsonrpc: "2.0",
      error: %{
        code: code,
        message: message
      }
    })
  end

  # SSE helpers have been moved to AegisWeb.MCP.SSEHandler
  # for better separation of concerns and maintainability
end
