defmodule Aegis.MCP.ServerClient do
  @moduledoc """
  HTTP client for communicating with MCP servers.

  Handles all server communication including capability fetching,
  tool calls, resource reads, and prompt execution.
  """

  require Logger

  alias Aegis.Cache
  alias Aegis.MCP.{OAuthClient, Retry}

  @type server :: %{name: String.t(), endpoint: String.t()}
  @type mcp_response :: {:ok, map()} | {:error, map()}

  @doc "Get all healthy servers from the cache"
  def get_healthy_servers do
    case Aegis.MCP.list_servers(load: [:api_key, :oauth_client_secret]) do
      {:ok, servers} ->
        servers
        |> Enum.map(&map_server_with_cache_status/1)
        |> Enum.filter(fn server -> server && Map.get(server, :status) != :unhealthy end)

      {:error, _} ->
        []
    end
  end

  defp map_server_with_cache_status(server) do
    cache_key = {:server, server.name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, cached_info} when not is_nil(cached_info) ->
        %{
          name: server.name,
          endpoint: server.endpoint,
          auth_type: Map.get(cached_info, :auth_type, :none),
          api_key: server.api_key,
          api_key_header: server.api_key_header,
          api_key_template: server.api_key_template,
          oauth_client_id: server.oauth_client_id,
          oauth_client_secret: server.oauth_client_secret,
          oauth_token_url: server.oauth_token_url,
          oauth_scopes: server.oauth_scopes || [],
          status: Map.get(cached_info, :status, :unknown)
        }

      _ ->
        %{
          name: server.name,
          endpoint: server.endpoint,
          auth_type: server.auth_type || :none,
          api_key: server.api_key,
          api_key_header: server.api_key_header,
          api_key_template: server.api_key_template,
          oauth_client_id: server.oauth_client_id,
          oauth_client_secret: server.oauth_client_secret,
          oauth_token_url: server.oauth_token_url,
          oauth_scopes: server.oauth_scopes || [],
          status: :unknown
        }
    end
  end

  @doc "Call a tool on a specific server with client context for OAuth Token Exchange"
  def call_tool_with_context(server, client_id, backend_session_id, tool_params) do
    start_time = System.monotonic_time()
    tool_name = Map.get(tool_params, "name")

    # Forward params as-is (includes name, arguments, and _meta with progressToken)
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: tool_params
    }

    # Build headers with OAuth Token Exchange for client context
    session_headers =
      if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    auth_headers =
      build_auth_headers(server,
        client_id: client_id,
        resource_type: :tools,
        resource_pattern: tool_name,
        action: :call
      )

    all_headers = auth_headers ++ session_headers

    # Make direct request with client-context authentication
    result =
      case make_request(server, request_body, all_headers) do
        {:ok, response, _headers} -> {:ok, response}
        {:error, {:http_error, status_code, body}} -> {:error, {:http_error, status_code, body}}
        {:error, reason} -> connection_error(reason)
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :mcp, :tool_call],
      %{duration: duration},
      %{server: server.name, tool: tool_name}
    )

    result
  end

  @doc "Read a resource from a specific server"
  def read_resource(server, uri, backend_session_id \\ nil) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "resources/read",
      params: %{uri: uri}
    }

    headers = if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    case make_request(server, request_body, headers) do
      {:ok, response, _headers} -> {:ok, response}
      {:error, {:http_error, status_code, body}} -> {:error, {:http_error, status_code, body}}
      {:error, reason} -> connection_error(reason)
    end
  end

  @doc "Subscribe to resource updates from a specific server"
  def subscribe_to_resource(server, uri, backend_session_id \\ nil) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "resources/subscribe",
      params: %{uri: uri}
    }

    headers = if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    case make_request(server, request_body, headers) do
      {:ok, response, _headers} -> {:ok, response}
      {:error, {:http_error, status_code, body}} -> {:error, {:http_error, status_code, body}}
      {:error, reason} -> connection_error(reason)
    end
  end

  @doc "Get a prompt from a specific server"
  def get_prompt(server, prompt_name, arguments \\ %{}, backend_session_id \\ nil) do
    params = %{name: prompt_name}
    params = if arguments == %{}, do: params, else: Map.put(params, :arguments, arguments)

    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "prompts/get",
      params: params
    }

    headers = if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    case make_request(server, request_body, headers) do
      {:ok, response, _headers} -> {:ok, response}
      {:error, {:http_error, status_code, body}} -> {:error, {:http_error, status_code, body}}
      {:error, reason} -> connection_error(reason)
    end
  end

  @doc "Fetch a list from a server (tools, resources, prompts)"
  def fetch_list(server, method, result_key, backend_session_id \\ nil) do
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: method,
      params: %{}
    }

    headers = if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    case make_request(server, request_body, headers) do
      {:ok, %{"result" => result}, _headers} ->
        items = Map.get(result, result_key, [])
        Enum.map(items, &Map.put(&1, :server_name, server.name))

      {:ok, %{"error" => error}, _headers} ->
        Logger.debug("Server #{server.name} failed for #{method}: #{inspect(error)}")
        []

      {:error, _reason} ->
        []
    end
  end

  # Private functions

  @doc """
  Send a notification to server without affecting circuit breaker state.

  Notifications are fire-and-forget, so failures shouldn't count against
  the server's health. Uses retry but doesn't record circuit breaker results.
  """
  def send_notification(server, notification_body, extra_headers \\ []) do
    # Build headers with authentication
    auth_headers = build_auth_headers(server)

    # Add Accept headers for MCP protocol compliance
    accept_headers = [
      {"accept", "application/json, text/event-stream"},
      {"content-type", "application/json"}
    ]

    all_headers = auth_headers ++ accept_headers ++ extra_headers

    # Use retry but skip circuit breaker recording
    Retry.retry_http_request(
      fn ->
        Req.post(server.endpoint,
          json: notification_body,
          headers: all_headers,
          finch: Aegis.Finch,
          receive_timeout: 5_000
        )
      end,
      max_attempts: 2,
      base_delay: 100,
      quiet: true,
      # nil endpoint = skip circuit breaker
      endpoint: nil
    )
    |> case do
      {:ok, %Req.Response{status: 200}} ->
        {:ok, :sent}

      {:ok, %Req.Response{status: status_code, body: body}} ->
        # Don't log 500 errors for unsupported notifications
        if status_code == 500 and is_binary(body) and
             String.contains?(body, "FunctionClauseError") do
          {:error, :unsupported_notification}
        else
          {:error, {:http_error, status_code, body}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    exception ->
      {:error, {:exception, exception}}
  end

  @doc "Make request to server and return response with headers"
  def make_request(server, request_body, extra_headers \\ [], opts \\ []) do
    quiet = Keyword.get(opts, :quiet, false)
    timeout = Keyword.get(opts, :timeout, 30_000)
    operation = Map.get(request_body, "method", "unknown")

    # Build headers with authentication
    auth_headers = build_auth_headers(server)

    # Add Accept headers for MCP protocol compliance
    accept_headers = [
      {"accept", "application/json, text/event-stream"},
      {"content-type", "application/json"}
    ]

    all_headers = auth_headers ++ accept_headers ++ extra_headers

    Retry.retry_http_request(
      fn ->
        Req.post(server.endpoint,
          json: request_body,
          headers: all_headers,
          finch: Aegis.Finch,
          receive_timeout: timeout
        )
      end,
      max_attempts: 3,
      base_delay: 200,
      quiet: quiet,
      endpoint: server.endpoint,
      server_name: server.name,
      operation: operation
    )
    |> case do
      {:ok, %Req.Response{status: 200, body: body, headers: headers}} ->
        # Parse SSE format if content-type is text/event-stream
        parsed_body =
          case Map.get(headers, "content-type") do
            ["text/event-stream" | _] when is_binary(body) ->
              parse_sse_response(body)

            _ ->
              body
          end

        {:ok, parsed_body, headers}

      {:ok, %Req.Response{status: status_code, body: body}} ->
        Logger.warning("Server #{server.name} returned status #{status_code}: #{inspect(body)}")
        {:error, {:http_error, status_code, body}}

      {:error, reason} ->
        Logger.warning("Failed to communicate with server #{server.name}: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    exception ->
      Logger.warning("Exception communicating with server #{server.name}: #{inspect(exception)}")
      {:error, {:exception, exception}}
  end

  defp connection_error(reason) do
    {:error,
     %{
       jsonrpc: "2.0",
       error: %{
         code: -32_603,
         message: "Failed to connect to server: #{inspect(reason)}"
       }
     }}
  end

  # Parse Server-Sent Events (SSE) response format.
  #
  # SSE format example:
  # event: message
  # data: {"result": {...}, "jsonrpc": "2.0", "id": 1}
  defp parse_sse_response(sse_body) when is_binary(sse_body) do
    # Split by double newline to get events
    events = String.split(sse_body, "\n\n", trim: true)

    # Process each event and extract the data field
    Enum.reduce_while(events, nil, fn event, _acc ->
      lines = String.split(event, "\n", trim: true)

      # Find the data line and parse its JSON
      data_line =
        Enum.find(lines, fn line ->
          String.starts_with?(line, "data: ")
        end)

      case data_line do
        "data: " <> json_str ->
          case Jason.decode(json_str) do
            {:ok, parsed} ->
              {:halt, parsed}

            {:error, _} ->
              {:cont, nil}
          end

        _ ->
          {:cont, nil}
      end
    end)
  end

  defp parse_sse_response(body), do: body

  @doc """
  Build authentication headers for server requests.

  ## Options
  - `:client_id` - Client ID for OAuth Token Exchange (required for OAuth servers)
  - `:resource_type` - Resource type for OAuth Token Exchange
  - `:resource_pattern` - Resource pattern for OAuth Token Exchange
  - `:action` - Action for OAuth Token Exchange
  """
  def build_auth_headers(server, opts \\ []) do
    auth_type = Map.get(server, :auth_type, :none)
    build_headers_for_auth_type(server, auth_type, opts)
  end

  defp build_headers_for_auth_type(server, :api_key, _opts) do
    case Map.get(server, :api_key) do
      api_key when is_binary(api_key) and api_key != "" ->
        header_name = Map.get(server, :api_key_header, "Authorization")
        header_name_lower = String.downcase(header_name)

        # Use template to format the API key value, default to "{API_KEY}"
        template = Map.get(server, :api_key_template, "{API_KEY}")
        header_value = String.replace(template, "{API_KEY}", api_key)

        [{header_name_lower, header_value}]

      _ ->
        []
    end
  end

  defp build_headers_for_auth_type(server, :oauth, opts) do
    client_id = Keyword.get(opts, :client_id)

    if is_nil(client_id) do
      Logger.error(
        "SECURITY: OAuth server #{server.name} requires client context - pass client_id option"
      )

      []
    else
      build_oauth_headers(server, opts)
    end
  end

  defp build_headers_for_auth_type(_server, _auth_type, _opts), do: []

  defp build_oauth_headers(server, opts) do
    client_id = Keyword.get(opts, :client_id)
    resource_type = Keyword.get(opts, :resource_type)
    resource_pattern = Keyword.get(opts, :resource_pattern)
    action = Keyword.get(opts, :action)

    case OAuthClient.get_access_token_with_context(
           server,
           client_id,
           resource_type,
           resource_pattern,
           action
         ) do
      {:ok, delegated_token} ->
        [{"authorization", "Bearer #{delegated_token}"}]

      {:error, reason} ->
        Logger.warning(
          "Failed to get delegated OAuth token for client #{client_id} → server #{server.name}: #{inspect(reason)}"
        )

        []
    end
  end
end
