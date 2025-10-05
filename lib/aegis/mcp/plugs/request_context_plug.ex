defmodule Aegis.MCP.RequestContextPlug do
  @moduledoc """
  Plug for collecting request context from HTTP requests.

  Extracts and stores relevant request metadata:
  - Request ID for correlation
  - Client IP address
  - User Agent
  - Session information
  - MCP protocol details

  This context is made available to controllers and services.
  """

  import Plug.Conn
  require Logger

  @doc """
  Initialize the plug with options.
  """
  def init(opts), do: opts

  @doc """
  Extract request context from the request and store in assigns.
  """
  def call(conn, _opts) do
    # Generate or extract request ID
    request_id = get_or_generate_request_id(conn)

    # Extract client information
    ip_address = get_client_ip(conn)
    user_agent = get_user_agent(conn)

    # Extract MCP protocol information
    protocol_version = get_protocol_version(conn)

    # Build request context
    request_context = %{
      request_id: request_id,
      ip_address: ip_address,
      user_agent: user_agent,
      protocol_version: protocol_version,
      method: conn.method,
      path: conn.request_path,
      timestamp: DateTime.utc_now()
    }

    conn
    |> assign(:request_context, request_context)
    |> put_resp_header("x-request-id", request_id)
  end

  @doc """
  Get request context from connection assigns.
  """
  def get_request_context(conn) do
    Map.get(conn.assigns, :request_context, %{})
  end

  @doc """
  Merge additional request context (like client_id after authentication).
  """
  def merge_request_context(conn, additional_context) when is_map(additional_context) do
    current_context = get_request_context(conn)
    merged_context = Map.merge(current_context, additional_context)
    assign(conn, :request_context, merged_context)
  end

  # Private helper functions

  defp get_or_generate_request_id(conn) do
    # Check for existing request ID from load balancer or previous middleware
    case get_req_header(conn, "x-request-id") do
      [request_id] when is_binary(request_id) and request_id != "" ->
        request_id

      _ ->
        # Generate a new request ID
        :crypto.strong_rand_bytes(16) |> Base.encode64() |> String.replace(~r/[^A-Za-z0-9]/, "")
    end
  end

  defp get_client_ip(conn) do
    # Check for forwarded IP first (load balancer/proxy)
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded] ->
        # X-Forwarded-For can contain multiple IPs, take the first one
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        case get_req_header(conn, "x-real-ip") do
          [real_ip] -> real_ip
          [] -> format_ip(conn.remote_ip)
        end
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [user_agent] -> user_agent
      [] -> "unknown"
    end
  end

  defp get_protocol_version(conn) do
    case get_req_header(conn, "mcp-protocol-version") do
      [version] -> version
      [] -> "unknown"
    end
  end

  defp format_ip({a, b, c, d}) do
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp format_ip({a, b, c, d, e, f, g, h}) do
    # IPv6 formatting
    Enum.map_join([a, b, c, d, e, f, g, h], ":", &Integer.to_string(&1, 16))
  end
end
