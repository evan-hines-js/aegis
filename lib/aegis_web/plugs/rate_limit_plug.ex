defmodule AegisWeb.RateLimitPlug do
  @moduledoc """
  Rate limiting plug for MCP requests using Hammer.

  Provides per-client rate limiting with different tiers based on client type.
  Integrates with existing audit logging for rate limit violations.
  """

  import Plug.Conn
  require Logger

  alias Aegis.MCP.{Constants, DistributedRateLimiter}

  def init(opts), do: opts

  def call(conn, _opts) do
    start_time = System.monotonic_time()

    result =
      case extract_client_identifier(conn) do
        {:ok, client_id} ->
          check_rate_limit(conn, client_id)

        {:error, :no_auth} ->
          # Apply stricter anonymous rate limiting
          check_rate_limit(conn, get_remote_ip(conn))
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :plug, :rate_limit],
      %{duration: duration},
      %{}
    )

    result
  end

  defp check_rate_limit(conn, identifier) do
    bucket_name = "mcp:#{identifier}"
    {rate_limit, window_ms} = get_rate_limits(conn, identifier)

    case DistributedRateLimiter.hit(bucket_name, window_ms, rate_limit) do
      {:allow, _count} ->
        conn

      {:deny, _limit} ->
        Logger.warning("Rate limit exceeded for #{identifier}")

        conn
        |> put_status(429)
        |> put_resp_header("retry-after", "#{div(window_ms, 1000)}")
        |> put_resp_content_type("application/json")
        |> send_resp(
          429,
          Jason.encode!(%{
            "jsonrpc" => "2.0",
            "error" => %{
              "code" => -32_000,
              "message" => "Rate limit exceeded"
            }
          })
        )
        |> halt()
    end
  end

  defp extract_client_identifier(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        # Use the first 16 chars of token as identifier for privacy
        # This prevents storing full tokens in rate limit buckets
        identifier = token |> String.slice(0, 16) |> Base.encode16()
        {:ok, identifier}

      _ ->
        {:error, :no_auth}
    end
  end

  defp get_rate_limits(conn, _identifier) do
    # First check controller action
    action = Phoenix.Controller.action_name(conn)

    case action do
      :info ->
        get_config_limit(:server_info, Constants.server_info_rate_limit())

      :sse_stream ->
        get_config_limit(:sse_streams, Constants.sse_streams_rate_limit())

      :delete ->
        get_config_limit(:session_deletion, Constants.session_deletion_rate_limit())

      :index ->
        get_mcp_method_rate_limit(conn)

      _ ->
        get_config_limit(:fallback, Constants.default_rate_limit())
    end
  end

  defp get_mcp_method_rate_limit(conn) do
    method = conn.params["method"] || "unknown"

    case method do
      "tools/call" ->
        get_config_limit(:tool_calls, Constants.tool_calls_rate_limit())

      method when method in ["tools/list", "resources/list", "prompts/list"] ->
        get_config_limit(:list_operations, Constants.list_operations_rate_limit())

      method when method in ["resources/read", "prompts/get"] ->
        get_config_limit(:resource_reads, Constants.resource_reads_rate_limit())

      _ ->
        get_config_limit(:default_operations, Constants.default_rate_limit())
    end
  end

  defp get_config_limit(key, default) do
    Application.get_env(:aegis, :rate_limits, [])[key] || default
  end

  defp get_remote_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> hd()
        |> String.trim()

      [] ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end
end
