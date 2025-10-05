defmodule AegisWeb.MCP.NotificationHandler do
  @moduledoc """
  Handles JSON-RPC notifications for MCP protocol.

  Notifications are fire-and-forget messages that don't expect responses.
  Always returns 202 Accepted regardless of processing outcome.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]
  require Logger

  alias Aegis.MCP.Session

  @doc """
  Handle a JSON-RPC notification.

  Notifications are processed asynchronously and always return 202 Accepted.
  """
  def handle_notification(conn, %{"method" => method} = params, session_id) do
    Logger.info("Processing notification #{method} for session #{session_id}")

    # Process the notification asynchronously
    process_notification_async(method, params, session_id)

    # Handle special notifications
    handle_special_notifications(method, session_id)

    # Always return 202 for notifications
    conn
    |> put_status(202)
    |> put_resp_content_type("application/json")
    |> json(%{"status" => "accepted"})
  end

  defp process_notification_async(method, params, session_id) do
    # Process notification in background to avoid blocking
    Task.start(fn ->
      try do
        Logger.debug("Processing notification async: #{method} for session #{session_id}")
        # Handle cancellation notifications specially - forward to backend
        if method == "notifications/cancelled" do
          forward_cancellation(session_id, params)
        else
          result = Session.handle_request(session_id, method, params)
          Logger.debug("Notification processing result: #{inspect(result)}")
        end
      rescue
        error ->
          Logger.error("Error processing notification #{method}: #{inspect(error)}")
          Logger.error("Stacktrace: #{inspect(__STACKTRACE__)}")
      end
    end)
  end

  defp handle_special_notifications("notifications/initialized", session_id) do
    # Mark session as initialized
    Session.mark_initialized(session_id)
  end

  defp handle_special_notifications("notifications/cancelled", session_id) do
    # Handle cancellation request - forward to backend server
    Logger.info("Received cancellation notification for session #{session_id}")
    # Actual forwarding is handled in process_notification_async
    :ok
  end

  defp handle_special_notifications(_method, _session_id) do
    # No special handling needed
    :ok
  end

  @doc """
  Broadcast a cancellation notification to all backend servers.

  Since we don't track which server is handling each request ID, we broadcast
  to all servers. Servers ignore cancellations for unknown/completed requests
  per the MCP spec.
  """
  def forward_cancellation(session_id, %{"params" => %{"requestId" => request_id}} = params) do
    alias Aegis.MCP.{ServerClient, SessionCache}

    Logger.info("Broadcasting cancellation for request #{request_id} to all backend servers")

    case SessionCache.get(session_id) do
      {:ok, %{backend_sessions: backend_sessions}} ->
        broadcast_to_servers(request_id, params, backend_sessions)

      {:error, _reason} ->
        :ok
    end
  end

  def forward_cancellation(_session_id, _params) do
    Logger.warning("Received cancellation notification without requestId")
    :ok
  end

  defp broadcast_to_servers(request_id, params, backend_sessions) do
    alias Aegis.MCP.ServerClient

    servers = ServerClient.get_healthy_servers()
    reason = Map.get(params["params"], "reason", "Client requested cancellation")

    Enum.each(servers, fn server ->
      send_cancellation_to_server(server, request_id, reason, backend_sessions)
    end)

    :ok
  end

  defp send_cancellation_to_server(server, request_id, reason, backend_sessions) do
    alias Aegis.MCP.ServerClient

    backend_session_id = Map.get(backend_sessions, server.name)

    cancellation_body = %{
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: %{
        requestId: request_id,
        reason: reason
      }
    }

    session_headers =
      if backend_session_id, do: [{"mcp-session-id", backend_session_id}], else: []

    Task.start(fn ->
      case ServerClient.make_request(server, cancellation_body, session_headers, quiet: true) do
        {:ok, _response, _headers} ->
          Logger.debug("Cancellation sent to #{server.name}")

        {:error, _reason} ->
          :ok
      end
    end)
  end
end
