defmodule AegisWeb.MCP.SSEHandler do
  @moduledoc """
  Handles Server-Sent Events (SSE) connections for MCP protocol.

  This module is responsible for:
  - Maintaining SSE connections
  - Handling SSE-specific messages
  - Managing event streaming to clients
  - Cleaning up connections on disconnect
  """

  require Logger
  alias Aegis.MCP.{Authorization, Constants, Handlers, Session}
  alias Phoenix.PubSub

  @doc """
  Maintain an SSE connection with a client.

  Listens for messages and handles them appropriately:
  - Client requests from backend servers
  - List change notifications
  - Session close requests
  - Connection timeouts
  """
  @spec maintain_connection(Plug.Conn.t(), String.t(), integer()) :: Plug.Conn.t()
  def maintain_connection(conn, session_id, event_counter) do
    receive do
      msg -> handle_message(conn, session_id, event_counter, msg)
    after
      Constants.sse_connection_timeout() ->
        handle_timeout(conn, session_id)
    end
  end

  # Message handler that delegates to specific handlers
  defp handle_message(conn, session_id, event_counter, msg) do
    case msg do
      {:client_request, request} ->
        handle_client_request(conn, session_id, event_counter, request)

      {:list_changed, notification} ->
        handle_list_changed(conn, session_id, event_counter, notification)

      {:progress_notification, notification} ->
        handle_progress_notification(conn, session_id, event_counter, notification)

      {:resource_updated, notification} ->
        handle_resource_updated(conn, session_id, event_counter, notification)

      {:log_message, message} ->
        handle_log_message(conn, session_id, event_counter, message)

      {:close_session} ->
        handle_session_close(conn, session_id)

      _ ->
        # Ignore unknown messages and continue listening
        maintain_connection(conn, session_id, event_counter)
    end
  end

  @doc """
  Handle client request from backend server.

  Forwards the request to the client via SSE and continues
  listening if successful, otherwise cleans up the connection.
  """
  def handle_client_request(conn, session_id, event_counter, request) do
    case send_event(conn, "message", request, event_counter) do
      {:ok, conn} ->
        maintain_connection(conn, session_id, event_counter + 1)

      {:error, _reason} ->
        # Connection closed - clean up subscriptions (session persists for reconnection)
        unsubscribe_from_topics(session_id)
        conn
    end
  end

  @doc """
  Handle tool list change notification.

  Only forwards the notification if the client has access to the
  server that triggered the change.
  """
  def handle_list_changed(conn, session_id, event_counter, change_notification) do
    if client_has_access?(session_id, change_notification) do
      notification = Map.put(change_notification, "jsonrpc", "2.0")

      case send_event(conn, "message", notification, event_counter) do
        {:ok, conn} ->
          maintain_connection(conn, session_id, event_counter + 1)

        {:error, _reason} ->
          # Connection closed - clean up subscriptions
          unsubscribe_from_topics(session_id)
          conn
      end
    else
      # Client doesn't have access, continue listening
      maintain_connection(conn, session_id, event_counter)
    end
  end

  @doc """
  Handle resource updated notification.

  Only forwards the notification if the client is subscribed to the specific resource.
  """
  def handle_resource_updated(conn, session_id, event_counter, notification) do
    if client_is_subscribed_to_resource?(session_id, notification) do
      notification_with_jsonrpc = Map.put(notification, "jsonrpc", "2.0")

      case send_event(conn, "message", notification_with_jsonrpc, event_counter) do
        {:ok, conn} ->
          maintain_connection(conn, session_id, event_counter + 1)

        {:error, _reason} ->
          # Connection closed - clean up subscriptions
          unsubscribe_from_topics(session_id)
          conn
      end
    else
      # Client not subscribed to this resource, continue listening
      maintain_connection(conn, session_id, event_counter)
    end
  end

  @doc """
  Handle log message notification.

  Only forwards the message if the client's session log level allows it.
  """
  def handle_log_message(conn, session_id, event_counter, message) do
    if should_forward_log_message?(session_id, message) do
      notification = %{
        "jsonrpc" => "2.0",
        "method" => "notifications/message",
        "params" => message
      }

      case send_event(conn, "message", notification, event_counter) do
        {:ok, conn} ->
          maintain_connection(conn, session_id, event_counter + 1)

        {:error, _reason} ->
          # Connection closed - clean up subscriptions
          unsubscribe_from_topics(session_id)
          conn
      end
    else
      # Log level filtering blocks this message, continue listening
      maintain_connection(conn, session_id, event_counter)
    end
  end

  @doc """
  Handle explicit session close request.

  Fully terminates the session and cleans up all resources.
  """
  def handle_session_close(conn, session_id) do
    cleanup_session(session_id)
    conn
  end

  @doc """
  Handle connection timeout.

  Closes the SSE connection but preserves the session for reconnection.
  """
  def handle_timeout(conn, session_id) do
    unsubscribe_from_topics(session_id)
    conn
  end

  @doc """
  Send an SSE event to the client.

  PERFORMANCE: Uses iolist to avoid multiple string allocations.
  Phoenix/Cowboy handles iolists efficiently, sending them directly
  to the socket without intermediate concatenation.
  """
  @spec send_event(Plug.Conn.t(), String.t(), map(), integer()) ::
          {:ok, Plug.Conn.t()} | {:error, atom()}
  def send_event(conn, event_type, data, event_counter) do
    # Build as iolist - no string allocations until final chunk
    event_data = [
      "id: ",
      Integer.to_string(event_counter),
      "\nevent: ",
      event_type,
      "\ndata: ",
      Jason.encode!(data),
      "\n\n"
    ]

    case Plug.Conn.chunk(conn, event_data) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Handle progress notification from the progress tracker.

  Forwards the progress notification to the client via SSE.
  """
  def handle_progress_notification(conn, session_id, event_counter, progress_notification) do
    case send_event(conn, "progress", progress_notification, event_counter) do
      {:ok, conn} ->
        maintain_connection(conn, session_id, event_counter + 1)

      {:error, _reason} ->
        # Connection closed - clean up subscriptions
        unsubscribe_from_topics(session_id)
        conn
    end
  end

  @doc """
  Subscribe to SSE topics for a session.
  """
  def subscribe_to_topics(session_id) do
    PubSub.subscribe(Aegis.PubSub, "mcp_session:#{session_id}")
    PubSub.subscribe(Aegis.PubSub, Constants.all_changes_topic())
    # Subscribe to progress notifications for this session
    PubSub.subscribe(Aegis.PubSub, "session:#{session_id}:progress")
  end

  @doc """
  Unsubscribe from SSE topics for a session.
  """
  def unsubscribe_from_topics(session_id) do
    PubSub.unsubscribe(Aegis.PubSub, "mcp_session:#{session_id}")
    PubSub.unsubscribe(Aegis.PubSub, Constants.all_changes_topic())
    PubSub.unsubscribe(Aegis.PubSub, "session:#{session_id}:progress")
  end

  # Check if client has access to the server that sent the notification
  defp client_has_access?(session_id, change_notification) do
    # Extract server name from the change notification
    server_name = get_in(change_notification, [:params, :server])

    if server_name do
      # Get client_id from session and check permissions
      case Session.get_client_id(session_id) do
        {:ok, client_id} ->
          # For server deletions, check permissions directly instead of checking if server exists
          # This allows clients who had access to receive the deletion notification
          client_has_server_permission?(client_id, server_name)

        {:error, _} ->
          false
      end
    else
      # If no server specified, assume it's a global notification and allow it
      true
    end
  end

  # Check if client has permission for a specific server by checking their permissions directly
  defp client_has_server_permission?(client_id, server_name) do
    case Authorization.get_client_permissions(client_id) do
      {:ok, permissions} ->
        Enum.any?(permissions, &(&1.server_name == server_name))

      {:error, _} ->
        false
    end
  end

  # Check if a log message should be forwarded based on session log level
  defp should_forward_log_message?(session_id, message) do
    message_level = Map.get(message, "level", "info")
    # Get session log level from the session
    case Session.get_log_level(session_id) do
      {:ok, session_log_level} ->
        Handlers.LoggingHandler.should_forward_log?(session_log_level, message_level)

      {:error, _} ->
        # Default to forwarding if we can't get log level
        true
    end
  end

  # Check if client is subscribed to a specific resource
  defp client_is_subscribed_to_resource?(session_id, notification) do
    # Extract resource URI from the notification - it should be in params.uri
    resource_uri = get_in(notification, [:params, :uri])
    server_name = get_in(notification, [:params, :server])

    if resource_uri && server_name do
      # Construct the namespaced URI that was used for subscription
      namespaced_uri = "#{server_name}://#{resource_uri}"

      case Session.get_resource_subscriptions(session_id) do
        {:ok, subscriptions} ->
          Enum.member?(subscriptions, namespaced_uri)

        {:error, _} ->
          false
      end
    else
      false
    end
  end

  # Clean up a disconnected session completely
  defp cleanup_session(session_id) do
    unsubscribe_from_topics(session_id)
    Session.terminate_session(session_id)
    Logger.info("SSE session terminated: #{session_id}")
  end
end
