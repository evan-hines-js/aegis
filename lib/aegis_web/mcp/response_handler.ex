defmodule AegisWeb.MCP.ResponseHandler do
  @moduledoc """
  Handles JSON-RPC responses from clients to server-initiated requests.

  Processes responses to server-initiated requests in bidirectional communication.
  """

  import Plug.Conn
  require Logger

  @doc """
  Handle a single JSON-RPC response from client.

  Broadcasts the response to any waiting server-initiated requests.
  """
  def handle_client_response(conn, params, session_id) do
    Logger.info("Processing client response for session #{session_id}: #{inspect(params)}")

    # Extract request ID from client response
    request_id = params["id"]

    if request_id do
      # Broadcast response to waiting processes
      Phoenix.PubSub.broadcast(
        Aegis.PubSub,
        "mcp_session:#{session_id}:responses",
        {:client_response, request_id, params}
      )

      Logger.debug("Broadcasted client response for request #{request_id}")
    else
      Logger.warning("Client response missing request ID: #{inspect(params)}")
    end

    # Client response processed successfully
    conn
    |> put_status(204)
    |> send_resp(204, "")
  end
end
