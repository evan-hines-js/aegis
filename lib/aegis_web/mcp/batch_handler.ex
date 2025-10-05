defmodule AegisWeb.MCP.BatchHandler do
  @moduledoc """
  Handles batch JSON-RPC requests for MCP protocol.

  Processes multiple requests/responses/notifications in a single HTTP call.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]
  require Logger

  alias Aegis.MCP.{RequestRouter, Session}

  @doc """
  Handle a batch of JSON-RPC messages.
  """
  def handle_batch_request(conn, params, session_id) when is_list(params) do
    Logger.info("Processing #{length(params)} batch messages for session #{session_id}")

    # Process all messages in the batch
    results =
      Enum.map(params, fn message ->
        process_batch_message(message, session_id)
      end)

    # Filter out nil results (notifications don't return responses)
    responses = Enum.reject(results, &is_nil/1)

    # Return appropriate response based on what we got
    cond do
      Enum.empty?(responses) ->
        # All notifications - return 204 No Content
        conn
        |> put_status(204)
        |> send_resp(204, "")

      length(responses) == 1 ->
        # Single response - return as object
        conn
        |> put_resp_content_type("application/json")
        |> json(hd(responses))

      true ->
        # Multiple responses - return as array
        conn
        |> put_resp_content_type("application/json")
        |> json(responses)
    end
  end

  defp process_batch_message(message, session_id) do
    case message do
      %{"jsonrpc" => "2.0", "method" => method} = params when is_map_key(params, "id") ->
        # Regular request with ID - process and return response
        case RequestRouter.route_request(session_id, method, params) do
          {:ok, response} -> response
          {:error, error} -> %{"jsonrpc" => "2.0", "id" => params["id"], "error" => error}
        end

      %{"jsonrpc" => "2.0", "method" => method} = params ->
        # Notification without ID - process but don't return response
        Session.handle_request(session_id, method, params)
        nil

      %{"jsonrpc" => "2.0", "id" => _id} = params when not is_map_key(params, "method") ->
        # Client response to our request - handle it
        # For now, just acknowledge it
        Logger.debug("Received client response in batch: #{inspect(params)}")
        nil

      invalid ->
        Logger.warning("Invalid batch message format: #{inspect(invalid)}")

        %{
          "jsonrpc" => "2.0",
          "id" => nil,
          "error" => %{"code" => -32_600, "message" => "Invalid Request"}
        }
    end
  end
end
