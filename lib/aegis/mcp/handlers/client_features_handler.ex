defmodule Aegis.MCP.Handlers.ClientFeaturesHandler do
  @moduledoc """
  Handler for MCP client feature requests (Streamable HTTP).

  Handles client-side features that are proxied through the MCP hub:
  - roots/list
  - sampling/createMessage
  - elicitation/create
  """

  require Logger

  alias Aegis.MCP.{
    ErrorResponse,
    RequestHelpers,
    Session
  }

  @doc """
  Handle roots/list request.

  Proxies the request to the client if they support the roots capability.
  """
  @spec handle_roots_list(String.t(), map()) :: {:ok, map()} | {:error, map()}
  def handle_roots_list(session_id, params) do
    handle_client_feature_request("roots/list", session_id, params)
  end

  @doc """
  Handle sampling/createMessage request.

  Proxies the request to the client if they support the sampling capability.
  """
  @spec handle_sampling_create_message(String.t(), map()) :: {:ok, map()} | {:error, map()}
  def handle_sampling_create_message(session_id, params) do
    handle_client_feature_request("sampling/createMessage", session_id, params)
  end

  @doc """
  Handle elicitation/create request.

  Proxies the request to the client if they support the elicitation capability.
  """
  @spec handle_elicitation_create(String.t(), map()) :: {:ok, map()} | {:error, map()}
  def handle_elicitation_create(session_id, params) do
    handle_client_feature_request("elicitation/create", session_id, params)
  end

  # Private helper functions

  defp handle_client_feature_request(method, session_id, params) do
    # Check if client supports this feature
    case Session.get_client_capabilities(session_id) do
      {:ok, client_capabilities} ->
        if supports_feature?(client_capabilities, method) do
          make_client_request(session_id, method, params)
        else
          ErrorResponse.build_error(
            ErrorResponse.method_not_found(),
            "Client does not support #{method}"
          )
        end

      {:error, _reason} ->
        ErrorResponse.build_error(
          ErrorResponse.internal_error(),
          "Session not found or invalid"
        )
    end
  end

  defp supports_feature?(capabilities, "roots/list"), do: Map.has_key?(capabilities, "roots")

  defp supports_feature?(capabilities, "sampling/createMessage"),
    do: Map.has_key?(capabilities, "sampling")

  defp supports_feature?(capabilities, "elicitation/create"),
    do: Map.has_key?(capabilities, "elicitation")

  defp supports_feature?(_capabilities, _method), do: false

  defp make_client_request(session_id, method, params) do
    # Generate unique request ID
    request_id = generate_request_id()

    # Build request for client
    client_request = %{
      jsonrpc: "2.0",
      id: request_id,
      method: method,
      params: Map.get(params, "params", %{})
    }

    # Send request to client via Streamable HTTP (SSE)
    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      "mcp_session:#{session_id}",
      {:client_request, client_request}
    )

    # Wait for client response
    case wait_for_client_response(session_id, request_id, 30_000) do
      {:ok, response} ->
        # Return client's response, preserving original request ID
        response_with_id = RequestHelpers.add_request_id_if_present(response, params)
        {:ok, response_with_id}

      {:error, :timeout} ->
        ErrorResponse.build_error(
          ErrorResponse.internal_error(),
          "Client request timeout"
        )

      {:error, reason} ->
        ErrorResponse.build_error(
          ErrorResponse.internal_error(),
          "Client request failed: #{inspect(reason)}"
        )
    end
  end

  defp wait_for_client_response(session_id, request_id, timeout) do
    # Subscribe to client responses for this session
    Phoenix.PubSub.subscribe(Aegis.PubSub, "mcp_session:#{session_id}:responses")

    receive do
      {:client_response, ^request_id, response} ->
        Phoenix.PubSub.unsubscribe(Aegis.PubSub, "mcp_session:#{session_id}:responses")

        case response do
          %{"result" => result} -> {:ok, %{"result" => result}}
          %{"error" => error} -> {:error, error}
          _ -> {:error, :invalid_response}
        end
    after
      timeout ->
        Phoenix.PubSub.unsubscribe(Aegis.PubSub, "mcp_session:#{session_id}:responses")
        {:error, :timeout}
    end
  end

  defp generate_request_id do
    System.unique_integer([:positive, :monotonic]) |> to_string()
  end
end
