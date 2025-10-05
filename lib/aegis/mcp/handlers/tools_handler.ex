defmodule Aegis.MCP.Handlers.ToolsHandler do
  @moduledoc """
  Handler for MCP tools/* method calls.

  Handles tool listing and execution with proper authorization and session management.
  """

  require Logger

  alias Aegis.MCP.{
    Authorization,
    Constants,
    ErrorResponse,
    Namespace,
    Pagination,
    RequestHelpers,
    ServerClient,
    Session
  }

  @doc """
  Handle tools/list request.

  Returns all tools from servers the client has access to with pagination support.
  Supports both stateful (with session_id) and stateless (session_id = nil) modes.
  """
  @spec handle_list(String.t() | nil, String.t(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, map()}
  def handle_list(session_id, client_id, pagination_tokens, params, auth_opts \\ [])

  def handle_list(session_id, client_id, _pagination_tokens, params, _auth_opts) do
    Pagination.handle_paginated_list(
      session_id,
      client_id,
      params,
      "tools/list",
      :tools,
      &filter_accessible_tools/2
    )
  end

  @doc """
  Handle tools/call request.

  Executes a tool with proper authorization and session management.
  Input validation is performed by InputValidationPlug before reaching this handler.
  """
  @spec handle_call(String.t() | nil, String.t(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, map()}
  def handle_call(session_id, client_id, backend_sessions, params, auth_opts \\ [])

  def handle_call(
        session_id,
        client_id,
        backend_sessions,
        %{
          "params" => %{"name" => namespaced_tool_name}
        } = params,
        auth_opts
      ) do
    arguments = get_in(params, ["params", "arguments"]) || %{}

    handle_authorized_tool_call(
      client_id,
      session_id,
      backend_sessions,
      namespaced_tool_name,
      arguments,
      params,
      auth_opts
    )
  end

  def handle_call(_session_id, _client_id, _backend_sessions, _params, _auth_opts) do
    {:error,
     ErrorResponse.build_error(
       ErrorResponse.invalid_params(),
       "Invalid parameters. Expected: name and optional arguments"
     )}
  end

  # Private helper functions

  defp filter_accessible_tools(tools, client_id) do
    alias Aegis.MCP.ResourceFilter

    case Authorization.get_client_permissions(client_id) do
      {:ok, permissions} ->
        accessible_servers = ResourceFilter.get_accessible_servers(permissions, :tools)

        tools_filtered_by_server =
          ResourceFilter.filter_by_servers(tools, accessible_servers, &get_tool_name/1, :tools)

        ResourceFilter.filter_by_permissions(
          tools_filtered_by_server,
          permissions,
          :tools,
          &get_tool_name/1
        )

      {:error, _} ->
        # If we can't get permissions, deny access to all tools
        []
    end
  end

  defp get_tool_name(%{name: name}), do: name
  defp get_tool_name(%{"name" => name}), do: name
  defp get_tool_name(_), do: nil

  defp handle_authorized_tool_call(
         client_id,
         session_id,
         backend_sessions,
         namespaced_tool_name,
         arguments,
         params,
         auth_opts
       ) do
    case Namespace.parse_namespaced_tool(namespaced_tool_name) do
      {:ok, server_name, tool_name} ->
        case Namespace.find_server_by_name(server_name) do
          {:ok, server} ->
            execute_tool_with_authorization(
              client_id,
              session_id,
              backend_sessions,
              server,
              tool_name,
              arguments,
              params,
              auth_opts
            )

          {:error, :not_found} ->
            {:error,
             ErrorResponse.build_error(
               ErrorResponse.method_not_found(),
               "Server not found: #{server_name}",
               Map.get(params, "id")
             )}
        end

      {:error, :invalid_format} ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.invalid_params(),
           "Invalid tool name format. Expected: server_name__tool_name",
           Map.get(params, "id")
         )}
    end
  end

  defp execute_tool_with_authorization(
         client_id,
         session_id,
         backend_sessions,
         server,
         tool_name,
         arguments,
         params,
         auth_opts
       ) do
    case Authorization.can_call_tool?(client_id, server.name, tool_name, auth_opts) do
      {:ok, :authorized} ->
        # Broadcast tool usage for analytics
        broadcast_tool_usage(client_id, session_id, server.name, tool_name)

        execute_tool_call(
          client_id,
          session_id,
          backend_sessions,
          server,
          tool_name,
          arguments,
          params
        )

      {:error, _reason} ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.method_not_found(),
           "Access denied: insufficient permissions to call tool #{tool_name}",
           Map.get(params, "id")
         )}
    end
  end

  defp execute_tool_call(
         client_id,
         session_id,
         backend_sessions,
         server,
         tool_name,
         arguments,
         params
       ) do
    # Get backend session ID for this server from state
    case Map.get(backend_sessions, server.name) do
      backend_session_id when is_binary(backend_session_id) ->
        call_tool_with_backend_session(
          server,
          tool_name,
          arguments,
          client_id,
          backend_session_id,
          session_id,
          params
        )

      nil ->
        # No backend session, call without session ID
        call_tool_without_backend_session(server, tool_name, arguments, client_id, params)
    end
  end

  defp call_tool_with_backend_session(
         server,
         tool_name,
         _arguments,
         client_id,
         backend_session_id,
         session_id,
         params
       ) do
    # Forward params but replace namespaced tool name with server-local name
    tool_params =
      params["params"]
      |> Map.put("name", tool_name)

    case ServerClient.call_tool_with_context(
           server,
           client_id,
           backend_session_id,
           tool_params
         ) do
      {:ok, %{"result" => result}} ->
        response = %{jsonrpc: "2.0", result: result}
        response = RequestHelpers.add_request_id_if_present(response, params)
        {:ok, response}

      {:ok, response} ->
        # If it's already a full response, fix the ID
        response = RequestHelpers.add_request_id_if_present(response, params)
        {:ok, response}

      {:error, {:http_error, 404, _body}} ->
        # Backend session was terminated - clean up and pass through to client
        Logger.info("Backend session terminated for #{server.name}, cleaning up mapping")

        Session.remove_backend_session(session_id, server.name)

        ErrorResponse.build_error(
          ErrorResponse.method_not_found(),
          "Backend session terminated. State may have been lost. Please reinitialize if needed."
        )

      error ->
        error
    end
  end

  defp call_tool_without_backend_session(server, tool_name, _arguments, client_id, params) do
    # Forward params but replace namespaced tool name with server-local name
    tool_params =
      params["params"]
      |> Map.put("name", tool_name)

    case ServerClient.call_tool_with_context(server, client_id, nil, tool_params) do
      {:ok, %{"result" => result}} ->
        response = %{jsonrpc: "2.0", result: result}
        response = RequestHelpers.add_request_id_if_present(response, params)
        {:ok, response}

      {:ok, response} ->
        response = RequestHelpers.add_request_id_if_present(response, params)
        {:ok, response}

      {:error, {:http_error, 400, _body}} ->
        # Backend requires session but we don't have one
        ErrorResponse.build_error(
          ErrorResponse.method_not_found(),
          "Backend server requires session initialization"
        )

      error ->
        error
    end
  end

  defp broadcast_tool_usage(client_id, session_id, server_name, tool_name) do
    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.usage_topic(),
      {:usage_event,
       %{
         type: :tool_call,
         client_id: client_id,
         session_id: session_id,
         server_name: server_name,
         item_name: tool_name,
         timestamp: DateTime.utc_now()
       }}
    )
  end
end
