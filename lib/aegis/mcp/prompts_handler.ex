defmodule Aegis.MCP.Handlers.PromptsHandler do
  @moduledoc """
  Handler for MCP prompts/* method calls.

  Handles prompt listing and execution with proper authorization and session management.
  """

  require Logger

  alias Aegis.MCP.{
    Authorization,
    Constants,
    ErrorResponse,
    Namespace,
    Pagination,
    ResourceFilter,
    ServerClient
  }

  @doc """
  Handle prompts/list request.

  Returns prompts that the client has permission to access with pagination support.
  """
  @spec handle_list(String.t() | nil, String.t(), map(), map()) :: {:ok, map()}
  def handle_list(session_id, client_id, pagination_tokens, params)

  def handle_list(session_id, client_id, _pagination_tokens, params) do
    Pagination.handle_paginated_list(
      session_id,
      client_id,
      params,
      "prompts/list",
      :prompts,
      &filter_accessible_prompts/2
    )
  end

  @doc """
  Handle prompts/get request.

  Executes a prompt with optional arguments and proper session management.
  Input validation is performed by InputValidationPlug before reaching this handler.
  """
  @spec handle_get(String.t() | nil, String.t(), map(), map()) ::
          {:ok, map()} | {:error, map()}
  def handle_get(session_id, client_id, backend_sessions, params)

  def handle_get(
        session_id,
        client_id,
        backend_sessions,
        %{
          "params" => %{"name" => namespaced_prompt_name} = prompt_params
        }
      ) do
    start_time = System.monotonic_time()
    arguments = Map.get(prompt_params, "arguments", %{})

    result =
      case Namespace.parse_namespaced_tool(namespaced_prompt_name) do
        {:ok, server_name, prompt_name} ->
          handle_get_for_server(
            session_id,
            client_id,
            backend_sessions,
            server_name,
            prompt_name,
            arguments
          )

        {:error, :invalid_format} ->
          ErrorResponse.build_error(
            ErrorResponse.invalid_params(),
            "Invalid prompt name format. Expected: server_name__prompt_name"
          )
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :mcp, :prompts_get],
      %{duration: duration},
      %{client_id: client_id}
    )

    result
  end

  def handle_get(_session_id, _client_id, _backend_sessions, _params) do
    {:error,
     ErrorResponse.build_error(
       ErrorResponse.invalid_params(),
       "Invalid parameters. Expected: name and optional arguments"
     )}
  end

  defp handle_get_for_server(
         session_id,
         client_id,
         backend_sessions,
         server_name,
         prompt_name,
         arguments
       ) do
    case Namespace.find_server_by_name(server_name) do
      {:ok, server} ->
        maybe_broadcast_prompt_usage(client_id, session_id, server_name, prompt_name)
        backend_session_id = Map.get(backend_sessions, server.name)
        ServerClient.get_prompt(server, prompt_name, arguments, backend_session_id)

      {:error, :not_found} ->
        ErrorResponse.build_error(
          ErrorResponse.method_not_found(),
          "Server not found: #{server_name}"
        )
    end
  end

  defp maybe_broadcast_prompt_usage(nil, _session_id, _server_name, _prompt_name), do: :ok

  defp maybe_broadcast_prompt_usage(client_id, session_id, server_name, prompt_name) do
    broadcast_prompt_usage(client_id, session_id, server_name, prompt_name)
  end

  # Private helper functions

  defp filter_accessible_prompts(prompts, client_id) do
    case Authorization.get_client_permissions(client_id) do
      {:ok, permissions} ->
        accessible_servers = ResourceFilter.get_accessible_servers(permissions, :prompts)

        prompts_filtered_by_server =
          ResourceFilter.filter_by_servers(
            prompts,
            accessible_servers,
            &get_prompt_name/1,
            :prompts
          )

        ResourceFilter.filter_by_permissions(
          prompts_filtered_by_server,
          permissions,
          :prompts,
          &get_prompt_name/1
        )

      {:error, _} ->
        # If we can't get permissions, deny access to all prompts
        []
    end
  end

  defp get_prompt_name(%{name: name}), do: name
  defp get_prompt_name(%{"name" => name}), do: name
  defp get_prompt_name(_), do: nil

  defp broadcast_prompt_usage(client_id, session_id, server_name, prompt_name) do
    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.usage_topic(),
      {:usage_event,
       %{
         type: :prompt_get,
         client_id: client_id,
         session_id: session_id,
         server_name: server_name,
         item_name: prompt_name,
         timestamp: DateTime.utc_now()
       }}
    )
  end
end
