defmodule Aegis.MCP.Handlers.ResourcesHandler do
  @moduledoc """
  Handler for MCP resources/* method calls.

  Handles resource listing, reading, and template operations with proper authorization.
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
    ServerContentCache,
    Session
  }

  @doc """
  Handle resources/list request.

  Returns all resources from servers the client has access to with pagination support.
  """
  @spec handle_list(String.t() | nil, String.t(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, map()}
  def handle_list(session_id, client_id, pagination_tokens, params, auth_opts \\ [])

  def handle_list(session_id, client_id, _pagination_tokens, params, _auth_opts) do
    Pagination.handle_paginated_list(
      session_id,
      client_id,
      params,
      "resources/list",
      :resources,
      &filter_accessible_resources/2
    )
  end

  @doc """
  Handle resources/templates/list request.

  Returns resource templates from servers the client has access to.
  """
  @spec handle_templates_list(String.t() | nil, String.t(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, map()}
  def handle_templates_list(
        _session_id,
        client_id,
        _pagination_tokens,
        params,
        _auth_opts \\ []
      ) do
    Logger.debug("handle_templates_list called with client_id: #{client_id}")

    case Authorization.get_client_permissions(client_id) do
      {:ok, permissions} ->
        build_templates_response(permissions, params)

      {:error, reason} ->
        Logger.debug("Failed to get permissions: #{inspect(reason)}")
        build_empty_templates_response(params)
    end
  end

  defp build_templates_response(permissions, params) do
    Logger.debug("Got permissions for client: #{length(permissions)} permissions")
    alias Aegis.MCP.ResourceFilter
    accessible_servers = ResourceFilter.get_accessible_servers(permissions, :resources)

    resource_templates =
      accessible_servers
      |> Enum.flat_map(&get_server_templates/1)
      |> Enum.map(&Namespace.namespace_resource_template(&1, &1.server_name))
      |> Enum.map(&Map.delete(&1, :server_name))

    response = %{
      jsonrpc: "2.0",
      result: %{"resourceTemplates" => resource_templates}
    }

    {:ok, RequestHelpers.add_request_id_if_present(response, params)}
  end

  defp get_server_templates(server) do
    case ServerContentCache.get_content(server, :resource_templates) do
      {:ok, templates} when is_list(templates) -> templates
      _ -> []
    end
  end

  defp build_empty_templates_response(params) do
    response = %{jsonrpc: "2.0", result: %{"resourceTemplates" => []}}
    {:ok, RequestHelpers.add_request_id_if_present(response, params)}
  end

  @doc """
  Handle resources/read request.

  Reads a specific resource with proper URI parsing and session management.
  Input validation is performed by InputValidationPlug before reaching this handler.
  """
  @spec handle_read(String.t() | nil, String.t(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, map()}
  def handle_read(session_id, client_id, backend_sessions, params, auth_opts \\ [])

  def handle_read(
        session_id,
        client_id,
        backend_sessions,
        %{
          "params" => %{"uri" => namespaced_uri}
        },
        _auth_opts
      ) do
    start_time = System.monotonic_time()

    result =
      case Namespace.parse_namespaced_uri(namespaced_uri) do
        {:ok, server_name, uri} ->
          handle_read_for_server(session_id, client_id, backend_sessions, server_name, uri)

        {:error, :invalid_format} ->
          {:error,
           ErrorResponse.build_error(
             ErrorResponse.invalid_params(),
             "Invalid URI format. Expected: server_name://<original_uri>"
           )}
      end

    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :mcp, :resources_read],
      %{duration: duration},
      %{client_id: client_id}
    )

    result
  end

  def handle_read(_session_id, _client_id, _backend_sessions, _params, _auth_opts) do
    {:error,
     ErrorResponse.build_error(
       ErrorResponse.invalid_params(),
       "Invalid parameters. Expected: uri"
     )}
  end

  defp handle_read_for_server(session_id, client_id, backend_sessions, server_name, uri) do
    case Namespace.find_server_by_name(server_name) do
      {:ok, server} ->
        maybe_broadcast_resource_usage(client_id, session_id, server_name, uri)
        backend_session_id = Map.get(backend_sessions, server.name)
        ServerClient.read_resource(server, uri, backend_session_id)

      {:error, :not_found} ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.method_not_found(),
           "Server not found: #{server_name}"
         )}
    end
  end

  defp maybe_broadcast_resource_usage(nil, _session_id, _server_name, _uri), do: :ok

  defp maybe_broadcast_resource_usage(client_id, session_id, server_name, uri) do
    broadcast_resource_usage(client_id, session_id, server_name, uri)
  end

  @doc """
  Handle resources/subscribe request.

  Subscribes to notifications for a specific resource URI with proper authorization.
  """
  @spec handle_subscribe(String.t(), String.t(), map(), map()) :: {:ok, map()} | {:error, map()}
  def handle_subscribe(
        session_id,
        client_id,
        backend_sessions,
        %{"params" => %{"uri" => namespaced_uri}} = params
      ) do
    case Authorization.check_list_permission(client_id, :resources) do
      {:ok, :authorized} ->
        do_subscribe(session_id, client_id, backend_sessions, namespaced_uri, params)

      {:error, reason} ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.method_not_found(),
           "Access denied: #{inspect(reason)}",
           Map.get(params, "id")
         )}
    end
  end

  def handle_subscribe(_session_id, _client_id, _backend_sessions, params) do
    {:error,
     ErrorResponse.build_error(
       ErrorResponse.invalid_params(),
       "Invalid parameters. Expected: uri",
       Map.get(params, "id")
     )}
  end

  @doc """
  Handle resources/unsubscribe request.
  """
  def handle_unsubscribe(
        session_id,
        client_id,
        %{"params" => %{"uri" => namespaced_uri}} = params
      ) do
    case Authorization.check_list_permission(client_id, :resources) do
      {:ok, :authorized} ->
        do_unsubscribe(session_id, namespaced_uri, params)

      {:error, reason} ->
        {:error,
         ErrorResponse.build_error(
           ErrorResponse.method_not_found(),
           "Access denied: #{inspect(reason)}",
           Map.get(params, "id")
         )}
    end
  end

  def handle_unsubscribe(_session_id, _client_id, params) do
    {:error,
     ErrorResponse.build_error(
       ErrorResponse.invalid_params(),
       "Invalid parameters. Expected: uri",
       Map.get(params, "id")
     )}
  end

  # Private helper functions

  defp do_unsubscribe(session_id, namespaced_uri, params) do
    # Remove from session subscriptions (returns :ok regardless of whether session exists)
    Session.remove_resource_subscription(session_id, namespaced_uri)
    Logger.debug("Resource unsubscribed: #{session_id} -> #{namespaced_uri}")
    success_response(params)
  end

  defp do_subscribe(session_id, client_id, backend_sessions, namespaced_uri, params) do
    with {:ok, server_name, uri} <- Namespace.parse_namespaced_uri(namespaced_uri),
         true <- client_has_resource_access?(client_id, namespaced_uri),
         {:ok, server} <- Namespace.find_server_by_name(server_name),
         true <- server_supports_resource_subscriptions?(server),
         :ok <- Session.add_resource_subscription(session_id, namespaced_uri),
         backend_session_id = Map.get(backend_sessions, server_name),
         {:ok, _response} <- ServerClient.subscribe_to_resource(server, uri, backend_session_id) do
      success_response(params)
    else
      {:error, :invalid_format} ->
        ErrorResponse.build_error(ErrorResponse.invalid_params(), "Invalid URI format")

      false ->
        ErrorResponse.build_error(ErrorResponse.invalid_params(), "Access denied or unsupported")

      {:error, :not_found} ->
        ErrorResponse.build_error(ErrorResponse.method_not_found(), "Server not found")

      {:error, error} ->
        # Clean up subscription if it was created
        Session.remove_resource_subscription(session_id, namespaced_uri)
        {:error, error}
    end
  end

  defp success_response(params) do
    response = %{jsonrpc: "2.0", result: %{}}
    {:ok, RequestHelpers.add_request_id_if_present(response, params)}
  end

  defp filter_accessible_resources(resources, client_id) do
    alias Aegis.MCP.ResourceFilter

    case Authorization.get_client_permissions(client_id) do
      {:ok, permissions} ->
        accessible_servers = ResourceFilter.get_accessible_servers(permissions, :resources)

        resources_filtered_by_server =
          ResourceFilter.filter_by_servers(
            resources,
            accessible_servers,
            &get_resource_uri/1,
            :resources
          )

        ResourceFilter.filter_by_permissions(
          resources_filtered_by_server,
          permissions,
          :resources,
          &get_resource_uri/1
        )

      {:error, _} ->
        # If we can't get permissions, deny access to all resources
        []
    end
  end

  defp get_resource_uri(%{uri: uri}), do: uri
  defp get_resource_uri(%{"uri" => uri}), do: uri
  defp get_resource_uri(_), do: nil

  defp server_supports_resource_subscriptions?(server) do
    case Map.get(server, :capabilities, %{}) do
      %{"resources" => %{"subscribe" => true}} -> true
      _ -> false
    end
  end

  defp client_has_resource_access?(client_id, namespaced_uri) do
    case Authorization.get_client_permissions(client_id) do
      {:ok, permissions} ->
        alias Aegis.MCP.ResourceFilter

        resources = [%{uri: namespaced_uri}]
        accessible_servers = ResourceFilter.get_accessible_servers(permissions, :resources)

        resources_filtered_by_server =
          ResourceFilter.filter_by_servers(
            resources,
            accessible_servers,
            &get_resource_uri/1,
            :resources
          )

        filtered_resources =
          ResourceFilter.filter_by_permissions(
            resources_filtered_by_server,
            permissions,
            :resources,
            &get_resource_uri/1
          )

        length(filtered_resources) > 0

      {:error, _} ->
        false
    end
  end

  defp broadcast_resource_usage(client_id, session_id, server_name, resource_uri) do
    Phoenix.PubSub.broadcast(
      Aegis.PubSub,
      Constants.usage_topic(),
      {:usage_event,
       %{
         type: :resource_read,
         client_id: client_id,
         session_id: session_id,
         server_name: server_name,
         item_name: resource_uri,
         timestamp: DateTime.utc_now()
       }}
    )
  end
end
