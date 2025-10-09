defmodule AegisWeb.Admin.ServersLive do
  use AegisWeb, :live_view

  require Ash.Query
  require Logger
  alias Aegis.MCP.{Constants, PermissionDefaults}

  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Aegis.PubSub, "servers")
      # Subscribe to server status changes
      Phoenix.PubSub.subscribe(Aegis.PubSub, Constants.all_changes_topic())
    end

    socket =
      socket
      |> assign(:current_page, :servers)
      |> assign(:page_title, "Server Management")
      |> assign(:show_form, false)
      |> assign(:editing_server, nil)
      |> assign(:form_mode, :create)
      |> assign(:selected_server, nil)
      |> assign(:server_status_cache, %{})
      |> assign(:page_size, 100)
      |> assign(:servers_page, nil)
      |> assign(:selected_auth_type, "none")
      |> load_servers()

    {:ok, socket}
  end

  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:show_form, false)
    |> assign(:editing_server, nil)
    |> assign(:form_mode, :create)
  end

  def handle_event("show_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :create)
      |> assign(:editing_server, nil)
      |> assign(:selected_auth_type, "none")

    {:noreply, socket}
  end

  def handle_event("hide_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, false)
      |> assign(:editing_server, nil)
      |> assign(:form_mode, :create)

    {:noreply, socket}
  end

  def handle_event("edit_server", %{"server_id" => server_id}, socket) do
    # Load server with sensitive fields for editing
    server = Aegis.MCP.get_server!(server_id, load: [:api_key])

    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :edit)
      |> assign(:editing_server, server)
      |> assign(:selected_auth_type, to_string(server.auth_type || :none))

    {:noreply, socket}
  end

  def handle_event("create_server", %{"server" => server_params}, socket) do
    processed_params = process_auth_params(server_params)

    case Aegis.MCP.create_server(
           processed_params[:name],
           processed_params[:endpoint],
           processed_params
         ) do
      {:ok, server} ->
        # Auto-generate basic permissions for the new server
        create_default_permissions(server)

        # Try to fetch capabilities on server creation (may fail if server is offline)
        fetch_server_capabilities(server)

        socket =
          socket
          |> put_flash(:info, "Server registered successfully with default permissions!")
          |> assign(:show_form, false)
          |> assign(:editing_server, nil)
          |> assign(:form_mode, :create)
          |> load_servers()

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to create server: #{inspect(errors)}")}
    end
  end

  def handle_event("update_server", %{"server" => server_params}, socket) do
    server = socket.assigns.editing_server
    processed_params = process_auth_params(server_params)

    case Aegis.MCP.update_server(server, processed_params) do
      {:ok, _updated_server} ->
        socket =
          socket
          |> put_flash(:info, "Server updated successfully!")
          |> assign(:show_form, false)
          |> assign(:editing_server, nil)
          |> assign(:form_mode, :create)
          |> load_servers()

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to update server: #{inspect(errors)}")}
    end
  end

  def handle_event("test_connectivity", %{"server_id" => server_id}, socket) do
    # Load server with sensitive fields for authentication during testing
    server = Aegis.MCP.get_server!(server_id, load: [:api_key])

    case test_server_connection(server) do
      {:ok, _response} ->
        # Update server status to healthy in cache
        update_server_status(server.name, :healthy, 0)

        # Broadcast the status change so UI updates
        Phoenix.PubSub.broadcast(
          Aegis.PubSub,
          "servers",
          {:server_status_changed, server.name, :healthy}
        )

        {:noreply, put_flash(socket, :info, "Server #{server.name} is responding correctly!")}

      {:error, reason} ->
        # Update server status to unhealthy in cache
        update_server_status(server.name, :unhealthy, 1)

        # Broadcast the status change so UI updates
        Phoenix.PubSub.broadcast(
          Aegis.PubSub,
          "servers",
          {:server_status_changed, server.name, :unhealthy}
        )

        {:noreply,
         put_flash(socket, :error, "Server #{server.name} connection failed: #{reason}")}
    end
  end

  def handle_event("delete_server", %{"server_id" => server_id}, socket) do
    server = Aegis.MCP.get_server!(server_id)

    case Aegis.MCP.delete_server(server) do
      :ok ->
        # Clean up associated permissions
        cleanup_server_permissions(server.name)

        socket =
          socket
          |> put_flash(:info, "Server deleted successfully!")
          |> load_servers()

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to delete server: #{inspect(errors)}")}
    end
  end

  def handle_event("auth_type_changed", %{"server" => %{"auth_type" => auth_type}}, socket) do
    {:noreply, assign(socket, :selected_auth_type, auth_type)}
  end

  def handle_event("load_more", _params, socket) do
    current_page = socket.assigns.servers_page

    case current_page && current_page.more? do
      true ->
        next_page = Ash.page!(current_page, :next)

        socket =
          socket
          |> assign(:servers_page, next_page)
          |> stream(:servers, next_page.results, at: -1)

        {:noreply, socket}

      _ ->
        {:noreply, socket}
    end
  end

  def handle_info({:list_changed, _change_notification}, socket) do
    # Server status changed, refresh the server list to update status display
    {:noreply, load_servers(socket)}
  end

  def handle_info({:server_status_changed, server_name, status}, socket) do
    # Server status changed, update just that server in the stream
    Logger.info("ServersLive received server_status_changed: #{server_name} -> #{status}")

    # Get the actual status from registry to verify it's updated
    actual_status = get_server_status(server_name)
    Logger.info("Fetched actual status for #{server_name}: #{actual_status}")

    # Find the server and update its status in the stream
    case Aegis.MCP.get_server_by_name(server_name) do
      {:ok, server} ->
        updated_server = Map.put(server, :current_status, actual_status)
        Logger.info("Updating stream for #{server_name} with status #{actual_status}")
        {:noreply, stream_insert(socket, :servers, updated_server)}

      {:error, _} ->
        Logger.warning("Could not find server #{server_name} to update status")
        {:noreply, socket}
    end
  end

  def handle_info(_msg, socket) do
    # Ignore other PubSub messages
    {:noreply, socket}
  end

  # Helper functions

  defp load_servers(socket) do
    page =
      Aegis.MCP.list_servers!(
        query: Ash.Query.sort(Aegis.MCP.Server, name: :asc),
        page: [limit: socket.assigns.page_size]
      )

    # Enrich server records with current status from registry
    servers_with_status =
      Enum.map(page.results, fn server ->
        status = get_server_status(server.name)
        Map.put(server, :current_status, status)
      end)

    socket
    |> assign(:servers_page, page)
    |> stream(:servers, servers_with_status, reset: true)
  end

  defp get_server_status(server_name) do
    alias Aegis.MCP.ServerManager

    case ServerManager.get_server(server_name) do
      {:ok, server_info} ->
        Logger.debug(
          "get_server_status for #{server_name}: found server_info with status #{server_info.status}"
        )

        server_info.status

      {:error, :not_found} ->
        Logger.debug("get_server_status for #{server_name}: not found, returning :unknown")
        :unknown
    end
  end

  defp create_default_permissions(server) do
    PermissionDefaults.create_comprehensive_permissions(server.name)
  end

  defp test_server_connection(server) do
    alias Aegis.MCP.ServerClient

    # Use MCP initialize protocol to test connection
    request_body = %{
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: %{
        protocolVersion: "2025-03-26",
        capabilities: %{},
        clientInfo: %{
          name: "Aegis MCP Hub",
          version: "1.0.0"
        }
      }
    }

    case ServerClient.make_request(server, request_body) do
      {:ok, %{"result" => %{"capabilities" => _capabilities}}, _headers} ->
        {:ok, "Server responding correctly with MCP protocol"}

      {:ok, _response, _headers} ->
        {:ok, "Server responding with 200 status"}

      {:error, {:http_error, status_code, _body}} ->
        {:error, "Server returned status #{status_code}"}

      {:error, reason} ->
        {:error, "Connection error: #{inspect(reason)}"}
    end
  end

  defp process_auth_params(server_params) do
    clear_irrelevant_auth_fields(server_params)
  end

  defp clear_irrelevant_auth_fields(server_params) do
    auth_type = Map.get(server_params, "auth_type", "none")

    case auth_type do
      "none" ->
        server_params
        |> Map.put("api_key", nil)
        |> Map.put("api_key_header", nil)
        |> Map.put("api_key_template", nil)

      "api_key" ->
        # Keep API key fields as-is
        server_params

      _ ->
        server_params
    end
  end

  defp cleanup_server_permissions(server_name) do
    Aegis.MCP.list_permissions!(
      query: Ash.Query.filter(Aegis.MCP.Permission, server_name: server_name)
    )
    |> Enum.each(&Aegis.MCP.delete_permission!/1)
  end

  defp fetch_server_capabilities(server) do
    # Create server info map for capability fetching
    server_info = %{
      name: server.name,
      endpoint: server.endpoint,
      auth_type: server.auth_type || :none,
      api_key: server.api_key,
      api_key_header: server.api_key_header,
      api_key_template: server.api_key_template
    }

    # Fetch capabilities using the standard capability aggregator
    alias Aegis.MCP.{CapabilityAggregator, Constants}
    protocol_version = Constants.default_protocol_version()

    try do
      # This will fetch and cache the capabilities in ETS
      capabilities = CapabilityAggregator.get_server_capabilities(server_info, protocol_version)

      if map_size(capabilities) > 0 do
        Logger.info(
          "Successfully fetched capabilities for new server #{server.name}: #{inspect(Map.keys(capabilities))}"
        )
      else
        Logger.warning(
          "No capabilities returned for new server #{server.name} - may be unreachable"
        )
      end

      capabilities
    rescue
      error ->
        Logger.warning(
          "Failed to fetch capabilities for new server #{server.name}: #{inspect(error)}"
        )

        # Don't fail server creation if capability fetch fails
        %{}
    end
  end

  defp update_server_status(server_name, status, failure_count) do
    alias Aegis.Cache

    cache_key = {:server, server_name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, server_info} when not is_nil(server_info) ->
        updated_info = %{
          server_info
          | status: status,
            last_check: DateTime.utc_now(),
            failure_count: failure_count
        }

        Cache.put(:mcp_meta_cache, cache_key, updated_info,
          tags: ["server:#{server_name}", "servers"]
        )

        :ok

      _ ->
        # Server not in cache, skip update
        Logger.warning("Server #{server_name} not in cache, skipping status update")
        :ok
    end
  end
end
