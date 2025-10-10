defmodule AegisWeb.Admin.ClientsLive do
  use AegisWeb, :live_view

  require Ash.Query
  alias Aegis.MCP.ClientPermissionManager
  alias AegisWeb.LiveHelpers

  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Subscribe to real-time updates
      Phoenix.PubSub.subscribe(Aegis.PubSub, "clients")
    end

    socket =
      socket
      |> assign(:current_page, :clients)
      |> assign(:page_title, "Client Management")
      |> assign(:show_form, false)
      |> assign(:editing_client, nil)
      |> assign(:form_mode, :create)
      |> assign(:selected_client, nil)
      |> assign(:permissions, [])
      |> assign(:servers, [])
      |> assign(:page_size, 100)
      |> assign(:clients_page, nil)
      |> assign(:selected_permissions, %{})
      |> load_clients()
      |> load_permissions()
      |> load_servers()

    {:ok, socket}
  end

  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:show_form, false)
    |> assign(:selected_client, nil)
    |> assign(:editing_client, nil)
    |> assign(:form_mode, :create)
  end

  def handle_event("show_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :create)
      |> assign(:editing_client, nil)
      |> assign(:selected_permissions, %{})

    {:noreply, socket}
  end

  def handle_event("hide_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, false)
      |> assign(:editing_client, nil)
      |> assign(:form_mode, :create)

    {:noreply, socket}
  end

  def handle_event("edit_client", %{"client_id" => client_id}, socket) do
    client = Aegis.MCP.get_client!(client_id, load: [:permissions])

    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :edit)
      |> assign(:editing_client, client)

    {:noreply, socket}
  end

  def handle_event("create_client", %{"client" => client_params} = params, socket) do
    base_params = Map.take(client_params, ["name", "description", "page_size"])

    case Aegis.MCP.create_client(base_params) do
      {:ok, client} ->
        ClientPermissionManager.sync_permissions(client.id, Map.get(params, "permissions", %{}))

        socket = build_success_response(socket, client)
        {:noreply, socket}

      {:error, changeset} ->
        LiveHelpers.handle_ash_error(socket, changeset, "create client")
    end
  end

  def handle_event("update_client", %{"client" => client_params} = params, socket) do
    client = socket.assigns.editing_client

    case Aegis.MCP.update_client(client, client_params) do
      {:ok, _updated_client} ->
        ClientPermissionManager.sync_permissions(client.id, Map.get(params, "permissions", %{}))

        socket =
          socket
          |> put_flash(:info, "Client updated successfully!")
          |> assign(:show_form, false)
          |> assign(:editing_client, nil)
          |> assign(:form_mode, :create)
          |> load_clients()

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to update client: #{inspect(errors)}")}
    end
  end

  def handle_event("regenerate_api_key", %{"client_id" => client_id}, socket) do
    case Aegis.MCP.get_client!(client_id) |> then(&Aegis.MCP.regenerate_client_api_key/1) do
      {:ok, client} ->
        api_key = Ash.Resource.get_metadata(client, :plaintext_api_key)

        socket =
          socket
          |> put_flash(:info, "API key regenerated successfully!")
          |> assign(:created_client, client)
          |> assign(:api_key, api_key)
          |> load_clients()

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to regenerate API key: #{inspect(errors)}")}
    end
  end

  def handle_event("toggle_client_status", %{"client_id" => client_id}, socket) do
    client = Aegis.MCP.get_client!(client_id)

    case Aegis.MCP.update_client(client, %{active: !client.active}) do
      {:ok, _client} ->
        status = if client.active, do: "deactivated", else: "activated"

        socket =
          socket
          |> put_flash(:info, "Client #{status} successfully!")
          |> load_clients()

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to update client: #{inspect(errors)}")}
    end
  end

  def handle_event("delete_client", %{"client_id" => client_id}, socket) do
    case Aegis.MCP.get_client(client_id) do
      {:ok, client} ->
        # First, delete all client permissions
        ClientPermissionManager.clear_permissions(client_id)

        # Then delete the client
        case Aegis.MCP.delete_client(client) do
          :ok ->
            socket =
              socket
              |> put_flash(:info, "Client deleted successfully!")
              |> load_clients()

            {:noreply, socket}

          {:error, changeset} ->
            errors = Ash.Error.to_error_class(changeset)
            {:noreply, put_flash(socket, :error, "Failed to delete client: #{inspect(errors)}")}
        end

      {:error, _} ->
        # Client already deleted or doesn't exist
        socket =
          socket
          |> put_flash(:info, "Client was already deleted")
          |> load_clients()

        {:noreply, socket}
    end
  end

  def handle_event("toggle_client_permissions", %{"client_id" => client_id}, socket) do
    if socket.assigns.selected_client == client_id do
      {:noreply, assign(socket, :selected_client, nil)}
    else
      client_permissions = load_client_permissions(client_id)

      {:noreply,
       assign(socket, selected_client: client_id, client_permissions: client_permissions)}
    end
  end

  def handle_event(
        "grant_permission",
        %{"client_id" => client_id, "permission_id" => permission_id},
        socket
      ) do
    case Aegis.MCP.grant_permission(client_id, permission_id) do
      {:ok, _client_permission} ->
        client_permissions = load_client_permissions(client_id)

        socket =
          socket
          |> put_flash(:info, "Permission granted successfully!")
          |> assign(:client_permissions, client_permissions)

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ash.Error.to_error_class(changeset)
        {:noreply, put_flash(socket, :error, "Failed to grant permission: #{inspect(errors)}")}
    end
  end

  def handle_event(
        "revoke_permission",
        %{"client_id" => client_id, "permission_id" => permission_id},
        socket
      ) do
    :ok = Aegis.MCP.revoke_permission!(client_id, permission_id, %{})
    client_permissions = load_client_permissions(client_id)

    socket =
      socket
      |> put_flash(:info, "Permission revoked successfully!")
      |> assign(:client_permissions, client_permissions)

    {:noreply, socket}
  end

  def handle_event("copy_api_key", _params, socket) do
    {:noreply, put_flash(socket, :info, "API key copied to clipboard!")}
  end

  def handle_event("close_api_key_modal", _params, socket) do
    socket =
      socket
      |> assign(:created_client, nil)
      |> assign(:api_key, nil)

    {:noreply, socket}
  end

  def handle_event("load_more", _params, socket) do
    current_page = socket.assigns.clients_page

    case current_page && current_page.more? do
      true ->
        next_page = Ash.page!(current_page, :next)
        loaded_page = %{next_page | results: Ash.load!(next_page.results, :permissions)}

        socket =
          socket
          |> assign(:clients_page, loaded_page)
          |> stream(:clients, loaded_page.results, at: -1)

        {:noreply, socket}

      _ ->
        {:noreply, socket}
    end
  end

  # Helper functions

  defp build_success_response(socket, client) do
    # All clients now use API keys - get the plaintext key from metadata
    api_key = Ash.Resource.get_metadata(client, :plaintext_api_key)

    socket
    |> put_flash(:info, "Client created successfully!")
    |> assign(:show_form, false)
    |> assign(:editing_client, nil)
    |> assign(:form_mode, :create)
    |> assign(:created_client, client)
    |> assign(:api_key, api_key)
    |> load_clients()
  end

  defp load_clients(socket) do
    page =
      Aegis.MCP.list_clients!(
        query: Ash.Query.sort(Aegis.MCP.Client, created_at: :desc),
        page: [limit: socket.assigns.page_size],
        load: [:permissions]
      )

    socket
    |> assign(:clients_page, page)
    |> stream(:clients, page.results, reset: true)
  end

  defp load_permissions(socket) do
    permissions =
      Aegis.MCP.list_permissions!(
        query:
          Ash.Query.sort(Aegis.MCP.Permission,
            resource_type: :asc,
            server_name: :asc,
            action: :asc
          )
      )

    assign(socket, :permissions, permissions)
  end

  defp load_servers(socket) do
    servers = Aegis.MCP.list_servers!(query: Ash.Query.sort(Aegis.MCP.Server, name: :asc))

    assign(socket, :servers, servers)
  end

  defp load_client_permissions(client_id) do
    Aegis.MCP.list_permissions_for_client!(client_id, load: [:permission])
    |> Enum.map(& &1.permission)
  end

  defp format_resource_type(resource_type) do
    resource_type
    |> Atom.to_string()
    |> String.capitalize()
  end

  defp format_action(action) do
    action
    |> Atom.to_string()
    |> String.capitalize()
  end

  defp client_permission_granted?(client_permissions, permission_id) do
    Enum.any?(client_permissions, &(&1.id == permission_id))
  end

  # Permission management moved to ClientPermissionManager

  defp get_server_capabilities(server_name) do
    # Use cached capabilities from cache
    # ServerMonitor caches capabilities with {server_name, protocol_version} key
    alias Aegis.Cache
    alias Aegis.MCP.Constants

    protocol_version = Constants.default_protocol_version()
    cache_key = {server_name, protocol_version}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, capabilities} when is_map(capabilities) ->
        capabilities

      _ ->
        %{}
    end
  end

  def server_supports_capability?(server_name, capability) do
    capabilities = get_server_capabilities(server_name)

    case Map.get(capabilities, capability) do
      # No capability data means not supported
      nil -> false
      _capability_map -> true
    end
  end

  def client_has_permission?(client, server_name, resource_type) do
    if client && client.permissions do
      Enum.any?(client.permissions, fn permission ->
        permission.server_name == server_name && permission.resource_type == resource_type
      end)
    else
      false
    end
  end
end
