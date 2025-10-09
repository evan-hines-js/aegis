defmodule Aegis.MCP do
  @moduledoc false
  use Ash.Domain,
    otp_app: :aegis,
    extensions: [AshJsonApi.Domain]

  json_api do
    routes do
      base_route "/servers", Aegis.MCP.Server do
        get :read
        index :read
        post :create
        patch :update
        delete :destroy
      end

      base_route "/clients", Aegis.MCP.Client do
        get :read
        index :read

        post :register,
          route: "/register",
          metadata: fn _subject, client, _request ->
            case Ash.Resource.get_metadata(client, :plaintext_api_key) do
              nil -> %{}
              api_key -> %{api_key: api_key}
            end
          end

        patch :update

        patch :regenerate_api_key,
          route: "/:id/regenerate-api-key",
          metadata: fn _subject, client, _request ->
            case Ash.Resource.get_metadata(client, :plaintext_api_key) do
              nil -> %{}
              api_key -> %{api_key: api_key}
            end
          end

        delete :destroy
      end

      base_route "/permissions", Aegis.MCP.Permission do
        get :read
        index :read
        post :create
        patch :update
        delete :destroy
      end

      base_route "/client-permissions", Aegis.MCP.ClientPermission do
        get :read
        index :read
        post :create
        delete :destroy
      end
    end
  end

  resources do
    resource Aegis.MCP.PersistedSession do
      define :persist_session, action: :persist
      define :get_persisted_session_by_session_id, action: :by_session_id, args: [:session_id]
      define :destroy_persisted_session, action: :destroy
      define :list_stale_persisted_sessions, action: :stale_sessions
    end

    resource Aegis.MCP.Server do
      define :create_server, action: :create, args: [:name, :endpoint]
      define :list_servers, action: :read
      define :get_server, action: :read, get_by: [:id]
      define :get_server_by_name, action: :read, get_by: [:name]
      define :update_server, action: :update
      define :delete_server, action: :destroy
    end

    resource Aegis.MCP.Client do
      define :create_client, action: :register
      define :list_clients, action: :read
      define :get_client, action: :read, get_by: [:id]
      define :get_client_by_api_key, action: :get_by_api_key, args: [:api_key]
      define :update_client, action: :update
      define :regenerate_client_api_key, action: :regenerate_api_key
      define :delete_client, action: :destroy
    end

    resource Aegis.MCP.Permission do
      define :create_permission, action: :create
      define :list_permissions, action: :read
      define :get_permission, action: :read, get_by: [:id]

      define :list_permissions_for_resource_type,
        action: :for_resource_type,
        args: [:resource_type]

      define :list_permissions_for_server, action: :for_server, args: [:server_name]

      define :check_permission,
        action: :check_permission,
        args: [:resource_type, :server_name, :resource_pattern, :action]

      define :update_permission, action: :update
      define :delete_permission, action: :destroy
    end

    resource Aegis.MCP.ClientPermission do
      define :grant_permission, action: :grant, args: [:client_id, :permission_id]
      define :revoke_permission, action: :revoke
      define :delete_client_permission, action: :destroy
      define :list_client_permissions, action: :read
      define :list_permissions_for_client, action: :for_client, args: [:client_id]
      define :list_clients_for_permission, action: :for_permission, args: [:permission_id]
      define :get_client_permission, action: :read, get_by: [:id]
    end
  end
end
