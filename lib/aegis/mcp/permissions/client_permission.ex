defmodule Aegis.MCP.ClientPermission do
  @moduledoc false
  use Ash.Resource,
    otp_app: :aegis,
    domain: Aegis.MCP,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshJsonApi.Resource]

  alias Aegis.MCP.{
    Authorization,
    NotificationDebouncer,
    ServerContentCache,
    ServerManager
  }

  postgres do
    table "mcp_client_permissions"
    repo Aegis.Repo
  end

  json_api do
    type "mcp_client_permission"
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]

    create :grant do
      description "Grant a permission to a client"
      accept [:client_id, :permission_id]

      argument :client_id, :uuid do
        allow_nil? false
      end

      argument :permission_id, :uuid do
        allow_nil? false
      end

      change set_attribute(:client_id, arg(:client_id))
      change set_attribute(:permission_id, arg(:permission_id))
      change after_action(&invalidate_permission_cache_for_grant/3)
    end

    read :for_client do
      description "Get all permissions for a specific client"

      argument :client_id, :uuid do
        allow_nil? false
      end

      filter expr(client_id == ^arg(:client_id))
    end

    read :for_permission do
      description "Get all clients that have a specific permission"

      argument :permission_id, :uuid do
        allow_nil? false
      end

      filter expr(permission_id == ^arg(:permission_id))
    end

    destroy :revoke do
      description "Revoke a permission from a client"
      require_atomic? false
      change after_action(&invalidate_permission_cache_for_revoke/3)
    end
  end

  policies do
    # Only authenticated admin users can manage client permissions
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy action_type([:create, :read, :update, :destroy]) do
      # Add proper admin authorization here
      authorize_if always()
    end
  end

  validations do
    validate present([:client_id, :permission_id])
  end

  attributes do
    uuid_v7_primary_key :id

    attribute :client_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :permission_id, :uuid do
      allow_nil? false
      public? true
    end

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :client, Aegis.MCP.Client do
      source_attribute :client_id
      destination_attribute :id
    end

    belongs_to :permission, Aegis.MCP.Permission do
      source_attribute :permission_id
      destination_attribute :id
    end
  end

  identities do
    # Ensure a client can't have the same permission granted twice
    identity :unique_client_permission, [:client_id, :permission_id]
  end

  # Cache invalidation functions - simplified approach

  defp invalidate_permission_cache_for_grant(changeset, result, _context) do
    client_id = Ash.Changeset.get_attribute(changeset, :client_id)
    invalidate_cache_if_present(client_id)
    {:ok, result}
  end

  defp invalidate_permission_cache_for_revoke(_changeset, result, _context) do
    # For revoke operations, extract client_id from the returned record
    case result do
      %{client_id: client_id} when not is_nil(client_id) ->
        invalidate_cache_if_present(client_id)

      _ ->
        # If we can't get client_id from result, we could log a warning
        # but the operation should still succeed
        :ok
    end

    {:ok, result}
  end

  defp invalidate_cache_if_present(nil), do: :ok

  defp invalidate_cache_if_present(client_id) when is_binary(client_id) do
    # Invalidate the client's permission cache
    Authorization.invalidate_client_permissions(client_id)

    # Immediately refresh the client's permissions to avoid race conditions
    # This ensures the cache has fresh data before any SSE notifications are sent
    case Authorization.refresh_client_permissions(client_id) do
      {:ok, _permissions} ->
        :ok

      {:error, reason} ->
        require Logger

        Logger.warning(
          "Failed to refresh permissions after cache invalidation for client #{client_id}: #{inspect(reason)}"
        )
    end

    # Invalidate all server content caches to ensure fresh data on next request
    ServerContentCache.invalidate_all_content()

    # Schedule debounced notification to prevent multiple rapid events for batch permission changes
    NotificationDebouncer.schedule(:permission_changed, client_id, fn ->
      ServerManager.notify_client_permissions_changed(client_id)
    end)
  end

  defp invalidate_cache_if_present(_), do: :ok
end
