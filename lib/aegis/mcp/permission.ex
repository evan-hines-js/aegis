defmodule Aegis.MCP.Permission do
  @moduledoc false
  use Ash.Resource,
    otp_app: :aegis,
    domain: Aegis.MCP,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshJsonApi.Resource]

  require Ash.Query
  alias Aegis.MCP.PatternMatcher

  postgres do
    table "mcp_permissions"
    repo Aegis.Repo
  end

  json_api do
    type "mcp_permission"
  end

  actions do
    defaults [:read, create: :*]

    destroy :destroy do
      primary? true
      require_atomic? false

      change before_action(fn changeset, _context ->
               permission_id = Ash.Changeset.get_attribute(changeset, :id) || changeset.data.id

               # Delete all client_permissions that reference this permission
               query =
                 Ash.Query.filter(Aegis.MCP.ClientPermission, permission_id == ^permission_id)

               client_permissions = Aegis.MCP.list_client_permissions!(query: query)
               Enum.each(client_permissions, &Aegis.MCP.delete_client_permission!/1)

               changeset
             end)
    end

    update :update do
      accept [:resource_type, :server_name, :resource_pattern, :action, :description]
      require_atomic? false
    end

    read :for_resource_type do
      description "Get permissions filtered by resource type"

      argument :resource_type, :atom do
        allow_nil? false
        constraints one_of: [:tools, :resources, :prompts]
      end

      filter expr(resource_type == ^arg(:resource_type))
    end

    read :for_server do
      description "Get permissions for a specific server"

      argument :server_name, :string do
        allow_nil? false
      end

      filter expr(server_name == ^arg(:server_name) or server_name == "*")
    end

    read :check_permission do
      description "Check if permission exists for specific resource access"
      get? true

      argument :resource_type, :atom do
        allow_nil? false
        constraints one_of: [:tools, :resources, :prompts]
      end

      argument :server_name, :string do
        allow_nil? false
      end

      argument :resource_pattern, :string do
        allow_nil? false
      end

      argument :action, :atom do
        allow_nil? false
        constraints one_of: [:read, :call]
      end

      filter expr(
               resource_type == ^arg(:resource_type) and
                 (server_name == ^arg(:server_name) or server_name == "*") and
                 (resource_pattern == ^arg(:resource_pattern) or resource_pattern == "*") and
                 action == ^arg(:action)
             )
    end
  end

  policies do
    # Only authenticated admin users can manage permissions
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy action_type([:create, :read, :update, :destroy]) do
      # Add proper admin authorization here
      authorize_if always()
    end
  end

  validations do
    validate present([:resource_type, :server_name, :resource_pattern, :action])

    validate fn changeset, _context ->
      server_name = Ash.Changeset.get_attribute(changeset, :server_name)
      resource_pattern = Ash.Changeset.get_attribute(changeset, :resource_pattern)

      PatternMatcher.validate_permission_pattern(server_name, resource_pattern)
    end
  end

  attributes do
    uuid_v7_primary_key :id

    attribute :resource_type, :atom do
      allow_nil? false
      public? true
      constraints one_of: [:tools, :resources, :prompts]
      description "Type of MCP resource (tools, resources, prompts)"
    end

    attribute :server_name, :string do
      allow_nil? false
      public? true
      description "MCP server name or '*' for all servers"
    end

    attribute :resource_pattern, :string do
      allow_nil? false
      public? true
      description "Specific resource name or '*' for all resources"
    end

    attribute :action, :atom do
      allow_nil? false
      public? true
      constraints one_of: [:read, :call]
      description "Allowed action on the resource"
    end

    attribute :description, :string do
      allow_nil? true
      public? true
      description "Human-readable description of the permission"
    end

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  relationships do
    has_many :client_permissions, Aegis.MCP.ClientPermission do
      destination_attribute :permission_id
    end

    many_to_many :clients, Aegis.MCP.Client do
      through Aegis.MCP.ClientPermission
      source_attribute_on_join_resource :permission_id
      destination_attribute_on_join_resource :client_id
    end
  end

  identities do
    # Ensure unique permission combinations
    identity :unique_permission, [:resource_type, :server_name, :resource_pattern, :action]
  end
end
