defmodule Aegis.MCP.Client do
  @moduledoc false
  use Ash.Resource,
    otp_app: :aegis,
    domain: Aegis.MCP,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshJsonApi.Resource, AshCloak]

  require Ash.Query

  alias Aegis.MCP.ApiKeyUtils

  postgres do
    table "mcp_clients"
    repo Aegis.Repo
  end

  json_api do
    type "mcp_client"
  end

  code_interface do
    define :register, args: [:name]
    define :get_by_id, action: :read, get_by: [:id]
    define :get_by_name, action: :read, get_by: [:name]
    define :get_by_api_key, args: [:api_key]
    define :list, action: :read
    define :update
    define :regenerate_api_key
    define :destroy
  end

  actions do
    defaults [:read]

    update :update do
      primary? true
      require_atomic? false

      accept [
        :name,
        :description,
        :active
      ]

      change after_transaction(fn _changeset, result, _context ->
               case result do
                 {:ok, client} ->
                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "client_changes",
                     {:client_updated, client}
                   )

                   result

                 error ->
                   error
               end
             end)
    end

    destroy :destroy do
      primary? true
      require_atomic? false

      change after_transaction(fn _changeset, result, _context ->
               case result do
                 {:ok, client} ->
                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "client_changes",
                     {:client_deleted, client}
                   )

                   result

                 error ->
                   error
               end
             end)
    end

    create :register do
      primary? true
      description "Register a new MCP client with auto-generated API key"

      accept [
        :name,
        :description
      ]

      change fn changeset, _context ->
        api_key = generate_api_key()
        api_key_hash = hash_api_key(api_key)
        api_key_lookup_hash = lookup_hash_api_key(api_key)

        changeset
        |> Ash.Changeset.change_attribute(:api_key_hash, api_key_hash)
        |> Ash.Changeset.change_attribute(:api_key_lookup_hash, api_key_lookup_hash)
        |> Ash.Changeset.after_action(fn _changeset, client ->
          {:ok, Ash.Resource.set_metadata(client, %{plaintext_api_key: api_key})}
        end)
      end

      change after_transaction(fn _changeset, result, _context ->
               case result do
                 {:ok, client} ->
                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "client_changes",
                     {:client_created, client}
                   )

                   result

                 error ->
                   error
               end
             end)
    end

    update :regenerate_api_key do
      require_atomic? false
      description "Generate a new API key for the client"
      accept []

      change fn changeset, _context ->
        # Capture the old API key hash before changing it
        old_api_key_hash = Ash.Changeset.get_attribute(changeset, :api_key_hash)

        api_key = generate_api_key()
        api_key_hash = hash_api_key(api_key)
        api_key_lookup_hash = lookup_hash_api_key(api_key)

        changeset
        |> Ash.Changeset.change_attribute(:api_key_hash, api_key_hash)
        |> Ash.Changeset.change_attribute(:api_key_lookup_hash, api_key_lookup_hash)
        |> Ash.Changeset.after_action(fn _changeset, client ->
          client_with_metadata =
            client
            |> Ash.Resource.set_metadata(%{plaintext_api_key: api_key})
            |> Ash.Resource.set_metadata(%{old_api_key_hash: old_api_key_hash})

          {:ok, client_with_metadata}
        end)
      end

      change after_transaction(fn _changeset, result, _context ->
               case result do
                 {:ok, client} ->
                   old_api_key_hash = Ash.Resource.get_metadata(client, :old_api_key_hash)

                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "client_changes",
                     {:api_key_regenerated, client, old_api_key_hash}
                   )

                   result

                 error ->
                   error
               end
             end)
    end

    read :get_by_api_key do
      description "Find client by API key for authentication"
      get? true

      argument :api_key, :string do
        allow_nil? false
        sensitive? true
      end

      prepare fn query, _context ->
        case Ash.Query.get_argument(query, :api_key) do
          api_key when is_binary(api_key) ->
            api_key_lookup_hash = lookup_hash_api_key(api_key)

            query
            |> Ash.Query.filter(api_key_lookup_hash == ^api_key_lookup_hash)
            |> Ash.Query.filter(active == true)

          _ ->
            # Return a query that will never match
            Ash.Query.filter(query, false)
        end
      end
    end
  end

  policies do
    # Only authenticated admin users can manage MCP clients
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy action_type([:create, :read, :update, :destroy]) do
      # Add proper admin authorization here
      authorize_if always()
    end
  end

  attributes do
    uuid_v7_primary_key :id

    attribute :name, :string do
      allow_nil? false
      public? true
      description "Human-readable name for the MCP client"
    end

    attribute :description, :string do
      allow_nil? true
      public? true
      description "Purpose or owner description for the client"
    end

    attribute :api_key_hash, :string do
      allow_nil? false
      public? false
      sensitive? true
      description "Encrypted API key for client authentication"
    end

    attribute :api_key_lookup_hash, :string do
      allow_nil? false
      public? false
      description "Fast lookup hash for API key indexing"
    end

    attribute :active, :boolean do
      allow_nil? false
      public? true
      default true
      description "Whether the client is active and can authenticate"
    end

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  # Private functions for API key management
  defp generate_api_key do
    ApiKeyUtils.generate_api_key()
  end

  defp hash_api_key(api_key) do
    ApiKeyUtils.hash_api_key(api_key)
  end

  defp lookup_hash_api_key(api_key) do
    ApiKeyUtils.lookup_hash(api_key)
  end

  relationships do
    many_to_many :permissions, Aegis.MCP.Permission do
      through Aegis.MCP.ClientPermission
      source_attribute_on_join_resource :client_id
      destination_attribute_on_join_resource :permission_id
    end
  end

  identities do
    identity :unique_name, [:name]
  end
end
