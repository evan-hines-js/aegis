defmodule Aegis.MCP.Server do
  @moduledoc false
  use Ash.Resource,
    otp_app: :aegis,
    domain: Aegis.MCP,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshJsonApi.Resource, AshCloak]

  postgres do
    table "servers"
    repo Aegis.Repo
  end

  json_api do
    type "server"
  end

  cloak do
    vault(Aegis.Vault)
    attributes [:api_key]
  end

  code_interface do
    define :create, args: [:name, :endpoint]
    define :get_by_name, action: :read, get_by: [:name]
    define :list, action: :read
    define :update
    define :destroy
  end

  actions do
    defaults [:read]

    create :create do
      primary? true

      accept [
        :name,
        :endpoint,
        :auth_type,
        :api_key,
        :api_key_header,
        :api_key_template
      ]

      change after_transaction(fn _changeset, result, _context ->
               case result do
                 {:ok, server} ->
                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "server_changes",
                     {:server_created, server}
                   )

                   result

                 error ->
                   error
               end
             end)
    end

    update :update do
      primary? true
      require_atomic? false

      accept [
        :name,
        :endpoint,
        :auth_type,
        :api_key,
        :api_key_header,
        :api_key_template,
        :capabilities
      ]

      change after_transaction(fn _changeset, result, _context ->
               case result do
                 {:ok, server} ->
                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "server_changes",
                     {:server_updated, server}
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
                 {:ok, server} ->
                   Phoenix.PubSub.broadcast(
                     Aegis.PubSub,
                     "server_changes",
                     {:server_deleted, server}
                   )

                   result

                 error ->
                   error
               end
             end)
    end
  end

  attributes do
    uuid_v7_primary_key :id

    attribute :name, :string, allow_nil?: false, public?: true

    attribute :endpoint, :string, allow_nil?: false, public?: true

    attribute :auth_type, :atom do
      allow_nil? false
      public? true
      default :none
      constraints one_of: [:none, :api_key]
    end

    attribute :api_key, :string do
      allow_nil? true
      public? true
      sensitive? true
    end

    attribute :api_key_header, :string do
      allow_nil? true
      public? true
      default "Authorization"
      description "HTTP header name for API key (e.g., 'Authorization', 'X-API-Key')"
    end

    attribute :api_key_template, :string do
      allow_nil? true
      public? true
      default "{API_KEY}"

      description "Template for API key value. Use {API_KEY} as placeholder (e.g., 'Bearer {API_KEY}', '{API_KEY}')"
    end

    attribute :capabilities, :map do
      allow_nil? true
      public? true
      default %{}
      description "Cached server capabilities from last successful fetch"
    end

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_name, [:name]
  end
end
