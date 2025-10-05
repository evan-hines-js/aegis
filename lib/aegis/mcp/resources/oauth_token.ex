defmodule Aegis.MCP.OAuthToken do
  @moduledoc false
  use Ash.Resource,
    otp_app: :aegis,
    domain: Aegis.MCP,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshCloak]

  require Ash.Query

  postgres do
    table "oauth_tokens"
    repo Aegis.Repo
  end

  cloak do
    vault(Aegis.Vault)
    attributes [:access_token, :refresh_token]
  end

  code_interface do
    define :create_token,
      args: [:client_id, :keycloak_client_id, :access_token, :refresh_token, :expires_in, :scopes]

    define :get_by_client, action: :by_client, args: [:client_id]
    define :get_by_keycloak_client_id, action: :by_keycloak_client_id, args: [:keycloak_client_id]
    define :update_token, action: :update
    define :refresh_token, action: :refresh_token
    define :list, action: :read
  end

  actions do
    defaults [:read, :update, :destroy]

    create :create_token do
      primary? true
      upsert? true
      upsert_identity :unique_client_keycloak

      accept [
        :keycloak_client_id,
        :access_token,
        :refresh_token,
        :expires_in,
        :scopes,
        :state
      ]

      argument :client_id, :uuid do
        allow_nil? false
      end

      change manage_relationship(:client_id, :client, type: :append_and_remove)
    end

    read :by_client do
      argument :client_id, :uuid do
        allow_nil? false
      end

      filter expr(client_id == ^arg(:client_id) and active == true)
    end

    read :by_keycloak_client_id do
      argument :keycloak_client_id, :string do
        allow_nil? false
      end

      filter expr(keycloak_client_id == ^arg(:keycloak_client_id) and active == true)
    end

    update :refresh_token do
      require_atomic? false
      accept [:access_token, :refresh_token, :expires_in, :refreshed_at]

      change fn changeset, _context ->
        Ash.Changeset.change_attribute(changeset, :refreshed_at, DateTime.utc_now())
      end
    end

    update :revoke_token do
      require_atomic? false
      accept []

      change fn changeset, _context ->
        changeset
        |> Ash.Changeset.change_attribute(:revoked_at, DateTime.utc_now())
        |> Ash.Changeset.change_attribute(:active, false)
      end
    end
  end

  policies do
    # Allow OAuth token operations for the proxy system
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy action_type([:create, :read, :update, :destroy]) do
      # Allow for OAuth proxy operations
      authorize_if always()
    end
  end

  preparations do
    prepare build(load: [:client])
  end

  attributes do
    uuid_primary_key :id

    attribute :keycloak_client_id, :string do
      allow_nil? false
      public? true
      description "Keycloak client ID returned from client registration"
    end

    # Encrypted token fields
    attribute :access_token, :string do
      allow_nil? false
      public? true
      sensitive? true
      description "Encrypted OAuth access token"
    end

    attribute :refresh_token, :string do
      allow_nil? true
      public? true
      sensitive? true
      description "Encrypted OAuth refresh token"
    end

    attribute :expires_in, :integer do
      allow_nil? true
      public? true
      description "Token lifetime in seconds"
    end

    attribute :scopes, :string do
      allow_nil? true
      public? true
      description "OAuth scopes granted to this token"
    end

    attribute :state, :string do
      allow_nil? true
      public? true
      description "OAuth state parameter for tracking authorization flow"
    end

    attribute :active, :boolean do
      allow_nil? false
      public? true
      default true
      description "Whether this token is currently active"
    end

    attribute :refreshed_at, :utc_datetime_usec do
      allow_nil? true
      public? true
      description "When this token was last refreshed"
    end

    attribute :revoked_at, :utc_datetime_usec do
      allow_nil? true
      public? true
      description "When this token was revoked"
    end

    timestamps()
  end

  relationships do
    belongs_to :client, Aegis.MCP.Client do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_client_keycloak, [:client_id, :keycloak_client_id] do
      nils_distinct? false
      description "Each client can have only one token per Keycloak client"
    end
  end
end
