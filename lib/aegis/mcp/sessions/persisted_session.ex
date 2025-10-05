defmodule Aegis.MCP.PersistedSession do
  @moduledoc """
  Temporary persistence for sessions during rolling restarts.

  When a node shuts down (SIGTERM), it persists active sessions to this table.
  When a client request hits a new node, the session is lazy-loaded from here.
  Sessions are deleted from this table once restored to ETS.

  This enables zero-downtime rolling restarts with sticky session routing.
  """

  use Ash.Resource,
    domain: Aegis.MCP,
    data_layer: AshPostgres.DataLayer

  postgres do
    table "mcp_persisted_sessions"
    repo Aegis.Repo
  end

  code_interface do
    define :persist_session, action: :persist
    define :get_by_session_id, action: :by_session_id, args: [:session_id]
    define :destroy_persisted_session, action: :destroy
    define :list_stale_sessions, action: :stale_sessions
  end

  actions do
    defaults [:read, :destroy]

    create :persist do
      accept [:session_id, :client_id, :session_data, :persisted_at]
      upsert? true
      upsert_identity :unique_session_id
    end

    read :by_session_id do
      get? true
      argument :session_id, :string, allow_nil?: false
      filter expr(session_id == ^arg(:session_id))
    end

    read :stale_sessions do
      description "Find persisted sessions older than 1 hour (likely orphaned)"

      filter expr(fragment("? < NOW() - INTERVAL '1 hour'", persisted_at))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :session_id, :string do
      allow_nil? false
      public? true
    end

    attribute :client_id, :string do
      allow_nil? false
      public? true
    end

    attribute :session_data, :map do
      allow_nil? false
      public? true
    end

    attribute :persisted_at, :utc_datetime_usec do
      allow_nil? false
      default &DateTime.utc_now/0
      public? true
    end

    timestamps()
  end

  identities do
    identity :unique_session_id, [:session_id]
  end
end
