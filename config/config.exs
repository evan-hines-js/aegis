# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :ash_oban, pro?: false

config :aegis, Oban,
  engine: Oban.Engines.Basic,
  notifier: Oban.Notifiers.Postgres,
  queues: [default: 10],
  repo: Aegis.Repo,
  plugins: [{Oban.Plugins.Cron, []}]

config :mime,
  extensions: %{"json" => "application/vnd.api+json"},
  types: %{
    "application/vnd.api+json" => ["json"],
    "text/event-stream" => ["event-stream"]
  }

# JWT validation configuration for OIDC providers
config :aegis, Aegis.MCP.JWTValidator,
  issuer: "http://localhost:8080/realms/aegis-mcp",
  audience: "aegis-mcp-hub",
  # JWKS endpoint - configurable for any OIDC provider
  jwks_url: "http://localhost:8080/realms/aegis-mcp/protocol/openid-connect/certs"

# OAuth 2.0 Protected Resource Metadata configuration (RFC 9728)
config :aegis, Aegis.MCP.OAuth.ProtectedResourceMetadata,
  authorization_servers: ["http://localhost:8080/realms/aegis-mcp"],
  resource_documentation: "https://docs.aegis-mcp.example.com/oauth"

# WWW-Authenticate header configuration
config :aegis, Aegis.MCP.OAuth.WWWAuthenticate, realm: "Aegis MCP Server"

config :ash_json_api,
  show_public_calculations_when_loaded?: false,
  authorize_update_destroy_with_error?: true

config :ash,
  allow_forbidden_field_for_relationships_by_default?: true,
  include_embedded_source_by_default?: false,
  show_keysets_for_all_actions?: false,
  default_page_type: :keyset,
  policies: [no_filter_static_forbidden_reads?: false],
  keep_read_action_loads_when_loading?: false,
  default_actions_require_atomic?: true,
  read_action_after_action_hooks_in_order?: true,
  bulk_actions_default_to_errors?: true

config :spark,
  formatter: [
    remove_parens?: true,
    "Ash.Resource": [
      section_order: [
        :admin,
        :authentication,
        :tokens,
        :postgres,
        :json_api,
        :resource,
        :code_interface,
        :actions,
        :policies,
        :pub_sub,
        :preparations,
        :changes,
        :validations,
        :multitenancy,
        :attributes,
        :relationships,
        :calculations,
        :aggregates,
        :identities
      ]
    ],
    "Ash.Domain": [
      section_order: [
        :admin,
        :json_api,
        :resources,
        :policies,
        :authorization,
        :domain,
        :execution
      ]
    ]
  ]

config :aegis,
  ecto_repos: [Aegis.Repo],
  generators: [timestamp_type: :utc_datetime],
  ash_domains: [Aegis.MCP, Aegis.Accounts]

# Cloak encryption configuration
# Note: In production, the key is loaded from environment variables in runtime.exs
config :aegis, Aegis.Vault,
  ciphers: [
    default: {
      Cloak.Ciphers.AES.GCM,
      # Development key only - DO NOT USE IN PRODUCTION
      tag: "AES.GCM.V1", key: "TVDTWhPqVXPQTcJX4f0+Dut5+0rdABzC", iv_length: 12
    }
  ]

# Audit logging configuration
config :aegis, :audit_logging,
  # Enable/disable audit logging globally
  enabled: true,

  # Critical security events that require synchronous logging
  # If these events cannot be logged, the request will fail
  sync_events: [
    :authentication_success,
    :authentication_failure,
    :token_validation_failure,
    :authorization_denied,
    :rate_limit_exceeded
  ],

  # Granular control over which event types to log
  # Set to false to disable logging for specific event types
  event_logging: %{
    # Authentication events
    authentication_success: true,
    authentication_failure: true,
    token_validation_success: true,
    token_validation_failure: true,

    # Authorization events
    authorization_granted: true,
    authorization_denied: true,

    # MCP operations (typically high volume)
    mcp_request: true,
    tools_list: true,
    tools_call: true,
    resources_list: true,
    resources_read: true,
    prompts_list: true,
    prompts_read: true,

    # Client management
    client_created: true,
    client_updated: true,
    client_deactivated: true,
    client_permissions_modified: true,

    # System events
    session_created: true,
    session_expired: true,
    rate_limit_exceeded: true,
    system_error: true
  }

# Configures the endpoint
config :aegis, AegisWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: AegisWeb.ErrorHTML, json: AegisWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Aegis.PubSub,
  live_view: [signing_salt: "klNDqM0O"]

# Rate limiting configuration - uses environment variables in all environments
config :aegis, :rate_limits,
  tool_calls: {String.to_integer(System.get_env("MCP_TOOL_CALLS_LIMIT") || "100"), 60_000},
  list_operations:
    {String.to_integer(System.get_env("MCP_LIST_OPERATIONS_LIMIT") || "500"), 60_000},
  resource_reads:
    {String.to_integer(System.get_env("MCP_RESOURCE_READS_LIMIT") || "1000"), 60_000},
  default_operations:
    {String.to_integer(System.get_env("MCP_DEFAULT_OPERATIONS_LIMIT") || "200"), 60_000},
  server_info: {String.to_integer(System.get_env("MCP_SERVER_INFO_LIMIT") || "2000"), 60_000},
  sse_streams: {String.to_integer(System.get_env("MCP_SSE_STREAMS_LIMIT") || "50"), 60_000},
  session_deletion:
    {String.to_integer(System.get_env("MCP_SESSION_DELETION_LIMIT") || "100"), 60_000},
  fallback: {String.to_integer(System.get_env("MCP_FALLBACK_LIMIT") || "100"), 60_000}

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :aegis, Aegis.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  aegis: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.1.7",
  aegis: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id, :client_id, :method, :rule]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
