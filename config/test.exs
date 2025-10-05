import Config
config :aegis, Oban, testing: :manual
config :aegis, token_signing_secret: "//DSYgQ045dPOIVT3+H4QLVTDHdd0XhT"
config :aegis, keycloak_base_url: "http://localhost:8080"
config :bcrypt_elixir, log_rounds: 1
config :ash, policies: [show_policy_breakdowns?: true], disable_async?: true

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :aegis, Aegis.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "aegis_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :aegis, AegisWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "Ij8XO3dQmi99Rq+vhdfBhqTLwVm5HwDu/BrZnIpLQiK07NDIKDXcrYFvawD1b8rX",
  server: false

# In test we don't send emails
config :aegis, Aegis.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Test configuration for smart pagination
config :aegis, :smart_pagination,
  # Keep sorting enabled in tests to test the functionality
  sorting_enabled: true,
  # Disable analytics in tests for faster execution
  analytics_enabled: false,
  # Use minimal decay values for predictable test behavior
  usage_decay_hours: 1,
  recency_decay_hours: 0.1,
  # Minimal retention for tests
  analytics_retention_days: 1
