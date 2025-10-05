export SECRET_KEY_BASE=SWsBXQVBzhXXmZ/CjNnTlWyATxjRmqtcftJvZSItWOjulAKlIUQSKBg4C6ie19TB
export TOKEN_SIGNING_SECRET=zm3QHvRqAAtwEnrICRW4vv8Jm/MVf0ebWxYbzuo1qlOcnCStvIi4SW6+keDq6fpE
export DATABASE_URL=ecto://postgres:postgres@localhost:5432/aegis_dev
 export ENCRYPTION_KEY=TVDTWhPqVXPQTcJX4f0+Dut5+0rdABzC
 export PHX_HOST=localhost
export ALLOWED_ORIGINS=http://localhost:4000,https://localhost:4000,http://127.0.0.1:4000,https://127.0.0.1:4000

# Rate limiting configuration for load testing
export MCP_TOOL_CALLS_LIMIT=999999
export MCP_LIST_OPERATIONS_LIMIT=999999
export MCP_RESOURCE_READS_LIMIT=999999
export MCP_DEFAULT_OPERATIONS_LIMIT=999999
export MCP_SERVER_INFO_LIMIT=999999
export MCP_SSE_STREAMS_LIMIT=999999
export MCP_SESSION_DELETION_LIMIT=999999
export ERL_CRASH_DUMP_SECONDS=30
ulimit -c unlimited
POOL_SIZE=50 PORT=$1 MIX_ENV=dev iex -S mix phx.server  
