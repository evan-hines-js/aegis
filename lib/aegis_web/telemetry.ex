defmodule AegisWeb.Telemetry do
  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      # Telemetry poller will execute the given period measurements
      # every 10_000ms. Learn more here: https://hexdocs.pm/telemetry_metrics
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}
      # Add reporters as children of your supervision tree.
      # {Telemetry.Metrics.ConsoleReporter, metrics: metrics()}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      # Phoenix Metrics
      summary("phoenix.endpoint.start.system_time",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.start.system_time",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.exception.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.stop.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.socket_connected.duration",
        unit: {:native, :millisecond}
      ),
      sum("phoenix.socket_drain.count"),
      summary("phoenix.channel_joined.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.channel_handled_in.duration",
        tags: [:event],
        unit: {:native, :millisecond}
      ),

      # Database Metrics
      summary("aegis.repo.query.total_time",
        unit: {:native, :millisecond},
        description: "The sum of the other measurements"
      ),
      summary("aegis.repo.query.decode_time",
        unit: {:native, :millisecond},
        description: "The time spent decoding the data received from the database"
      ),
      summary("aegis.repo.query.query_time",
        unit: {:native, :millisecond},
        description: "The time spent executing the query"
      ),
      summary("aegis.repo.query.queue_time",
        unit: {:native, :millisecond},
        description: "The time spent waiting for a database connection"
      ),
      summary("aegis.repo.query.idle_time",
        unit: {:native, :millisecond},
        description:
          "The time the connection spent waiting before being checked out for the query"
      ),

      # VM Metrics
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io"),

      # Aegis MCP Session Metrics
      counter("aegis.session.created.count"),
      counter("aegis.session.terminated.count"),

      # Performance Metrics - Hot Path Monitoring
      summary("aegis.pagination.fetch_from_servers.duration",
        unit: {:native, :microsecond},
        description: "Time to fetch data from backend MCP servers",
        tags: [:method]
      ),
      summary("aegis.pagination.extract_and_filter.duration",
        unit: {:native, :microsecond},
        description: "Time to filter and process items",
        tags: [:method]
      ),
      summary("aegis.authorization.get_permissions.duration",
        unit: {:native, :microsecond},
        description: "Time to fetch client permissions (should be <1ms from cache)"
      ),
      summary("aegis.session_manager.cleanup.duration_ms",
        unit: {:native, :millisecond},
        description: "Time for periodic session cleanup"
      ),
      counter("aegis.session_manager.cleanup.cleanup_count",
        description: "Number of sessions cleaned up"
      ),

      # Plug Performance Metrics
      summary("aegis.plug.api_key_auth.duration",
        unit: {:native, :microsecond},
        description: "API key authentication plug duration",
        tags: []
      ),
      summary("aegis.plug.rate_limit.duration",
        unit: {:native, :microsecond},
        description: "Rate limiting plug duration (distributed coordination)",
        tags: []
      ),

      # Rate Limiter Internal Metrics
      summary("aegis.rate_limiter.check.duration",
        unit: {:native, :microsecond},
        description: "Total rate limiter check duration (broadcast + local check)",
        tags: []
      ),
      summary("aegis.rate_limiter.check.broadcast_duration",
        unit: {:native, :microsecond},
        description: "PubSub broadcast duration within rate limiter",
        tags: []
      ),

      # MCP HTTP Request Metrics (Controller + Plugs)
      summary("aegis.mcp.http_request.duration",
        unit: {:native, :microsecond},
        description: "Full HTTP request time including plugs (auth, rate limit, body parsing)",
        tags: [:method]
      ),

      # MCP Request Metrics (Handler Only)
      summary("aegis.mcp.request.duration",
        unit: {:native, :microsecond},
        description: "Request handler processing time (excludes plugs)",
        tags: [:method, :client_id, :status]
      ),
      counter("aegis.mcp.request.count",
        description: "Total MCP requests",
        tags: [:method, :status]
      ),

      # Track slow request outliers
      distribution("aegis.mcp.request.duration",
        unit: {:native, :millisecond},
        description: "Request duration distribution to spot outliers",
        reporter_options: [
          buckets: [10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
        ],
        tags: [:method]
      ),

      # MCP Handler Metrics (Component-Level)
      summary("aegis.mcp.tool_call.duration",
        unit: {:native, :microsecond},
        description: "Time to execute MCP tool calls on backend servers",
        tags: [:server, :tool]
      ),
      summary("aegis.mcp.resources_read.duration",
        unit: {:native, :microsecond},
        description: "Time to read resources from backend servers",
        tags: [:client_id]
      ),
      summary("aegis.mcp.prompts_get.duration",
        unit: {:native, :microsecond},
        description: "Time to get prompts from backend servers",
        tags: [:client_id]
      ),

      # Cache Performance Metrics
      summary("aegis.cache.get.duration",
        unit: {:native, :microsecond},
        description: "Time to get value from cache",
        tags: [:table, :result]
      ),
      counter("aegis.cache.get.count",
        description: "Total cache get operations",
        tags: [:table, :result]
      ),
      distribution("aegis.cache.hit_rate",
        description: "Cache hit rate percentage",
        unit: :percent,
        tags: [:table]
      )
    ]
  end

  defp periodic_measurements do
    [
      # A module, function and arguments to be invoked periodically.
      # This function must call :telemetry.execute/3 and a metric must be added above.
      # {AegisWeb, :count_users, []}
    ]
  end
end
