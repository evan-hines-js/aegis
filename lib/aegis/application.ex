defmodule Aegis.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      AegisWeb.Telemetry,
      Aegis.Vault,
      Aegis.Repo,
      {DNSCluster, query: Application.get_env(:aegis, :dns_cluster_query) || :ignore},
      {Cluster.Supervisor,
       [Application.get_env(:libcluster, :topologies, []), [name: Aegis.ClusterSupervisor]]},
      # HTTP connection pool for backend MCP servers (high-concurrency)
      {Finch,
       name: Aegis.Finch,
       pools: %{
         # Default pool for all backend MCP server connections
         :default => [
           # 1000 connections per pool
           size: 1000,
           # 10 pools = 10000 total concurrent connections
           count: 10,
           # Connection pool settings - increased from 30s to reduce idle timeout errors
           pool_max_idle_time: :timer.seconds(60),
           conn_opts: [
             # Transport options for HTTP/1.1 and HTTP/2
             transport_opts: [
               # Increase socket buffer for high throughput
               sndbuf: 65_536,
               recbuf: 65_536,
               # TCP keepalive to detect dead connections
               keepalive: true
             ]
           ]
         ]
       }},
      {Oban,
       AshOban.config(
         Application.fetch_env!(:aegis, :ash_domains),
         Application.fetch_env!(:aegis, Oban)
       )},
      {Phoenix.PubSub, name: Aegis.PubSub},
      {Task.Supervisor, name: Aegis.TaskSupervisor},
      # Session lifecycle manager (single GenServer for all sessions)
      Aegis.MCP.SessionManager,
      # Distributed rate limiter for MCP endpoints
      Aegis.MCP.DistributedRateLimiter,
      # Start cache system
      Aegis.Cache,
      # Start MCP server management
      Aegis.MCP.Supervisor,
      # Start a worker by calling: Aegis.Worker.start_link(arg)
      # {Aegis.Worker, arg},
      # Start to serve requests, typically the last entry
      AegisWeb.Endpoint,
      {AshAuthentication.Supervisor, [otp_app: :aegis]}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Aegis.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    AegisWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  @impl true
  def prep_stop(state) do
    try do
      :ok
    rescue
      # Graceful shutdown
      _ -> :ok
    catch
      # Process might be down
      :exit, _ -> :ok
    end

    state
  end
end
