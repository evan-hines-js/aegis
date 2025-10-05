defmodule Aegis.MCP.Supervisor do
  @moduledoc false
  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    # Create ETS tables that are still actively used
    :ets.new(:jwks_cache, [:named_table, :set, :public, read_concurrency: true])

    children = [
      {Registry, keys: :unique, name: Aegis.MCP.ServerMonitorRegistry},
      {Aegis.MCP.ServerManager, []},
      {Aegis.MCP.ClientManager, []},
      {Aegis.MCP.ServerMonitorSupervisor, []},
      {Aegis.MCP.NotificationDebouncer, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
