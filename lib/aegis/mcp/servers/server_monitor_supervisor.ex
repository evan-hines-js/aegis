defmodule Aegis.MCP.ServerMonitorSupervisor do
  @moduledoc """
  DynamicSupervisor for managing per-server monitor processes.

  Each server gets its own ServerMonitor process that manages:
  - Backend session initialization and storage
  - Health monitoring and content fetching
  - Change detection and notifications
  """

  use DynamicSupervisor
  require Logger

  alias Aegis.MCP.ServerMonitor

  def start_link(init_arg) do
    DynamicSupervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc """
  Start monitoring a server by spawning a ServerMonitor process.
  """
  def start_monitor(server) do
    spec = {ServerMonitor, server}

    case DynamicSupervisor.start_child(__MODULE__, spec) do
      {:ok, pid} ->
        Logger.info("Started ServerMonitor for #{server.name} (#{inspect(pid)})")
        {:ok, pid}

      {:error, {:already_started, pid}} ->
        Logger.debug("ServerMonitor for #{server.name} already running (#{inspect(pid)})")
        {:ok, pid}

      error ->
        Logger.error("Failed to start ServerMonitor for #{server.name}: #{inspect(error)}")
        error
    end
  end

  @doc """
  Stop monitoring a server by terminating its ServerMonitor process.
  """
  def stop_monitor(server_name) do
    case find_monitor_pid(server_name) do
      {:ok, pid} ->
        DynamicSupervisor.terminate_child(__MODULE__, pid)
        Logger.info("Stopped ServerMonitor for #{server_name}")
        :ok

      :not_found ->
        Logger.debug("No ServerMonitor found for #{server_name}")
        :ok
    end
  end

  @doc """
  Find the PID of a server's monitor process.
  """
  def find_monitor_pid(server_name) do
    __MODULE__
    |> DynamicSupervisor.which_children()
    |> Enum.find_value(:not_found, fn
      {_id, pid, _type, _modules} when is_pid(pid) ->
        case ServerMonitor.get_server_name(pid) do
          ^server_name -> {:ok, pid}
          _ -> nil
        end

      _ ->
        nil
    end)
  end

  @doc """
  List all active monitor PIDs.
  """
  def list_monitors do
    __MODULE__
    |> DynamicSupervisor.which_children()
    |> Enum.map(fn {_id, pid, _type, _modules} -> pid end)
    |> Enum.filter(&is_pid/1)
  end
end
