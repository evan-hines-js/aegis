defmodule Aegis.MCP.DistributedRateLimiter do
  @moduledoc """
  Distributed, eventually consistent rate limiter using `Phoenix.PubSub` and `Hammer`.

  This module provides a rate-limiting mechanism for MCP requests using a distributed,
  eventually consistent approach. It combines local in-memory counting with a
  broadcasting mechanism to keep counters in sync across nodes in a cluster.
  """

  alias __MODULE__.Local

  # Checks rate locally and broadcasts the hit to other nodes to synchronize.
  def check_rate(key, scale_ms, limit, increment \\ 1) do
    start_time = System.monotonic_time()

    # Broadcast first to ensure eventual consistency
    :ok = broadcast({:hit, key, scale_ms, increment})

    broadcast_duration = System.monotonic_time() - start_time

    # Then check local rate limit using Hammer v7 syntax
    result = Local.hit(key, scale_ms, limit, increment)

    total_duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:aegis, :rate_limiter, :check],
      %{
        duration: total_duration,
        broadcast_duration: broadcast_duration
      },
      %{}
    )

    result
  end

  def hit(key, scale_ms, limit, increment \\ 1) do
    check_rate(key, scale_ms, limit, increment)
  end

  defmodule Local do
    @moduledoc false
    use Hammer, backend: :ets

    # This inner module handles local hit counting via Hammer with ETS backend.
    # Algorithm (Token Bucket) is configured in start_link/1 below.
  end

  defmodule Listener do
    @moduledoc false
    use GenServer
    require Logger

    # Starts the listener process, subscribing to the specified PubSub topic.
    # This process will listen for `:hit` messages to keep local counters in sync.

    @doc false
    def start_link(opts) do
      pubsub = Keyword.fetch!(opts, :pubsub)
      topic = Keyword.fetch!(opts, :topic)
      GenServer.start_link(__MODULE__, {pubsub, topic}, name: __MODULE__)
    end

    @impl true
    def init({pubsub, topic}) do
      Logger.info("Starting distributed rate limiter listener on topic: #{topic}")
      :ok = Phoenix.PubSub.subscribe(pubsub, topic)
      {:ok, %{pubsub: pubsub, topic: topic}}
    end

    # Handles remote `:hit` messages by updating the local counter.
    @impl true
    def handle_info({:hit, key, scale_ms, increment}, state) do
      alias Aegis.MCP.DistributedRateLimiter

      # Only increment local counter, don't broadcast again to avoid loops
      # Use a very high limit since we just want to increment, not rate limit
      _result = DistributedRateLimiter.Local.hit(key, scale_ms, 999_999, increment)
      {:noreply, state}
    end

    @impl true
    def handle_info(msg, state) do
      Logger.debug("Received unexpected message in rate limiter: #{inspect(msg)}")
      {:noreply, state}
    end
  end

  @pubsub Aegis.PubSub
  @topic "__mcp_ratelimit"

  # Sends a message to other nodes in the cluster to synchronize rate-limiting information.
  defp broadcast(message) do
    Phoenix.PubSub.broadcast(@pubsub, @topic, message)
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor
    }
  end

  # Wraps the local Hammer counter and the listener processes under a single supervisor.
  def start_link(_opts \\ []) do
    children = [
      # Use Token Bucket algorithm for bursty MCP workloads
      # Token Bucket allows accumulated tokens to be used in bursts, ideal for:
      # - User asks question → LLM makes 3-5 tool calls in < 1 second → silence
      # - Much more user-friendly than fixed window for this pattern
      {Local, [clean_period: 60_000 * 10, algorithm: Hammer.ETS.TokenBucket]},
      {Listener, pubsub: @pubsub, topic: @topic}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__.Supervisor)
  end

  @doc """
  Get statistics about the rate limiter for monitoring.
  """
  def stats do
    case GenServer.whereis(Listener) do
      nil ->
        %{status: :not_running}

      _pid ->
        %{
          status: :running,
          local_backend: :ets,
          pubsub_topic: @topic,
          pubsub_server: @pubsub
        }
    end
  end
end
