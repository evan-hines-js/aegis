defmodule Aegis.MCP.CircuitBreaker do
  @moduledoc """
  Circuit breaker pattern for HTTP requests to MCP servers.

  Prevents repeated requests to failing servers by tracking failures
  and temporarily blocking requests when a threshold is reached.

  Uses atomic ETS counters to prevent race conditions under high concurrency.

  ## States

  - `:closed` - Normal operation, requests pass through
  - `:open` - Too many failures, requests are short-circuited
  - `:half_open` - Testing if server recovered, allows one request through

  ## Configuration

  - Failure threshold: 3 consecutive failures opens the circuit
  - Open timeout: Exponential backoff starting at 5s, up to 60s max
    - 1st failure: 5s wait
    - 2nd failure: 10s wait
    - 3rd failure: 20s wait
    - 4th+ failures: 40s-60s wait (capped at max)
  - Success in half-open state closes the circuit and resets backoff
  - Failure in half-open state reopens with increased backoff

  ## Usage

      case CircuitBreaker.allow_request?(server_endpoint) do
        :allow ->
          case make_http_request(server_endpoint) do
            {:ok, response} ->
              CircuitBreaker.record_success(server_endpoint)
              {:ok, response}

            {:error, reason} ->
              CircuitBreaker.record_failure(server_endpoint)
              {:error, reason}
          end

        {:deny, reason} ->
          {:error, {:circuit_open, reason}}
      end
  """

  require Logger
  alias Aegis.Cache

  @cache_table :circuit_breaker_cache
  @failure_threshold 3
  @initial_timeout_ms 5_000
  @max_timeout_ms 60_000
  @half_open_timeout_ms 10_000
  @counter_ttl :timer.minutes(10)

  @type state :: :closed | :open | :half_open
  @type endpoint :: String.t()

  defmodule State do
    @moduledoc false
    defstruct [
      :state,
      :last_failure_at,
      :opened_at,
      :half_opened_at,
      consecutive_failures: 0
    ]

    @type t :: %__MODULE__{
            state: :closed | :open | :half_open,
            last_failure_at: DateTime.t() | nil,
            opened_at: DateTime.t() | nil,
            half_opened_at: DateTime.t() | nil,
            consecutive_failures: non_neg_integer()
          }
  end

  @doc """
  Check if a request to the endpoint should be allowed.

  Returns:
  - `:allow` - Request is allowed
  - `{:deny, reason}` - Request is denied, circuit is open
  """
  @spec allow_request?(endpoint()) :: :allow | {:deny, map()}
  def allow_request?(endpoint) do
    case get_state(endpoint) do
      %State{state: :closed} ->
        :allow

      %State{state: :half_open, half_opened_at: half_opened_at} = circuit_state ->
        # In half-open, check if we're still within the test window
        elapsed = DateTime.diff(DateTime.utc_now(), half_opened_at, :millisecond)

        if elapsed < @half_open_timeout_ms do
          :allow
        else
          # Half-open timeout expired without success, reopen circuit
          reopen_circuit(endpoint, circuit_state)
          timeout = calculate_backoff_timeout(circuit_state.consecutive_failures)
          {:deny, %{reason: :circuit_open, retry_after_ms: timeout}}
        end

      %State{state: :open, opened_at: opened_at, consecutive_failures: failures} = circuit_state ->
        # Check if we should transition to half-open
        elapsed = DateTime.diff(DateTime.utc_now(), opened_at, :millisecond)
        timeout = calculate_backoff_timeout(failures)

        if elapsed >= timeout do
          # Transition to half-open to test server recovery
          transition_to_half_open(endpoint, circuit_state)
          :allow
        else
          retry_after = timeout - elapsed

          {:deny,
           %{
             reason: :circuit_open,
             retry_after_ms: retry_after,
             opened_at: DateTime.to_iso8601(opened_at)
           }}
        end
    end
  end

  @doc """
  Record a successful request.

  In closed state: Resets failure count
  In half-open state: Transitions back to closed
  """
  @spec record_success(endpoint()) :: :ok
  def record_success(endpoint) do
    case get_state(endpoint) do
      %State{state: :half_open} ->
        Logger.info("Circuit breaker for #{endpoint}: half-open → closed (success)")
        reset_counter(endpoint)
        put_state(endpoint, %State{state: :closed, consecutive_failures: 0})

      %State{state: :closed} ->
        # Reset failure count on success
        reset_counter(endpoint)

      _ ->
        :ok
    end
  end

  @doc """
  Record a failed request.

  Increments failure count and may open the circuit if threshold is reached.
  """
  @spec record_failure(endpoint()) :: :ok
  def record_failure(endpoint) do
    now = DateTime.utc_now()
    state = get_state(endpoint)

    case state do
      %State{state: :closed, consecutive_failures: _failures} ->
        # Atomically increment failure counter
        new_count = increment_counter(endpoint)

        if new_count >= @failure_threshold do
          Logger.warning("Circuit breaker for #{endpoint}: closed → open (#{new_count} failures)")

          put_state(endpoint, %State{
            state: :open,
            last_failure_at: now,
            opened_at: now,
            # Start counting from 1 when circuit opens
            consecutive_failures: 1
          })
        else
          put_state(endpoint, %State{
            state: :closed,
            last_failure_at: now,
            # Still closed, reset counter
            consecutive_failures: 0
          })
        end

      %State{state: :half_open, consecutive_failures: failures} ->
        Logger.warning("Circuit breaker for #{endpoint}: half-open → open (test failed)")
        increment_counter(endpoint)
        new_failures = failures + 1

        put_state(endpoint, %State{
          state: :open,
          last_failure_at: now,
          opened_at: now,
          consecutive_failures: new_failures
        })

      %State{state: :open, consecutive_failures: failures} ->
        # Already open, just update failure tracking
        increment_counter(endpoint)
        new_failures = failures + 1

        put_state(endpoint, %State{
          state: :open,
          last_failure_at: now,
          opened_at: state.opened_at,
          consecutive_failures: new_failures
        })
    end
  end

  @doc """
  Reset the circuit breaker for an endpoint.

  Useful for manual intervention or testing.
  """
  @spec reset(endpoint()) :: :ok
  def reset(endpoint) do
    Logger.info("Circuit breaker for #{endpoint}: manual reset")
    reset_counter(endpoint)
    Cache.delete(@cache_table, circuit_key(endpoint))
  end

  @doc """
  Get the current circuit breaker state for an endpoint.
  """
  @spec get_circuit_state(endpoint()) :: map()
  def get_circuit_state(endpoint) do
    state = get_state(endpoint)
    failure_count = get_counter(endpoint)

    %{
      state: state.state,
      failure_count: failure_count,
      last_failure_at: state.last_failure_at,
      opened_at: state.opened_at,
      half_opened_at: state.half_opened_at
    }
  end

  # Private Functions

  defp circuit_key(endpoint), do: {:circuit_breaker, endpoint}

  defp get_state(endpoint) do
    case Cache.get(@cache_table, circuit_key(endpoint)) do
      {:ok, %State{consecutive_failures: failures} = state} when is_integer(failures) ->
        state

      {:ok, %State{} = state} ->
        # Old state without consecutive_failures, add it with default value
        %{state | consecutive_failures: 0}

      _ ->
        %State{state: :closed, consecutive_failures: 0}
    end
  end

  defp put_state(endpoint, %State{} = state) do
    # Use a 10-minute TTL to auto-cleanup old circuit states
    # This prevents the cache from filling up with stale circuit data
    Cache.put(@cache_table, circuit_key(endpoint), state, ttl: :timer.minutes(10))
  end

  defp transition_to_half_open(endpoint, _state) do
    Logger.info("Circuit breaker for #{endpoint}: open → half-open (testing recovery)")
    reset_counter(endpoint)

    put_state(endpoint, %State{
      state: :half_open,
      half_opened_at: DateTime.utc_now()
    })
  end

  defp reopen_circuit(endpoint, _state) do
    Logger.warning("Circuit breaker for #{endpoint}: half-open → open (timeout)")

    put_state(endpoint, %State{
      state: :open,
      last_failure_at: DateTime.utc_now(),
      opened_at: DateTime.utc_now()
    })
  end

  # Counter helpers using Cachex

  defp increment_counter(endpoint) do
    counter_key = counter_key(endpoint)

    # Atomically increment counter
    case Cachex.incr(@cache_table, counter_key, 1, initial: 0) do
      {:ok, new_count} ->
        # Reset TTL on increment to keep active counters alive
        Cachex.expire(@cache_table, counter_key, @counter_ttl)
        new_count

      {:error, _reason} ->
        # Fallback: try to set initial value
        Cachex.put(@cache_table, counter_key, 1, ttl: @counter_ttl)
        1
    end
  end

  defp get_counter(endpoint) do
    counter_key = counter_key(endpoint)

    case Cachex.get(@cache_table, counter_key) do
      {:ok, count} when is_integer(count) -> count
      _ -> 0
    end
  end

  defp reset_counter(endpoint) do
    counter_key = counter_key(endpoint)
    Cachex.del(@cache_table, counter_key)
    :ok
  end

  defp counter_key(endpoint), do: {:counter, endpoint}

  # Calculate exponential backoff timeout based on consecutive failures
  # Formula: initial_timeout * 2^(failures - 1), capped at max_timeout
  # Cap failures at 10 to prevent arithmetic overflow (2^10 = 1024, well within safe range)
  @max_backoff_failures 10

  defp calculate_backoff_timeout(failures) when failures < 1 do
    @initial_timeout_ms
  end

  defp calculate_backoff_timeout(failures) do
    # Cap failures to prevent :math.pow overflow
    capped_failures = min(failures, @max_backoff_failures)
    timeout = @initial_timeout_ms * :math.pow(2, capped_failures - 1)
    min(round(timeout), @max_timeout_ms)
  end
end
