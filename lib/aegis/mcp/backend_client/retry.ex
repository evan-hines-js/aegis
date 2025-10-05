defmodule Aegis.MCP.Retry do
  @moduledoc """
  Simple retry logic for HTTP requests to external MCP servers.

  Provides exponential backoff with jitter to avoid thundering herd problems.
  Integrates with circuit breaker to prevent requests to failing servers.
  """

  require Logger
  alias Aegis.MCP.CircuitBreaker

  @default_max_attempts 3
  @default_base_delay 100
  @default_max_delay 5_000

  defmodule Config do
    @moduledoc false
    @type t :: %__MODULE__{
            max_attempts: pos_integer(),
            base_delay: pos_integer(),
            max_delay: pos_integer(),
            jitter: boolean(),
            quiet: boolean(),
            opts: keyword()
          }

    defstruct [:max_attempts, :base_delay, :max_delay, :jitter, :quiet, :opts]
  end

  @doc """
  Retry a function with exponential backoff.

  ## Options
  - `:max_attempts` - Maximum number of attempts (default: 3)
  - `:base_delay` - Base delay in milliseconds (default: 100ms)
  - `:max_delay` - Maximum delay in milliseconds (default: 5s)
  - `:jitter` - Add random jitter to delays (default: true)
  - `:quiet` - Suppress retry and failure logging (default: false)

  ## Examples

      Retry.with_backoff(fn ->
        Req.post(url, json: payload)
      end)

      Retry.with_backoff(fn ->
        some_operation()
      end, max_attempts: 5, base_delay: 200, quiet: true)
  """
  @spec with_backoff(function(), keyword()) :: any()
  def with_backoff(fun, opts \\ []) when is_function(fun, 0) do
    config = %Config{
      max_attempts: Keyword.get(opts, :max_attempts, @default_max_attempts),
      base_delay: Keyword.get(opts, :base_delay, @default_base_delay),
      max_delay: Keyword.get(opts, :max_delay, @default_max_delay),
      jitter: Keyword.get(opts, :jitter, true),
      quiet: Keyword.get(opts, :quiet, false),
      opts: opts
    }

    do_retry(fun, 1, config)
  end

  # Main retry loop
  @spec do_retry(function(), pos_integer(), Config.t()) :: {:ok, any()} | {:error, term()}
  defp do_retry(fun, attempt, config) do
    case fun.() do
      {:ok, result} ->
        handle_success(result, attempt, config.quiet)

      {:error, reason} when attempt < config.max_attempts ->
        handle_retryable_error(fun, attempt, reason, config)

      {:error, reason} ->
        handle_final_error(reason, config)

      result ->
        handle_success(result, attempt, config.quiet)
    end
  end

  defp handle_success(result, attempt, quiet) do
    log_retry_success(attempt, quiet)
    {:ok, result}
  end

  defp handle_retryable_error(fun, attempt, reason, config) do
    delay = calculate_delay(attempt, config.base_delay, config.max_delay, config.jitter)
    log_retry_attempt(attempt, config.max_attempts, reason, delay, config.quiet)
    Process.sleep(delay)
    do_retry(fun, attempt + 1, config)
  end

  defp handle_final_error(reason, config) do
    log_final_failure(config.max_attempts, reason, config.quiet, config.opts)
    {:error, reason}
  end

  defp log_retry_success(attempt, quiet) do
    if attempt > 1 and not quiet do
      Logger.info("Retry succeeded on attempt #{attempt}")
    end
  end

  defp log_retry_attempt(attempt, max_attempts, reason, delay, quiet) do
    if !quiet do
      Logger.warning(
        "Attempt #{attempt}/#{max_attempts} failed: #{inspect(reason)}. " <>
          "Retrying in #{delay}ms..."
      )
    end

  end

  defp log_final_failure(max_attempts, reason, quiet, opts) do
    if !quiet do
      server_name = Keyword.get(opts, :server_name)
      endpoint = Keyword.get(opts, :endpoint)
      operation = Keyword.get(opts, :operation)

      context_parts = []

      context_parts =
        if server_name, do: ["server: #{server_name}" | context_parts], else: context_parts

      context_parts =
        if endpoint, do: ["endpoint: #{endpoint}" | context_parts], else: context_parts

      context_parts =
        if operation, do: ["operation: #{operation}" | context_parts], else: context_parts

      context =
        if Enum.empty?(context_parts), do: "", else: " (#{Enum.join(context_parts, ", ")})"

      Logger.error(
        "All #{max_attempts} attempts failed#{context}. Final error: #{inspect(reason)}"
      )
    end
  end

  # Calculate delay with exponential backoff and optional jitter
  defp calculate_delay(attempt, base_delay, max_delay, jitter) do
    # Exponential backoff: base_delay * 2^(attempt-1)
    delay = base_delay * :math.pow(2, attempt - 1)
    delay = min(delay, max_delay)

    if jitter do
      # Add ±25% jitter to prevent thundering herd
      jitter_range = delay * 0.25
      jitter_amount = :rand.uniform() * jitter_range * 2 - jitter_range
      max(0, delay + jitter_amount)
    else
      delay
    end
    |> round()
  end

  @doc """
  Retry specifically for Req HTTP requests.

  Automatically handles common HTTP error conditions and timeouts.
  Integrates with circuit breaker to prevent requests to failing servers.

  ## Options
  - `:endpoint` - Server endpoint for circuit breaker tracking (required for circuit breaker)
  - `:server_name` - Server name for better error logging
  - `:operation` - Operation description for better error logging (e.g. "tools/list")
  - `:quiet` - Suppress retry and failure logging (default: false)
  """
  @spec retry_http_request(function(), keyword()) :: {:ok, Req.Response.t()} | {:error, term()}
  def retry_http_request(req_fun, opts \\ []) when is_function(req_fun, 0) do
    endpoint = Keyword.get(opts, :endpoint)

    case check_circuit_breaker(endpoint) do
      :allow ->
        result = with_backoff(fn -> handle_req_response(req_fun.()) end, opts)
        record_circuit_breaker_result(endpoint, result)
        result

      {:deny, reason} ->
        {:error, {:circuit_breaker, reason}}
    end
  end

  # Private functions for HTTP response handling

  defp handle_req_response({:ok, %Req.Response{status: status} = response})
       when status >= 200 and status < 300 do
    {:ok, response}
  end

  defp handle_req_response({:ok, %Req.Response{status: status} = response})
       when status >= 500 do
    # Retry on 5xx errors (server errors)
    {:error, {:http_error, status, response.body}}
  end

  defp handle_req_response({:ok, %Req.Response{} = response}) do
    # Don't retry on 4xx errors (client errors)
    {:ok, response}
  end

  defp handle_req_response({:error, %Req.TransportError{reason: :timeout}}) do
    # Retry on timeouts
    {:error, :timeout}
  end

  defp handle_req_response({:error, %Req.TransportError{reason: reason}}) do
    # Retry on connection errors
    {:error, {:connection_error, reason}}
  end

  defp handle_req_response({:error, reason}) do
    # Retry on other errors
    {:error, reason}
  end

  # Private functions for circuit breaker integration

  defp check_circuit_breaker(nil), do: :allow

  defp check_circuit_breaker(endpoint) do
    CircuitBreaker.allow_request?(endpoint)
  end

  defp record_circuit_breaker_result(nil, _result), do: :ok

  defp record_circuit_breaker_result(endpoint, {:ok, _response}) do
    CircuitBreaker.record_success(endpoint)
  end

  defp record_circuit_breaker_result(endpoint, {:error, _reason}) do
    CircuitBreaker.record_failure(endpoint)
  end
end
