defmodule Aegis.MCP.ErrorHandler do
  @moduledoc """
  Centralized error handling utilities for the MCP implementation.

  Provides consistent error handling patterns and standardizes how errors
  are propagated through the system.
  """

  require Logger

  @type error_result :: {:ok, any()} | {:error, atom() | map() | binary()}

  @doc """
  Wraps a function call in consistent error handling.

  ## Examples

      safe_execute(fn ->
        perform_risky_operation()
      end)

      safe_execute(fn ->
        perform_risky_operation()
      end, :operation_failed)
  """
  @spec safe_execute(function(), atom()) :: error_result()
  def safe_execute(fun, default_error \\ :operation_failed) do
    case fun.() do
      {:ok, _} = result -> result
      {:error, _} = error -> error
      result -> {:ok, result}
    end
  rescue
    error ->
      Logger.error("Operation failed: #{inspect(error)}")
      {:error, default_error}
  catch
    :exit, reason ->
      Logger.error("Operation exited: #{inspect(reason)}")
      {:error, default_error}
  end

  @doc """
  Chains multiple operations that return {:ok, value} | {:error, reason}.
  Stops at the first error.

  ## Examples

      chain_operations([
        fn -> validate_input(params) end,
        fn -> process_data(params) end,
        fn -> save_results(params) end
      ])
  """
  @spec chain_operations([function()]) :: error_result()
  def chain_operations(operations) do
    Enum.reduce_while(operations, {:ok, nil}, fn operation, _acc ->
      case safe_execute(operation) do
        {:ok, result} -> {:cont, {:ok, result}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  @doc """
  Handles async operations with proper error handling.

  ## Examples

      async_safe_execute(fn ->
        update_database(data)
      end, :db_update_failed)
  """
  @spec async_safe_execute(function(), atom()) :: {:ok, pid()}
  def async_safe_execute(fun, error_context \\ :async_operation) do
    Task.start(fn ->
      case safe_execute(fun, error_context) do
        {:error, reason} ->
          Logger.warning("Async operation failed (#{error_context}): #{inspect(reason)}")

        _ ->
          :ok
      end
    end)
  end

  @doc """
  Logs an error with context and returns a standardized error tuple.

  ## Examples

      log_and_return_error(:validation_failed, %{
        field: "email",
        value: "invalid"
      })
  """
  @spec log_and_return_error(atom(), map()) :: {:error, atom()}
  def log_and_return_error(error_type, context \\ %{}) do
    Logger.error("Error: #{error_type}", context)
    {:error, error_type}
  end

  @doc """
  Transforms various error formats into a consistent structure.

  ## Examples

      normalize_error({:error, "Something went wrong"})
      # => {:error, :unknown_error}

      normalize_error({:error, %{code: -32_600, message: "Invalid"}})
      # => {:error, %{code: -32_600, message: "Invalid"}}
  """
  @spec normalize_error(any()) :: {:error, atom() | map()}
  def normalize_error({:error, reason} = error) when is_atom(reason) or is_map(reason) do
    error
  end

  def normalize_error({:error, _reason}) do
    {:error, :unknown_error}
  end

  def normalize_error(_) do
    {:error, :unknown_error}
  end

  @doc """
  Ensures operations are properly cleaned up on failure.

  ## Examples

      with_cleanup(
        fn -> allocate_resource() end,
        fn resource -> process(resource) end,
        fn resource -> deallocate(resource) end
      )
  """
  @spec with_cleanup(function(), function(), function()) :: error_result()
  def with_cleanup(setup_fun, process_fun, cleanup_fun) do
    case safe_execute(setup_fun) do
      {:ok, resource} ->
        try do
          result = safe_execute(fn -> process_fun.(resource) end)
          cleanup_fun.(resource)
          result
        rescue
          error ->
            cleanup_fun.(resource)
            {:error, error}
        end

      error ->
        error
    end
  end
end
