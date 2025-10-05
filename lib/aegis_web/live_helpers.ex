defmodule AegisWeb.LiveHelpers do
  @moduledoc """
  Shared utilities for LiveView operations.

  Provides consistent error handling and flash messaging patterns.
  """

  @doc """
  Handle Ash changeset errors and put appropriate flash messages.

  Returns a {:noreply, socket} tuple for use in LiveView handle_event callbacks.
  """
  @spec handle_ash_error(Phoenix.LiveView.Socket.t(), any(), String.t()) ::
          {:noreply, Phoenix.LiveView.Socket.t()}
  def handle_ash_error(socket, changeset_or_error, operation_description) do
    errors = Ash.Error.to_error_class(changeset_or_error)
    message = "Failed to #{operation_description}: #{inspect(errors)}"
    {:noreply, Phoenix.LiveView.put_flash(socket, :error, message)}
  end

  @doc """
  Handle successful operations with flash messages.

  Returns a {:noreply, socket} tuple for use in LiveView handle_event callbacks.
  """
  @spec handle_success(Phoenix.LiveView.Socket.t(), String.t()) ::
          {:noreply, Phoenix.LiveView.Socket.t()}
  def handle_success(socket, success_message) do
    {:noreply, Phoenix.LiveView.put_flash(socket, :info, success_message)}
  end

  @doc """
  Handle successful operations with flash messages and socket updates.

  Returns a {:noreply, socket} tuple for use in LiveView handle_event callbacks.
  """
  @spec handle_success(Phoenix.LiveView.Socket.t(), String.t(), Phoenix.LiveView.Socket.t()) ::
          {:noreply, Phoenix.LiveView.Socket.t()}
  def handle_success(_original_socket, success_message, updated_socket) do
    {:noreply, Phoenix.LiveView.put_flash(updated_socket, :info, success_message)}
  end
end
