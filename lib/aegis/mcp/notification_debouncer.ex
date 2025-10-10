defmodule Aegis.MCP.NotificationDebouncer do
  @moduledoc """
  General-purpose notification debouncer to prevent multiple rapid events
  for the same key within a short time window.

  Useful for batching rapid database operations that would otherwise
  trigger multiple notifications for the same logical operation.
  """

  use GenServer
  require Logger

  @debounce_delay 100

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @doc """
  Schedule a debounced notification for a given key and callback.
  Multiple calls for the same key within the debounce window
  will result in only one callback being executed.

  ## Examples

      # Debounce permission notifications
      NotificationDebouncer.schedule(:permission_changed, client_id, fn ->
        ServerManager.notify_client_permissions_changed(client_id)
      end)
  """
  def schedule(notification_type, key, callback) when is_function(callback, 0) do
    GenServer.cast(__MODULE__, {:schedule_notification, notification_type, key, callback})
  end

  @impl true
  def init(state) do
    {:ok, state}
  end

  @impl true
  def handle_cast({:schedule_notification, notification_type, key, callback}, state) do
    # Create a unique identifier for this notification
    notification_id = {notification_type, key}

    # Cancel any existing timer for this notification
    case Map.get(state, notification_id) do
      nil -> :ok
      {timer_ref, _callback} -> Process.cancel_timer(timer_ref)
    end

    # Start a new timer
    timer_ref = Process.send_after(self(), {:send_notification, notification_id}, @debounce_delay)
    new_state = Map.put(state, notification_id, {timer_ref, callback})

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:send_notification, notification_id}, state) do
    # Execute the callback if it still exists
    case Map.get(state, notification_id) do
      {_timer_ref, callback} ->
        try do
          callback.()
        rescue
          error ->
            Logger.error("Error executing debounced notification: #{inspect(error)}")
        end

      nil ->
        # Timer was cancelled, do nothing
        :ok
    end

    # Remove the notification from state
    new_state = Map.delete(state, notification_id)

    {:noreply, new_state}
  end
end
