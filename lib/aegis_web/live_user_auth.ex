defmodule AegisWeb.LiveUserAuth do
  @moduledoc """
  Helpers for authenticating users in LiveViews.
  """

  import Phoenix.Component
  use AegisWeb, :verified_routes

  alias AshAuthentication.Phoenix.LiveSession
  alias Phoenix.LiveView

  # This is used for nested liveviews to fetch the current user.
  # To use, place the following at the top of that liveview:
  # on_mount {AegisWeb.LiveUserAuth, :current_user}
  def on_mount(:current_user, _params, session, socket) do
    {:cont, LiveSession.assign_new_resources(socket, session)}
  end

  def on_mount(:live_user_optional, _params, _session, socket) do
    if socket.assigns[:current_user] do
      {:cont, socket}
    else
      {:cont, assign(socket, :current_user, nil)}
    end
  end

  def on_mount(:live_user_required, _params, _session, socket) do
    if socket.assigns[:current_user] do
      {:cont, socket}
    else
      {:halt, LiveView.redirect(socket, to: ~p"/sign-in")}
    end
  end

  def on_mount(:live_no_user, _params, _session, socket) do
    if socket.assigns[:current_user] do
      {:halt, LiveView.redirect(socket, to: ~p"/")}
    else
      {:cont, assign(socket, :current_user, nil)}
    end
  end

  def on_mount(:live_admin_required, _params, _session, socket) do
    case socket.assigns[:current_user] do
      %{email: email} = user when not is_nil(email) ->
        if admin_user?(user) do
          {:cont, socket}
        else
          {:halt, LiveView.redirect(socket, to: ~p"/unauthorized")}
        end

      _ ->
        {:halt, LiveView.redirect(socket, to: ~p"/sign-in")}
    end
  end

  # Check if user has admin role
  defp admin_user?(%{admin: true}), do: true
  defp admin_user?(_), do: false
end
