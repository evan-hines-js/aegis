defmodule AegisWeb.Admin.DashboardLive do
  use AegisWeb, :live_view

  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:current_page, :dashboard)
      |> assign(:page_title, "Dashboard")

    {:ok, socket}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end
end
