defmodule AegisWeb.AuthLive.Index do
  use AegisWeb, :live_view

  alias Aegis.Accounts
  alias Aegis.Accounts.User
  alias AshPhoenix.Form

  @impl true
  def mount(_, _, socket) do
    if socket.assigns[:current_user] do
      {:ok, push_navigate(socket, to: ~p"/admin")}
    else
      {:ok, socket}
    end
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, action, _params) when action in [:register, :sign_in] do
    socket
    |> assign(:page_title, "Sign In / Register")
    |> assign(:form_id, "magic-link-form")
    |> assign(:cta, "Send Magic Link")
    |> assign(:form, Form.for_action(User, :request_magic_link, domain: Accounts, as: "user"))
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-800 flex items-center justify-center px-4">
      <div class="w-full max-w-md">
        <div class="text-center mb-8">
          <div class="flex items-center justify-center gap-3 mb-6">
            <.icon name="hero-shield-check" class="h-12 w-12 text-white" />
            <h1 class="text-3xl font-bold text-white">Aegis</h1>
          </div>
          <h2 class="text-2xl font-semibold text-white mb-2">{@page_title}</h2>
          <p class="text-gray-300 text-sm">
            Enter your email to receive a magic link
          </p>
        </div>

        <.live_component
          module={AegisWeb.AuthLive.AuthForm}
          id={@form_id}
          form={@form}
          cta={@cta}
        />
      </div>
    </div>
    """
  end
end
