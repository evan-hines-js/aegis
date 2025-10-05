defmodule AegisWeb.AuthLive.MagicSignInLive do
  use AegisWeb, :live_view

  @impl true
  def mount(%{"token" => token}, _session, socket) do
    socket =
      socket
      |> assign(:token, token)
      |> assign(:page_title, "Signing In")

    {:ok, socket}
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
          <h2 class="text-2xl font-semibold text-white mb-2">Complete Sign In</h2>
          <p class="text-gray-300 text-sm">
            Click the button below to complete your sign in
          </p>
        </div>

        <div class="bg-white rounded-lg shadow-xl p-8">
          <form action={~p"/auth/user/magic_link"} method="POST">
            <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
            <input type="hidden" name="token" value={@token} />
            <button
              type="submit"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-md transition-colors duration-200"
            >
              Sign In
            </button>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
