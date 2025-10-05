defmodule AegisWeb.AuthLive.AuthForm do
  use AegisWeb, :live_component
  alias AshPhoenix.Form

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> assign(trigger_action: false)
      |> assign(submitted: false)
      |> assign(errors: [])

    {:ok, socket}
  end

  @impl true
  def handle_event("validate", %{"user" => params}, socket) do
    form = socket.assigns.form |> Form.validate(params, errors: false)

    {:noreply, assign(socket, form: form)}
  end

  @impl true
  def handle_event("submit", %{"user" => params}, socket) do
    form = socket.assigns.form |> Form.validate(params)

    if form.valid? do
      case Form.submit(form, params: params) do
        :ok ->
          handle_success(socket)

        {:ok, _result} ->
          handle_success(socket)

        {:error, form} ->
          {:noreply,
           socket
           |> assign(:form, form)
           |> assign(:errors, Form.errors(form))
           |> assign(:trigger_action, false)
           |> assign(:submitted, false)}
      end
    else
      {:noreply,
       socket
       |> assign(:form, form)
       |> assign(:errors, Form.errors(form))
       |> assign(:trigger_action, false)
       |> assign(:submitted, false)}
    end
  end

  defp handle_success(socket) do
    # Create a fresh form to clear the input
    fresh_form =
      Form.for_action(
        socket.assigns.form.source.resource,
        socket.assigns.form.source.action.name,
        domain: socket.assigns.form.domain,
        as: socket.assigns.form.name
      )

    {:noreply,
     socket
     |> assign(:form, fresh_form)
     |> assign(:submitted, true)
     |> assign(:trigger_action, false)
     |> assign(:errors, [])}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow-xl p-8">
      <%= if @submitted do %>
        <div class="mb-6 bg-green-50 border border-green-200 rounded-md p-4">
          <p class="text-sm text-green-600">
            Magic link sent! Check your email to complete sign in.
          </p>
        </div>
      <% end %>

      <%= if !@submitted && assigns[:errors] && @errors != [] do %>
        <div class="mb-6 bg-red-50 border border-red-200 rounded-md p-4">
          <ul class="text-sm text-red-600 space-y-1">
            <%= for {k, v} <- @errors do %>
              <li>{Phoenix.Naming.humanize("#{k}")}: {v}</li>
            <% end %>
          </ul>
        </div>
      <% end %>

      <.form
        :let={f}
        for={@form}
        phx-change="validate"
        phx-submit="submit"
        phx-target={@myself}
        class="space-y-6"
      >
        <div>
          <.input
            field={f[:email]}
            type="email"
            label="Email"
            placeholder="email@example.com"
            required
          />
        </div>

        <button
          type="submit"
          class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-md transition-colors duration-200"
        >
          {@cta}
        </button>
      </.form>
    </div>
    """
  end
end
