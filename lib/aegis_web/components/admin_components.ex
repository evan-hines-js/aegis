defmodule AegisWeb.AdminComponents do
  @moduledoc """
  Reusable components for admin UI pages.
  Reduces template duplication across admin LiveViews.
  """
  use Phoenix.Component
  import AegisWeb.CoreComponents

  @doc """
  Renders a page header with optional action button.

  ## Examples

      <.page_header description="Manage MCP clients">
        <:action>
          <button phx-click="show_form">Create Client</button>
        </:action>
      </.page_header>
  """
  attr :description, :string, required: true
  slot :action

  def page_header(assigns) do
    ~H"""
    <div class="sm:flex sm:items-center">
      <div class="sm:flex-auto">
        <p class="mt-2 text-sm text-gray-700">
          {@description}
        </p>
      </div>
      <div :if={@action != []} class="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
        {render_slot(@action)}
      </div>
    </div>
    """
  end

  @doc """
  Renders a modal dialog for forms.

  ## Examples

      <.modal show={@show_form} on_cancel="hide_form">
        <:title>Create New Client</:title>
        <:body>
          <.form>...</.form>
        </:body>
      </.modal>
  """
  attr :show, :boolean, required: true
  attr :on_cancel, :string, required: true
  slot :title, required: true
  slot :body, required: true

  def modal(assigns) do
    ~H"""
    <%= if @show do %>
      <div class="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center z-50">
        <div class="bg-white rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-medium text-gray-900">
              {render_slot(@title)}
            </h3>
            <button phx-click={@on_cancel} class="text-gray-400 hover:text-gray-600">
              <.icon name="hero-x-mark" class="w-5 h-5" />
            </button>
          </div>
          {render_slot(@body)}
        </div>
      </div>
    <% end %>
    """
  end

  @doc """
  Renders form action buttons (Cancel/Submit).

  ## Examples

      <.form_buttons on_cancel="hide_form" submit_label="Create" />
      <.form_buttons on_cancel="hide_form" submit_label="Update" color="green" />
  """
  attr :on_cancel, :string, required: true
  attr :submit_label, :string, required: true
  attr :color, :string, default: "blue"

  def form_buttons(assigns) do
    ~H"""
    <div class="flex justify-end space-x-3">
      <button
        type="button"
        phx-click={@on_cancel}
        class="rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
      >
        Cancel
      </button>
      <button
        type="submit"
        class={[
          "rounded-md px-3 py-2 text-sm font-semibold text-white shadow-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
          case @color do
            "green" ->
              "bg-green-600 hover:bg-green-500 focus-visible:outline-green-600"

            "blue" ->
              "bg-blue-600 hover:bg-blue-500 focus-visible:outline-blue-600"

            _ ->
              "bg-blue-600 hover:bg-blue-500 focus-visible:outline-blue-600"
          end
        ]}
      >
        {@submit_label}
      </button>
    </div>
    """
  end

  @doc """
  Renders a data table wrapper.

  ## Examples

      <.data_table title="Registered Servers">
        <:header>
          <th>Name</th>
          <th>Endpoint</th>
        </:header>
        <:body>
          <tr><td>server1</td><td>https://...</td></tr>
        </:body>
      </.data_table>
  """
  attr :title, :string, required: true
  slot :header, required: true
  slot :body, required: true

  def data_table(assigns) do
    ~H"""
    <div class="bg-white shadow overflow-hidden sm:rounded-lg">
      <div class="px-4 py-5 sm:px-6">
        <h3 class="text-lg leading-6 font-medium text-gray-900">
          {@title}
        </h3>
      </div>
      <div class="border-t border-gray-200">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                {render_slot(@header)}
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              {render_slot(@body)}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
  end

  @doc """
  Renders a table header cell.

  ## Examples

      <.th>Server Name</.th>
  """
  slot :inner_block, required: true

  def th(assigns) do
    ~H"""
    <th
      scope="col"
      class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
    >
      {render_slot(@inner_block)}
    </th>
    """
  end

  @doc """
  Renders an action button with icon.

  ## Examples

      <.action_button icon="hero-plus" color="blue" click="show_form">
        Create Client
      </.action_button>
  """
  attr :icon, :string, required: true
  attr :color, :string, default: "blue"
  attr :click, :string, required: true
  slot :inner_block, required: true

  def action_button(assigns) do
    ~H"""
    <button
      type="button"
      phx-click={@click}
      class={[
        "block rounded-md px-3 py-2 text-center text-sm font-semibold text-white shadow-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
        case @color do
          "green" -> "bg-green-600 hover:bg-green-500 focus-visible:outline-green-600"
          "blue" -> "bg-blue-600 hover:bg-blue-500 focus-visible:outline-blue-600"
          "red" -> "bg-red-600 hover:bg-red-500 focus-visible:outline-red-600"
          _ -> "bg-blue-600 hover:bg-blue-500 focus-visible:outline-blue-600"
        end
      ]}
    >
      <.icon name={@icon} class="w-4 h-4 inline mr-1" /> {render_slot(@inner_block)}
    </button>
    """
  end

  @doc """
  Renders a status badge.

  ## Examples

      <.badge status={:healthy}>Healthy</.badge>
      <.badge status={:unhealthy}>Unhealthy</.badge>
  """
  attr :status, :atom, required: true
  slot :inner_block, required: true

  def badge(assigns) do
    ~H"""
    <span class={[
      "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium",
      case @status do
        :healthy -> "bg-green-100 text-green-800"
        :unhealthy -> "bg-red-100 text-red-800"
        :active -> "bg-green-100 text-green-800"
        :inactive -> "bg-gray-100 text-gray-800"
        :api_key -> "bg-blue-100 text-blue-800"
        :none -> "bg-gray-100 text-gray-800"
        _ -> "bg-gray-100 text-gray-800"
      end
    ]}>
      {render_slot(@inner_block)}
    </span>
    """
  end

  @doc """
  Renders an icon avatar (for table rows).

  ## Examples

      <.icon_avatar icon="hero-server" color="green" />
  """
  attr :icon, :string, required: true
  attr :color, :string, default: "blue"

  def icon_avatar(assigns) do
    assigns =
      assign(
        assigns,
        :icon_class,
        case assigns.color do
          "green" -> "h-5 w-5 text-green-600"
          "blue" -> "h-5 w-5 text-blue-600"
          "purple" -> "h-5 w-5 text-purple-600"
          _ -> "h-5 w-5 text-blue-600"
        end
      )

    ~H"""
    <div class="flex-shrink-0 h-10 w-10">
      <div class={[
        "h-10 w-10 rounded-full flex items-center justify-center",
        case @color do
          "green" -> "bg-green-100"
          "blue" -> "bg-blue-100"
          "purple" -> "bg-purple-100"
          _ -> "bg-blue-100"
        end
      ]}>
        <.icon name={@icon} class={@icon_class} />
      </div>
    </div>
    """
  end

  @doc """
  Renders a form section with title.

  ## Examples

      <.form_section title="Authentication Configuration">
        <.input ... />
      </.form_section>
  """
  attr :title, :string, required: true
  attr :class, :string, default: "mt-6 border-t border-gray-200 pt-6"
  slot :inner_block, required: true

  def form_section(assigns) do
    ~H"""
    <div class={@class}>
      <h4 class="text-sm font-medium text-gray-900 mb-4">{@title}</h4>
      {render_slot(@inner_block)}
    </div>
    """
  end
end
