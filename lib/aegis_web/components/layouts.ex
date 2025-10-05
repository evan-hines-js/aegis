defmodule AegisWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use AegisWeb, :html

  # Embed all files in layouts/* within this module.
  # The default root.html.heex file contains the HTML
  # skeleton of your application, namely HTML headers
  # and other static content.
  embed_templates "layouts/*"

  @spec app(map()) :: Phoenix.LiveView.Rendered.t()
  @doc """
  Renders your app layout.

  This function is typically invoked from every template,
  and it often contains your application menu, sidebar,
  or similar.

  ## Examples

      <Layouts.app flash={@flash}>
        <h1>Content</h1>
      </Layouts.app>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://hexdocs.pm/phoenix/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <header class="navbar px-4 sm:px-6 lg:px-8">
      <div class="flex-1">
        <a href="/" class="flex-1 flex w-fit items-center gap-2">
          <img src={~p"/images/logo.svg"} width="36" />
          <span class="text-sm font-semibold">v{Application.spec(:phoenix, :vsn)}</span>
        </a>
      </div>
      <div class="flex-none">
        <ul class="flex flex-column px-1 space-x-4 items-center">
          <li>
            <a href="https://phoenixframework.org/" class="btn btn-ghost">Website</a>
          </li>
          <li>
            <a href="https://github.com/phoenixframework/phoenix" class="btn btn-ghost">GitHub</a>
          </li>
          <li>
            <a href="https://hexdocs.pm/phoenix/overview.html" class="btn btn-primary">
              Get Started <span aria-hidden="true">&rarr;</span>
            </a>
          </li>
        </ul>
      </div>
    </header>

    <main class="px-4 py-20 sm:px-6 lg:px-8">
      <div class="mx-auto max-w-2xl space-y-4">
        {render_slot(@inner_block)}
      </div>
    </main>

    <.flash_group flash={@flash} />
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end

  @doc """
  Renders the admin layout with navigation and user context.
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :current_user, :map, required: true, doc: "the current authenticated user"
  attr :current_page, :atom, default: nil, doc: "the current page for navigation highlighting"
  attr :page_title, :string, default: nil, doc: "the page title"

  slot :inner_block, required: true

  def admin(assigns) do
    ~H"""
    <!DOCTYPE html>
    <html lang="en" class="h-full bg-gray-100" data-theme="system">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="csrf-token" content={get_csrf_token()} />
        <.live_title suffix=" · Aegis Admin">
          {@page_title || "Admin"}
        </.live_title>
        <link phx-track-static rel="stylesheet" href={~p"/assets/app.css"} />
        <script defer phx-track-static type="text/javascript" src={~p"/assets/app.js"}>
        </script>
      </head>
      <body class="h-full">
        <div class="min-h-full">
          <!-- Navigation -->
          <nav class="bg-gray-800">
            <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
              <div class="flex h-16 items-center justify-between">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <.link navigate={~p"/admin"} class="text-white font-bold text-xl">
                      <.icon name="hero-shield-check" class="h-8 w-8 inline mr-2" /> Aegis Admin
                    </.link>
                  </div>
                  <div class="hidden md:block">
                    <div class="ml-10 flex items-baseline space-x-4">
                      <.admin_nav_link href={~p"/admin"} current={@current_page == :dashboard}>
                        <.icon name="hero-chart-bar-square" class="w-4 h-4 mr-2" /> Dashboard
                      </.admin_nav_link>
                      <.admin_nav_link href={~p"/admin/clients"} current={@current_page == :clients}>
                        <.icon name="hero-users" class="w-4 h-4 mr-2" /> Clients
                      </.admin_nav_link>
                      <.admin_nav_link href={~p"/admin/servers"} current={@current_page == :servers}>
                        <.icon name="hero-server" class="w-4 h-4 mr-2" /> Servers
                      </.admin_nav_link>
                    </div>
                  </div>
                </div>
                <div class="hidden md:block">
                  <div class="ml-4 flex items-center md:ml-6">
                    <div class="relative ml-3">
                      <div class="flex items-center space-x-4">
                        <span class="text-gray-300 text-sm">{@current_user.email}</span>
                        <.link
                          href={~p"/sign-out"}
                          class="text-gray-300 hover:bg-gray-700 hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                        >
                          Sign out
                        </.link>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </nav>
          
    <!-- Page header -->
          <header class="bg-white shadow">
            <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
              <h1 class="text-3xl font-bold tracking-tight text-gray-900">
                {@page_title || "Admin"}
              </h1>
            </div>
          </header>
          
    <!-- Main content -->
          <main>
            <div class="mx-auto max-w-7xl py-6 sm:px-6 lg:px-8">
              <.flash_group flash={@flash} />
              {render_slot(@inner_block)}
            </div>
          </main>
        </div>
      </body>
    </html>
    """
  end

  @doc """
  Admin navigation link component with active state styling.
  """
  attr :href, :string, required: true
  attr :current, :boolean, default: false

  slot :inner_block, required: true

  def admin_nav_link(assigns) do
    ~H"""
    <.link
      href={@href}
      class={[
        "flex items-center px-3 py-2 rounded-md text-sm font-medium",
        if(@current,
          do: "bg-gray-900 text-white",
          else: "text-gray-300 hover:bg-gray-700 hover:text-white"
        )
      ]}
    >
      {render_slot(@inner_block)}
    </.link>
    """
  end

  @doc """
  Provides dark vs light theme toggle based on themes defined in app.css.

  See <head> in root.html.heex which applies the theme before page load.
  """
  def theme_toggle(assigns) do
    ~H"""
    <div class="card relative flex flex-row items-center border-2 border-base-300 bg-base-300 rounded-full">
      <div class="absolute w-1/3 h-full rounded-full border-1 border-base-200 bg-base-100 brightness-200 left-0 [[data-theme=light]_&]:left-1/3 [[data-theme=dark]_&]:left-2/3 transition-[left]" />

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="system"
      >
        <.icon name="hero-computer-desktop-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="light"
      >
        <.icon name="hero-sun-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="dark"
      >
        <.icon name="hero-moon-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>
    </div>
    """
  end
end
