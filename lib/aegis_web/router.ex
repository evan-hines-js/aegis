defmodule AegisWeb.Router do
  use AegisWeb, :router

  import Oban.Web.Router
  use AshAuthentication.Phoenix.Router

  import AshAuthentication.Plug.Helpers

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {AegisWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session
  end

  pipeline :api do
    plug :accepts, ["json", "event-stream"]
    plug :load_from_bearer
    plug :set_actor, :user
  end

  pipeline :mcp do
    plug :accepts, ["json", "event-stream"]
    plug Aegis.MCP.RequestContextPlug
    plug Aegis.MCP.ApiKeyAuthPlug
  end

  scope "/", AegisWeb do
    pipe_through :browser

    ash_authentication_live_session :authenticated_routes,
      on_mount: [{AegisWeb.LiveUserAuth, :live_user_optional}] do
      # Custom authentication views
      live "/register", AuthLive.Index, :register
      live "/sign-in", AuthLive.Index, :sign_in
      live "/magic_link/:token", AuthLive.MagicSignInLive, :sign_in
    end

    ash_authentication_live_session :admin_routes,
      on_mount: [{AegisWeb.LiveUserAuth, :live_admin_required}] do
      scope "/admin", Admin do
        live "/", DashboardLive, :index
        live "/clients", ClientsLive, :index
        live "/servers", ServersLive, :index
      end
    end
  end

  scope "/api/json" do
    pipe_through [:api]

    forward "/swaggerui", OpenApiSpex.Plug.SwaggerUI,
      path: "/api/json/open_api",
      default_model_expand_depth: 4

    forward "/", AegisWeb.AshJsonApiRouter
  end

  scope "/", AegisWeb do
    pipe_through [:mcp]

    post "/mcp", MCPController, :index
    get "/mcp", MCPController, :sse_stream
    delete "/mcp", MCPController, :delete
    options "/mcp", MCPController, :options
  end

  scope "/", AegisWeb do
    pipe_through [:api]

    get "/api/health", HealthController, :index
  end

  scope "/", AegisWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/unauthorized", PageController, :unauthorized
    auth_routes AuthController, Aegis.Accounts.User, path: "/auth"
    sign_out_route AuthController

    # Remove this if you do not want to use the reset password feature
    reset_route auth_routes_prefix: "/auth",
                overrides: [AegisWeb.AuthOverrides, AshAuthentication.Phoenix.Overrides.Default]

    # Remove this if you do not use the confirmation strategy
    confirm_route Aegis.Accounts.User, :confirm_new_user,
      auth_routes_prefix: "/auth",
      overrides: [AegisWeb.AuthOverrides, AshAuthentication.Phoenix.Overrides.Default]
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:aegis, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).

    # Other scopes may use custom stacks.
    # scope "/api", AegisWeb do
    #   pipe_through :api
    # end
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: AegisWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end

    scope "/" do
      pipe_through :browser

      oban_dashboard("/oban")
    end
  end

  if Application.compile_env(:aegis, :dev_routes) do
    import AshAdmin.Router

    scope "/admin" do
      pipe_through :browser

      ash_admin "/"
    end
  end
end
