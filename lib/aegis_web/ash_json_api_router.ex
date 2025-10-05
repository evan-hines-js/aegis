defmodule AegisWeb.AshJsonApiRouter do
  @moduledoc false
  use AshJsonApi.Router,
    domains: [Aegis.MCP],
    open_api: "/open_api"
end
