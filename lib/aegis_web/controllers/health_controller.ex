defmodule AegisWeb.HealthController do
  use AegisWeb, :controller

  def index(conn, _params) do
    json(conn, %{status: "ok", node: node()})
  end
end
