defmodule AegisWeb.PageController do
  use AegisWeb, :controller

  def home(conn, _params) do
    redirect(conn, to: ~p"/admin")
  end

  def unauthorized(conn, _params) do
    conn
    |> put_status(:forbidden)
    |> render(:unauthorized)
  end
end
