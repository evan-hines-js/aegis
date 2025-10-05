defmodule AegisWeb.PageControllerTest do
  use AegisWeb.ConnCase

  test "GET /", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert redirected_to(conn) == ~p"/admin"
  end
end
