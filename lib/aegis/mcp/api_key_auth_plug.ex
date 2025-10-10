defmodule Aegis.MCP.ApiKeyAuthPlug do
  @moduledoc """
  API key authentication plug for MCP requests.

  Extracts and validates API keys from the Authorization header.
  Supports both "Bearer ak_xxx" and "ak_xxx" formats.
  """

  import Plug.Conn
  require Logger

  alias Aegis.MCP.Authorization

  @behaviour Plug

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    case extract_api_key(conn) do
      {:ok, api_key} ->
        authenticate_with_api_key(conn, api_key)

      {:error, :missing_credentials} ->
        send_unauthorized_response(conn, "Missing API key in Authorization header")
    end
  end

  # Extract API key from Authorization header
  defp extract_api_key(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        extract_from_token(String.trim(token))

      ["bearer " <> token] ->
        extract_from_token(String.trim(token))

      [token] ->
        extract_from_token(String.trim(token))

      [] ->
        {:error, :missing_credentials}

      _multiple ->
        {:error, :missing_credentials}
    end
  end

  defp extract_from_token(token) do
    if String.starts_with?(token, "ak_") do
      {:ok, token}
    else
      {:error, :missing_credentials}
    end
  end

  # Authenticate using API key
  defp authenticate_with_api_key(conn, api_key) do
    case Authorization.authenticate_client(api_key) do
      {:ok, client} ->
        conn
        |> assign(:current_client, client)
        |> assign(:auth_method, :api_key)
        |> assign(:authenticated, true)

      {:error, :invalid_api_key} ->
        send_unauthorized_response(conn, "Invalid API key")

      {:error, :client_inactive} ->
        send_unauthorized_response(conn, "Client account is inactive")

      {:error, reason} ->
        Logger.error("API key authentication failed: #{inspect(reason)}")
        send_unauthorized_response(conn, "Authentication failed")
    end
  end

  # Send 401 Unauthorized response
  defp send_unauthorized_response(conn, error_description) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      401,
      Jason.encode!(%{
        "error" => "unauthorized",
        "error_description" => error_description
      })
    )
    |> halt()
  end
end
