defmodule AegisWeb.OAuth.RegistrationController do
  @moduledoc """
  OAuth client registration endpoints.

  Proxies client registration operations to the authorization server
  with proper CORS support.
  """

  use AegisWeb, :controller
  require Logger

  alias Aegis.MCP.OAuth.Errors

  @doc """
  Proxy client registration requests.
  """
  def register_client(conn, %{"realm" => realm} = params) do
    Logger.info("Client registration request: #{inspect(params)}")

    base_url = build_base_url(conn)

    original_redirect_uris = Map.get(params, "redirect_uris", [])

    body_params =
      params
      |> Map.drop(["realm"])
      |> Map.put("client_uri", base_url)
      |> Map.put("client_name", "#{params["client_name"]} (via #{base_url})")
      |> Map.put("redirect_uris", original_redirect_uris)

    body = Jason.encode!(body_params)

    case proxy_to_provider("POST", realm, "clients-registrations/openid-connect", body, conn) do
      {:ok, response} ->
        response_body = format_response_body(response.body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(response.status)
        |> put_resp_content_type("application/json")
        |> send_resp(response.status, response_body)

      {:error, reason} ->
        Logger.error("Client registration failed: #{inspect(reason)}")
        Errors.registration_failed(conn)
    end
  end

  @doc """
  Proxy client retrieval requests.
  """
  def get_client(conn, %{"realm" => realm, "client_id" => client_id}) do
    case proxy_to_provider(
           "GET",
           realm,
           "clients-registrations/openid-connect/#{client_id}",
           "",
           conn
         ) do
      {:ok, response} ->
        response_body = format_response_body(response.body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(response.status)
        |> put_resp_content_type("application/json")
        |> send_resp(response.status, response_body)

      {:error, reason} ->
        Logger.error("Client retrieval failed: #{inspect(reason)}")
        Errors.client_retrieval_failed(conn)
    end
  end

  @doc """
  Proxy client update requests.
  """
  def update_client(conn, %{"realm" => realm, "client_id" => client_id} = params) do
    body_params = Map.drop(params, ["realm", "client_id"])
    body = Jason.encode!(body_params)

    case proxy_to_provider(
           "PUT",
           realm,
           "clients-registrations/openid-connect/#{client_id}",
           body,
           conn
         ) do
      {:ok, response} ->
        response_body = format_response_body(response.body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(response.status)
        |> put_resp_content_type("application/json")
        |> send_resp(response.status, response_body)

      {:error, reason} ->
        Logger.error("Client update failed: #{inspect(reason)}")
        Errors.update_failed(conn)
    end
  end

  @doc """
  Proxy client deletion requests.
  """
  def delete_client(conn, %{"realm" => realm, "client_id" => client_id}) do
    case proxy_to_provider(
           "DELETE",
           realm,
           "clients-registrations/openid-connect/#{client_id}",
           "",
           conn
         ) do
      {:ok, response} ->
        response_body = format_response_body(response.body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(response.status)
        |> send_resp(response.status, response_body)

      {:error, reason} ->
        Logger.error("Client deletion failed: #{inspect(reason)}")
        Errors.deletion_failed(conn)
    end
  end

  @doc """
  Handle CORS preflight OPTIONS requests.
  """
  def options(conn, _params) do
    conn
    |> AegisWeb.CORS.add_oauth_registration_headers()
    |> AegisWeb.CORS.add_preflight_headers()
    |> send_resp(200, "")
  end

  # Private functions

  defp proxy_to_provider(method, realm, path, body, conn) do
    provider_base_url =
      Application.get_env(:aegis, :keycloak_base_url, "http://localhost:8080")

    url = "#{provider_base_url}/realms/#{realm}/#{path}"

    Logger.debug("Proxying #{method} to #{url}")

    headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    headers =
      case Plug.Conn.get_req_header(conn, "authorization") do
        [auth_header] -> [{"authorization", auth_header} | headers]
        [] -> headers
      end

    Logger.debug("Request headers: #{inspect(headers)}")

    result =
      case String.upcase(method) do
        "GET" -> Req.get(url, headers: headers)
        "POST" -> Req.post(url, body: body, headers: headers)
        "PUT" -> Req.put(url, body: body, headers: headers)
        "DELETE" -> Req.delete(url, headers: headers)
      end

    case result do
      {:ok, %Req.Response{} = response} ->
        Logger.debug("Provider response: status=#{response.status}")
        {:ok, response}

      {:error, reason} ->
        Logger.error("Provider request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp format_response_body(body) when is_binary(body), do: body
  defp format_response_body(body) when is_map(body), do: Jason.encode!(body)
  defp format_response_body(body), do: inspect(body)

  defp build_base_url(conn) do
    scheme = conn.scheme |> to_string() |> String.downcase()
    host = conn.host |> String.downcase()
    port = get_port_string(conn)

    "#{scheme}://#{host}#{port}"
  end

  defp get_port_string(conn) do
    case {conn.scheme, conn.port} do
      {:https, 443} -> ""
      {:http, 80} -> ""
      {_, port} -> ":#{port}"
    end
  end
end
