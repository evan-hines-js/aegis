defmodule AegisWeb.OAuth.ProxyController do
  @moduledoc """
  OAuth protocol proxy endpoints.

  Proxies OAuth token, authorization, userinfo, and JWKS requests
  to configured authorization servers with proper validation.
  """

  use AegisWeb, :controller
  require Logger

  alias Aegis.MCP.Client
  alias Aegis.MCP.OAuth.{Config, Errors, Provider, ResourceValidation}

  @doc """
  Proxy OAuth token requests with resource parameter validation.

  Per RFC 8707, validates the resource parameter to ensure tokens
  are bound to the correct MCP server resource.
  """
  def proxy_token(conn, %{"realm" => _realm} = params) do
    case validate_resource_param_for_token(params, conn) do
      :ok ->
        client_id = Map.get(params, "client_id")

        case determine_oauth_provider(client_id) do
          {:ok, provider_url} ->
            proxy_token_to_provider(conn, provider_url, params)

          {:error, :no_client_id} ->
            Errors.missing_client_id(conn)

          {:error, :client_not_found} ->
            Errors.client_not_found(conn)
        end

      {:error, :missing_resource} ->
        Errors.missing_resource_parameter(conn)

      {:error, :invalid_resource} ->
        expected = ResourceValidation.get_expected_resource(conn)
        Errors.invalid_resource_parameter(conn, expected)

      {:error, :invalid_resource_format} ->
        Errors.invalid_resource_format(conn)
    end
  end

  @doc """
  Proxy OAuth authorization requests with resource parameter validation.

  Per MCP spec, clients MUST include the resource parameter in
  authorization requests for proper token audience binding.
  """
  def proxy_authorization(conn, %{"realm" => realm}) do
    Logger.info("Authorization request params: #{inspect(conn.query_params)}")

    case validate_resource_param_for_auth(conn.query_params, conn) do
      :ok ->
        process_authorization_request(conn, realm)

      {:error, :missing_resource} ->
        expected = ResourceValidation.get_expected_resource(conn)
        Errors.missing_resource_parameter(conn, expected)

      {:error, :invalid_resource} ->
        expected = ResourceValidation.get_expected_resource(conn)
        Errors.invalid_resource_parameter(conn, expected)

      {:error, :invalid_resource_format} ->
        Errors.invalid_resource_format(conn)
    end
  end

  @doc """
  Proxy OAuth userinfo requests.
  """
  def proxy_userinfo(conn, %{"realm" => realm}) do
    case proxy_to_provider("GET", realm, "protocol/openid-connect/userinfo", "", conn) do
      {:ok, response} ->
        response_body = format_response_body(response.body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(response.status)
        |> put_resp_content_type("application/json")
        |> send_resp(response.status, response_body)

      {:error, reason} ->
        Logger.error("OAuth userinfo proxy failed: #{inspect(reason)}")
        Errors.proxy_failed(conn, inspect(reason))
    end
  end

  @doc """
  Proxy JWKS requests.
  """
  def proxy_jwks(conn, %{"realm" => realm}) do
    case proxy_to_provider("GET", realm, "protocol/openid-connect/certs", "", conn) do
      {:ok, response} ->
        response_body = format_response_body(response.body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(response.status)
        |> put_resp_content_type("application/json")
        |> put_resp_header("cache-control", "public, max-age=3600")
        |> send_resp(response.status, response_body)

      {:error, reason} ->
        Logger.error("JWKS proxy failed: #{inspect(reason)}")
        Errors.proxy_failed(conn, inspect(reason))
    end
  end

  @doc """
  Handle OAuth callback and redirect back to the original client.
  """
  def proxy_callback(conn, params) do
    original_callback_url = Config.default_callback_url()

    query_string =
      Enum.map_join(params, "&", fn {key, value} -> "#{key}=#{URI.encode(value)}" end)

    redirect_url = "#{original_callback_url}?#{query_string}"

    Logger.debug("OAuth callback proxy: redirecting to #{redirect_url}")

    conn
    |> put_status(302)
    |> put_resp_header("location", redirect_url)
    |> send_resp(302, "")
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

  defp process_authorization_request(conn, realm) do
    client_id = Map.get(conn.query_params, "client_id")

    case determine_oauth_provider(client_id) do
      {:ok, provider_url} ->
        redirect_to_oauth_provider(conn, provider_url, realm)

      {:error, :no_client_id} ->
        Errors.missing_client_id(conn)

      {:error, :client_not_found} ->
        Errors.client_not_found(conn, client_id)
    end
  end

  defp determine_oauth_provider(nil), do: {:error, :no_client_id}

  defp determine_oauth_provider(oauth_client_id) when is_binary(oauth_client_id) do
    case Client.get_by_oauth_client_id(oauth_client_id) do
      {:ok, client} when client.oauth_issuer_url != nil ->
        Logger.info(
          "Routing OAuth client '#{oauth_client_id}' to provider: #{client.oauth_issuer_url}"
        )

        {:ok, client.oauth_issuer_url}

      {:ok, _client} ->
        Logger.info("OAuth client '#{oauth_client_id}' has no custom provider, using default")
        {:error, :client_not_found}

      {:error, _} ->
        {:error, :client_not_found}
    end
  end

  defp redirect_to_oauth_provider(conn, provider_base_url, _realm) do
    supported_scopes = Application.get_env(:aegis, :oauth_scopes_supported, ["openid"])
    requested_scope = Map.get(conn.query_params, "scope", "openid")
    validated_scope = validate_and_filter_scopes(requested_scope, supported_scopes)
    filtered_params = Map.put(conn.query_params, "scope", validated_scope)
    query_string = "?" <> URI.encode_query(filtered_params)

    authorization_endpoint = Provider.build_endpoint(provider_base_url, :authorize)
    redirect_url = "#{authorization_endpoint}#{query_string}"

    Logger.info("Redirecting to OAuth provider: #{redirect_url}")

    conn
    |> AegisWeb.CORS.add_oauth_registration_headers()
    |> put_status(302)
    |> put_resp_header("location", redirect_url)
    |> send_resp(302, "")
  end

  defp proxy_token_to_provider(conn, provider_url, params) do
    token_endpoint = Provider.build_endpoint(provider_url, :token)
    body_params = Map.drop(params, ["realm"])
    body = URI.encode_query(body_params)

    headers = [
      {"content-type", "application/x-www-form-urlencoded"},
      {"accept", "application/json"}
    ]

    Logger.info("Proxying token request to: #{token_endpoint}")

    case Req.post(token_endpoint, body: body, headers: headers) do
      {:ok, %Req.Response{status: status, body: response_body}} ->
        formatted_body = format_response_body(response_body)

        conn
        |> AegisWeb.CORS.add_oauth_registration_headers()
        |> put_status(status)
        |> put_resp_content_type("application/json")
        |> send_resp(status, formatted_body)

      {:error, reason} ->
        Logger.error("Token request to #{provider_url} failed: #{inspect(reason)}")
        Errors.proxy_failed(conn)
    end
  end

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

  defp validate_and_filter_scopes(requested_scope, supported_scopes)
       when is_binary(requested_scope) do
    requested_scopes =
      requested_scope
      |> String.split(~r/[\s,]+/, trim: true)
      |> Enum.uniq()

    valid_scopes =
      requested_scopes
      |> Enum.filter(&(&1 in supported_scopes))

    case valid_scopes do
      [] -> "openid"
      scopes -> Enum.join(scopes, " ")
    end
  end

  defp format_response_body(body) when is_binary(body), do: body
  defp format_response_body(body) when is_map(body), do: Jason.encode!(body)
  defp format_response_body(body), do: inspect(body)

  defp validate_resource_param_for_token(params, conn) do
    ResourceValidation.extract_and_validate_resource(params, conn)
  end

  defp validate_resource_param_for_auth(params, conn) do
    case ResourceValidation.extract_and_validate_resource(params, conn) do
      :ok -> :ok
      {:error, _reason} = error -> error
    end
  end
end
