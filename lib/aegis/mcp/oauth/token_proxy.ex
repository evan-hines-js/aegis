defmodule Aegis.MCP.OAuth.TokenProxy do
  @moduledoc """
  OAuth token proxy service for handling token exchange operations.

  Extracted from OAuthMetadataController to separate HTTP concerns from
  business logic and improve maintainability.
  """

  require Logger
  alias Aegis.MCP.OAuth.Config
  alias Aegis.MCP.OAuth.Errors
  alias Aegis.MCP.OAuthToken

  @doc """
  Proxy OAuth token requests to Keycloak.

  Returns the response data and status for the controller to handle HTTP concerns.
  """
  @spec proxy_token_request(String.t(), map()) ::
          {:ok, pos_integer(), binary()} | {:error, atom(), binary()}
  def proxy_token_request(realm, params) do
    # Convert parsed params back to form-encoded data since token endpoint expects form data
    body_params = Map.drop(params, ["realm"])

    # Add client authentication if client_id is present
    {body_params, headers} = prepare_request_with_auth(body_params)

    body = URI.encode_query(body_params)
    url = "#{Config.keycloak_base_url()}/realms/#{realm}/protocol/openid-connect/token"

    Logger.debug("Token request to #{url} with headers: #{inspect(headers)}")

    case make_token_request(url, body, headers) do
      {:ok, %{status: 200, body: response_body}} ->
        formatted_body = format_response_body(response_body)

        # Parse successful token response and create OAuth token record
        case create_oauth_token_from_response(response_body, body_params) do
          {:ok, _oauth_token} ->
            Logger.info("OAuth token mapping created successfully")

          {:error, reason} ->
            Logger.warning("Failed to create OAuth token mapping: #{inspect(reason)}")
            # Continue with response even if token mapping fails
        end

        {:ok, 200, formatted_body}

      {:ok, %{status: status, body: response_body}} ->
        # Non-200 responses (errors) - just proxy them
        formatted_body = format_response_body(response_body)
        {:ok, status, formatted_body}

      {:error, reason} ->
        Errors.handle_error({:error, reason}, "token_proxy")
    end
  end

  # Prepare request with client authentication
  #
  # For Keycloak proxy flow, we pass through all parameters as-is.
  # PKCE (code_verifier) provides security without needing to store client_secret.
  defp prepare_request_with_auth(body_params) do
    headers = [
      {"content-type", "application/x-www-form-urlencoded"},
      {"accept", "application/json"}
    ]

    if Map.has_key?(body_params, "code_verifier") do
      Logger.debug("PKCE flow detected, passing through parameters without modification")
    end

    {body_params, headers}
  end

  # Make the HTTP request to Keycloak
  defp make_token_request(url, body, headers) do
    Req.post(url, body: body, headers: headers)
  end

  # Format response body ensuring it's valid JSON
  defp format_response_body(response_body) when is_binary(response_body) do
    case Jason.decode(response_body) do
      {:ok, _decoded} -> response_body
      {:error, _} -> Jason.encode!(%{"error" => "invalid_response"})
    end
  end

  defp format_response_body(response_body) when is_map(response_body) do
    Jason.encode!(response_body)
  end

  defp format_response_body(_), do: Jason.encode!(%{"error" => "invalid_response"})

  # Create OAuth token record from successful response
  defp create_oauth_token_from_response(response_body, request_params) do
    with {:ok, token_data} <- parse_token_response(response_body),
         {:ok, client_id} <- extract_client_id(request_params),
         {:ok, mcp_client} <- lookup_mcp_client(client_id) do
      create_oauth_token_record(token_data, client_id, mcp_client)
    else
      {:error, reason} -> {:error, reason}
    end
  end

  # Parse token response JSON
  defp parse_token_response(response_body) when is_binary(response_body) do
    case Jason.decode(response_body) do
      {:ok, %{"access_token" => _} = token_data} -> {:ok, token_data}
      {:ok, _} -> {:error, :no_access_token}
      {:error, _} -> {:error, :invalid_json}
    end
  end

  defp parse_token_response(response_body) when is_map(response_body) do
    case Map.get(response_body, "access_token") do
      nil -> {:error, :no_access_token}
      _ -> {:ok, response_body}
    end
  end

  # Extract client ID from request parameters
  defp extract_client_id(request_params) do
    case Map.get(request_params, "client_id") do
      nil -> {:error, :no_client_id}
      client_id when is_binary(client_id) -> {:ok, client_id}
      _ -> {:error, :invalid_client_id}
    end
  end

  # Look up MCP client by OAuth client ID via token mapping
  defp lookup_mcp_client(oauth_client_id) do
    alias Aegis.MCP.OAuth.ClientLookup
    ClientLookup.by_oauth_token(oauth_client_id)
  end

  # Create OAuth token record in database
  defp create_oauth_token_record(token_data, keycloak_client_id, mcp_client) do
    case OAuthToken.create_token(
           mcp_client.id,
           keycloak_client_id,
           Map.get(token_data, "access_token"),
           Map.get(token_data, "refresh_token"),
           Map.get(token_data, "expires_in", 3600),
           Map.get(token_data, "scope", "")
         ) do
      {:ok, oauth_token} ->
        Logger.info("Created OAuth token record for client #{keycloak_client_id}")
        {:ok, oauth_token}

      {:error, reason} ->
        Logger.error("Failed to create OAuth token record: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
