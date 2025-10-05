defmodule Aegis.MCP.OAuth.Errors do
  @moduledoc """
  Unified OAuth error handling for both Authorization Server and Resource Server roles.

  This module consolidates all OAuth error handling, providing:
  - Error type definitions and normalization
  - HTTP status code mapping
  - JSON response generation
  - WWW-Authenticate header generation (RFC 6750)
  - Plug.Conn integration for controllers
  - Standardized logging

  ## Error Responses

  ### Authorization Server Errors (OAuth Proxy)
  - Used by token, authorization, and registration endpoints
  - Standard OAuth 2.0 error responses with CORS support

  ### Resource Server Errors (MCP Server)
  - Used by MCP endpoints requiring OAuth authentication
  - RFC 6750 compliant with WWW-Authenticate headers
  - Supports step-up authorization for insufficient scope

  ## Usage

      # In a controller/plug (Authorization Server)
      OAuth.Errors.send_error(conn, :invalid_client, "Client not found")

      # In MCP endpoint (Resource Server)
      OAuth.Errors.unauthorized(conn, :token_expired,
        error_description: "Token has expired",
        required_scopes: ["tools:call"]
      )
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]
  require Logger

  alias Aegis.MCP.OAuth.WWWAuthenticate

  # Type Definitions

  @typedoc "Standard OAuth error types"
  # Configuration errors
  @type oauth_error ::
          :missing_configuration
          | :invalid_configuration
          # Authentication errors
          | :invalid_client
          | :invalid_client_secret
          | :client_not_found
          | :client_inactive
          # Token errors
          | :invalid_token
          | :token_expired
          | :token_malformed
          | :missing_token
          | :token_creation_failed
          | :token_refresh_failed
          # JWKS errors
          | :jwks_fetch_failed
          | :jwks_invalid
          | :key_not_found
          | :key_conversion_failed
          # JWT validation errors
          | :invalid_signature
          | :missing_required_claims
          | :invalid_issuer
          | :invalid_audience
          | :signature_verification_error
          # Network/HTTP errors
          | :network_error
          | :timeout_error
          | :proxy_failed
          | :invalid_response
          # General errors
          | :invalid_request
          | :unauthorized
          | :forbidden
          | :not_found
          | :invalid_target
          | :insufficient_scope
          | :registration_failed

  @typedoc "Error result tuple"
  @type error_result :: {:error, oauth_error()} | {:error, oauth_error(), String.t()}

  # Error Normalization

  @doc """
  Convert various error formats to standardized OAuth errors.

  Handles errors from different libraries and systems, providing
  consistent error types across the OAuth implementation.
  """
  @spec normalize_error(term()) :: error_result()
  def normalize_error({:error, reason}) when is_atom(reason), do: {:error, reason}
  def normalize_error({:error, %Jason.DecodeError{}}), do: {:error, :invalid_response}

  def normalize_error({:error, %Req.TransportError{reason: :timeout}}),
    do: {:error, :timeout_error}

  def normalize_error({:error, %Req.TransportError{}}), do: {:error, :network_error}
  def normalize_error({:error, :econnrefused}), do: {:error, :network_error}
  def normalize_error({:error, :timeout}), do: {:error, :timeout_error}

  # Ash errors
  def normalize_error({:error, %{__struct__: struct_name}}) when is_atom(struct_name) do
    case to_string(struct_name) do
      "Elixir.Ash.Error.Invalid" -> {:error, :invalid_request}
      "Elixir.Ash.Error.NotFound" -> {:error, :not_found}
      "Elixir.Ash.Error.Forbidden" -> {:error, :forbidden}
      _ -> {:error, :invalid_request}
    end
  end

  # JOSE errors
  def normalize_error({:error, {:badarg, _}}), do: {:error, :invalid_token}
  def normalize_error({:error, :invalid_signature}), do: {:error, :invalid_signature}

  # Application configuration errors
  def normalize_error({:error, {:badkey, _key}}), do: {:error, :missing_configuration}
  def normalize_error({:error, :badarg}), do: {:error, :invalid_configuration}

  # Fallback for unknown errors
  def normalize_error({:error, reason}) when is_binary(reason),
    do: {:error, :invalid_request, reason}

  def normalize_error({:error, reason}), do: {:error, :invalid_request, inspect(reason)}
  def normalize_error(_), do: {:error, :invalid_request}

  # HTTP Status Code Mapping

  @error_status_map %{
    # 400 Bad Request
    invalid_request: 400,
    invalid_token: 400,
    token_malformed: 400,
    missing_token: 400,
    missing_required_claims: 400,
    invalid_response: 400,
    # 401 Unauthorized
    unauthorized: 401,
    invalid_client: 401,
    invalid_client_secret: 401,
    token_expired: 401,
    invalid_signature: 401,
    invalid_issuer: 401,
    invalid_audience: 401,
    signature_verification_error: 401,
    # 403 Forbidden
    forbidden: 403,
    client_inactive: 403,
    insufficient_scope: 403,
    # 404 Not Found
    not_found: 404,
    client_not_found: 404,
    key_not_found: 404,
    # 500 Internal Server Error
    missing_configuration: 500,
    invalid_configuration: 500,
    token_creation_failed: 500,
    jwks_fetch_failed: 500,
    jwks_invalid: 500,
    key_conversion_failed: 500,
    registration_failed: 500,
    # 502 Bad Gateway
    network_error: 502,
    proxy_failed: 502,
    # 503 Service Unavailable
    token_refresh_failed: 503,
    # 504 Gateway Timeout
    timeout_error: 504
  }

  @doc """
  Convert OAuth errors to HTTP status codes.
  """
  @spec error_to_http_status(oauth_error()) :: pos_integer()
  def error_to_http_status(error) do
    Map.get(@error_status_map, error, 500)
  end

  # OAuth 2.0 Spec Error Codes

  @oauth_spec_map %{
    invalid_request:
      {"invalid_request", "The request is missing a required parameter or is otherwise malformed"},
    invalid_client: {"invalid_client", "Client authentication failed"},
    invalid_client_secret: {"invalid_client", "Invalid client secret"},
    unauthorized: {"invalid_client", "The client is not authorized"},
    invalid_token: {"invalid_token", "The access token provided is invalid"},
    token_expired: {"invalid_token", "The access token has expired"},
    token_malformed: {"invalid_token", "The access token is malformed"},
    missing_token: {"invalid_request", "Access token is required"},
    invalid_signature: {"invalid_token", "Token signature verification failed"},
    invalid_issuer: {"invalid_token", "Token issuer is not trusted"},
    invalid_audience: {"invalid_token", "Token audience does not match"},
    client_not_found: {"invalid_client", "Client not found"},
    client_inactive: {"invalid_client", "Client is inactive"},
    network_error: {"temporarily_unavailable", "Network error occurred"},
    timeout_error: {"temporarily_unavailable", "Request timed out"},
    proxy_failed: {"server_error", "Proxy operation failed"},
    token_creation_failed: {"server_error", "Unable to create access token"},
    token_refresh_failed: {"temporarily_unavailable", "Token refresh service unavailable"},
    jwks_fetch_failed: {"server_error", "Unable to fetch signing keys"},
    missing_configuration: {"server_error", "OAuth service configuration error"},
    invalid_configuration: {"server_error", "OAuth service configuration invalid"},
    invalid_target: {"invalid_target", "Resource parameter does not match this server"},
    insufficient_scope: {"insufficient_scope", "Token lacks required permissions"},
    registration_failed: {"registration_failed", "Unable to register client"}
  }

  defp error_to_oauth_spec(error) do
    Map.get(@oauth_spec_map, error, {"server_error", "An unexpected error occurred"})
  end

  # JSON Response Generation

  @doc """
  Build standardized OAuth error response body.
  """
  @spec build_error_body(String.t() | atom(), String.t()) :: map()
  def build_error_body(error_code, error_description) do
    error_code_str = if is_atom(error_code), do: to_string(error_code), else: error_code

    %{
      "error" => error_code_str,
      "error_description" => error_description
    }
  end

  @doc """
  Convert OAuth errors to JSON error responses.
  """
  @spec error_to_json_response(oauth_error()) :: map()
  def error_to_json_response(error) do
    {oauth_error_code, description} = error_to_oauth_spec(error)
    build_error_body(oauth_error_code, description)
  end

  @doc """
  Convert OAuth errors to JSON error responses with custom description.
  """
  @spec error_to_json_response(oauth_error(), String.t()) :: map()
  def error_to_json_response(error, custom_description) do
    {oauth_error_code, _description} = error_to_oauth_spec(error)
    build_error_body(oauth_error_code, custom_description)
  end

  # Plug.Conn Integration - Authorization Server (Proxy)

  @doc """
  Send a standardized OAuth error response (for Authorization Server endpoints).

  ## Options
  - `:status` - HTTP status code (default: determined from error)

  ## Examples

      send_error(conn, :invalid_request, "Missing client_id parameter")
      send_error(conn, :client_not_found, "Client not found", status: 404)
  """
  @spec send_error(Plug.Conn.t(), oauth_error() | atom(), String.t(), keyword()) ::
          Plug.Conn.t()
  def send_error(conn, error_code, description, opts \\ []) do
    status = Keyword.get(opts, :status) || error_to_http_status(error_code)

    conn
    |> put_status(status)
    |> put_resp_content_type("application/json")
    |> json(build_error_body(error_code, description))
  end

  @doc """
  Send OAuth error response with CORS headers (for proxy endpoints).
  """
  @spec send_error_with_cors(Plug.Conn.t(), oauth_error() | atom(), String.t(), keyword()) ::
          Plug.Conn.t()
  def send_error_with_cors(conn, error_code, description, opts \\ []) do
    conn
    |> AegisWeb.CORS.add_oauth_registration_headers()
    |> send_error(error_code, description, opts)
  end

  # Plug.Conn Integration - Resource Server (MCP)

  @doc """
  Send 401 Unauthorized response with WWW-Authenticate header (for MCP endpoints).

  Options:
  - `:error_description` - Human-readable error description
  - `:required_scopes` - List of scopes required (included in WWW-Authenticate)
  """
  @spec unauthorized(Plug.Conn.t(), atom() | String.t(), keyword()) :: Plug.Conn.t()
  def unauthorized(conn, error_code \\ :invalid_token, opts \\ []) do
    error_description = Keyword.get(opts, :error_description)
    required_scopes = Keyword.get(opts, :required_scopes, [])

    error_code_str = to_string(error_code)

    www_authenticate =
      WWWAuthenticate.generate_error_header(
        conn,
        error_code_str,
        error_description,
        scope: required_scopes
      )

    body = build_error_body(error_code_str, error_description || "Authentication required")

    Logger.warning("OAuth 401 Unauthorized: #{error_code_str} - #{error_description}")

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(body))
    |> halt()
  end

  @doc """
  Send 401 Unauthorized for missing credentials (no error params in WWW-Authenticate).
  """
  @spec unauthorized_missing_credentials(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def unauthorized_missing_credentials(conn, opts \\ []) do
    required_scopes = Keyword.get(opts, :required_scopes, [])

    www_authenticate = WWWAuthenticate.generate_header(conn, scope: required_scopes)
    body = build_error_body("unauthorized", "Authentication required")

    Logger.info("OAuth 401: Missing credentials")

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(body))
    |> halt()
  end

  @doc """
  Send 403 Forbidden response for insufficient scope (triggers step-up authorization).

  Options:
  - `:required_scopes` - List of scopes needed for the operation (REQUIRED)
  - `:error_description` - Human-readable error description
  - `:granted_scopes` - List of scopes currently granted
  """
  @spec insufficient_scope(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def insufficient_scope(conn, opts) do
    required_scopes = Keyword.get(opts, :required_scopes, [])
    granted_scopes = Keyword.get(opts, :granted_scopes, [])
    error_description = Keyword.get(opts, :error_description, "Insufficient scope")

    # Build scope challenge including both granted and required scopes
    scope_challenge =
      (granted_scopes ++ required_scopes)
      |> Enum.uniq()
      |> Enum.join(" ")

    www_authenticate =
      WWWAuthenticate.generate_insufficient_scope_header(conn, scope_challenge, error_description)

    body = build_error_body("insufficient_scope", error_description)

    Logger.warning(
      "OAuth 403 Forbidden: insufficient_scope - Required: #{inspect(required_scopes)}, Granted: #{inspect(granted_scopes)}"
    )

    conn
    |> put_resp_header("www-authenticate", www_authenticate)
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(body))
    |> halt()
  end

  @doc """
  Send 400 Bad Request for invalid OAuth requests.
  """
  @spec bad_request(Plug.Conn.t(), String.t(), keyword()) :: Plug.Conn.t()
  def bad_request(conn, error_description, opts \\ []) do
    error_code = Keyword.get(opts, :error_code, "invalid_request")
    body = build_error_body(error_code, error_description)

    Logger.warning("OAuth 400 Bad Request: #{error_code} - #{error_description}")

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(400, Jason.encode!(body))
    |> halt()
  end

  @doc """
  Send 500 Internal Server Error for OAuth processing failures.
  """
  @spec server_error(Plug.Conn.t(), String.t(), keyword()) :: Plug.Conn.t()
  def server_error(conn, error_description, _opts \\ []) do
    body = build_error_body("server_error", error_description)

    Logger.error("OAuth 500 Server Error: #{error_description}")

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(500, Jason.encode!(body))
    |> halt()
  end

  # Common Error Response Helpers

  @doc """
  Common error responses for OAuth flows.
  """

  def missing_client_id(conn) do
    send_error_with_cors(
      conn,
      :invalid_request,
      "client_id is required for token requests"
    )
  end

  def client_not_found(conn, client_id \\ nil) do
    description =
      if client_id do
        "Client '#{client_id}' not found or not configured for OAuth. Please contact your administrator."
      else
        "Client not found or not configured for OAuth"
      end

    send_error_with_cors(conn, :invalid_client, description)
  end

  def missing_resource_parameter(conn, expected \\ nil) do
    description =
      if expected do
        "Missing required 'resource' parameter. Per RFC 8707 and MCP OAuth specification, MCP clients must include the resource parameter. Expected: #{expected}"
      else
        "Missing required 'resource' parameter. Per RFC 8707, MCP clients must include the resource parameter identifying the target MCP server."
      end

    send_error_with_cors(conn, :invalid_request, description)
  end

  def invalid_resource_parameter(conn, expected) do
    send_error_with_cors(
      conn,
      :invalid_target,
      "Resource parameter does not match this MCP server. Expected: #{expected}"
    )
  end

  def invalid_resource_format(conn) do
    send_error_with_cors(
      conn,
      :invalid_request,
      "Resource parameter must be a valid URI string"
    )
  end

  def proxy_failed(conn, reason \\ "Failed to contact OAuth provider") do
    send_error_with_cors(conn, :proxy_failed, reason, status: 500)
  end

  def registration_failed(conn) do
    send_error_with_cors(
      conn,
      :registration_failed,
      "Unable to register client",
      status: 500
    )
  end

  def client_retrieval_failed(conn) do
    send_error_with_cors(
      conn,
      :invalid_client,
      "Client not found",
      status: 404
    )
  end

  def update_failed(conn) do
    send_error_with_cors(
      conn,
      :invalid_request,
      "Failed to update client",
      status: 500
    )
  end

  def deletion_failed(conn) do
    send_error_with_cors(
      conn,
      :invalid_request,
      "Failed to delete client",
      status: 500
    )
  end

  # Logging

  @doc """
  Handle error with logging and JSON response generation.

  Takes any error, normalizes it, logs it appropriately, and returns
  a standardized error tuple with JSON response.
  """
  @spec handle_error(term(), String.t(), keyword()) :: {:error, oauth_error(), String.t()}
  def handle_error(error, context, metadata \\ []) do
    {:error, normalized_error} = normalize_error(error)
    log_error(normalized_error, context, metadata)
    json_response = error_to_json_response(normalized_error) |> Jason.encode!()
    {:error, normalized_error, json_response}
  end

  @doc """
  Log OAuth errors with appropriate log levels.
  """
  @spec log_error(oauth_error(), String.t(), keyword()) :: :ok
  def log_error(error, context, metadata \\ []) do
    log_level = error_log_level(error)
    message = "OAuth Error in #{context}: #{inspect(error)}"

    case log_level do
      :error -> Logger.error(message, metadata)
      :warning -> Logger.warning(message, metadata)
      :info -> Logger.info(message, metadata)
      :debug -> Logger.debug(message, metadata)
    end
  end

  @error_log_level_map %{
    # Critical errors that need immediate attention
    missing_configuration: :error,
    invalid_configuration: :error,
    jwks_fetch_failed: :error,
    token_creation_failed: :error,
    # Security-related errors that should be logged but are expected
    invalid_client: :warning,
    invalid_token: :warning,
    token_expired: :warning,
    unauthorized: :warning,
    forbidden: :warning,
    # Transient errors that may resolve themselves
    network_error: :info,
    timeout_error: :info,
    token_refresh_failed: :info,
    # Expected errors during normal operation
    client_not_found: :debug,
    not_found: :debug
  }

  defp error_log_level(error) do
    Map.get(@error_log_level_map, error, :warning)
  end

  @doc """
  Check if a connection has been halted by an OAuth error response.
  """
  @spec halted?(Plug.Conn.t()) :: boolean()
  def halted?(conn) do
    conn.halted
  end
end
