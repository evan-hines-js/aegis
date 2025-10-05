defmodule Aegis.MCP.OAuth.ScopeAuthorization do
  @moduledoc """
  OAuth 2.1 scope-based authorization for MCP operations.

  Implements RFC 6750 Section 3 and MCP OAuth specification requirements
  for runtime scope validation and insufficient_scope error handling.

  This module provides:
  - Scope requirement mapping for MCP operations
  - Runtime scope validation against JWT tokens
  - HTTP 403 Forbidden responses with proper WWW-Authenticate headers
  - Step-up authorization guidance for clients
  """

  require Logger
  alias Aegis.MCP.OAuth.{JWTService, WWWAuthenticate}

  @doc """
  Get required scopes for an MCP operation.

  Maps MCP method names to their required OAuth scopes following
  the pattern: <resource_type>:<action>

  ## Examples

      iex> get_required_scopes("tools/call")
      ["tools:call"]

      iex> get_required_scopes("resources/read")
      ["resources:read"]
  """
  @method_scopes %{
    "tools/call" => ["tools:call"],
    "tools/list" => ["tools:call"],
    "resources/read" => ["resources:read"],
    "resources/list" => ["resources:read"],
    "resources/templates/list" => ["resources:read"],
    "prompts/get" => ["prompts:read"],
    "prompts/list" => ["prompts:read"],
    "roots/list" => ["roots:list"],
    "sampling/createMessage" => ["sampling:create"],
    "completion/complete" => ["sampling:create"],
    "initialize" => [],
    "ping" => []
  }

  @spec get_required_scopes(String.t()) :: [String.t()]
  def get_required_scopes(method) do
    Map.get(@method_scopes, method, [])
  end

  @doc """
  Validate that a request has sufficient scopes for the operation.

  Checks JWT claims against required scopes for the MCP method.
  Returns :ok if authorized, or {:error, details} if insufficient scope.

  ## Return values

  - `{:ok, scopes}` - Authorization successful, returns token scopes
  - `{:error, :insufficient_scope, required, current}` - Missing scopes
  - `{:error, :no_scope_claim}` - Token has no scope claim
  """
  @spec validate_scopes(map(), String.t()) ::
          {:ok, [String.t()]}
          | {:error, :insufficient_scope, [String.t()], [String.t()]}
          | {:error, :no_scope_claim}
  def validate_scopes(jwt_claims, method) do
    required_scopes = get_required_scopes(method)
    token_scopes = JWTService.extract_scopes(jwt_claims)

    cond do
      # No scopes required for this operation
      required_scopes == [] ->
        {:ok, token_scopes}

      # Token has no scope claim but scopes are required
      token_scopes == [] ->
        Logger.warning(
          "Token has no scope claim but method '#{method}' requires: #{inspect(required_scopes)}"
        )

        {:error, :no_scope_claim}

      # Check if all required scopes are present
      JWTService.has_required_scopes?(jwt_claims, required_scopes) ->
        {:ok, token_scopes}

      # Missing some required scopes
      true ->
        missing = required_scopes -- token_scopes

        Logger.warning(
          "Insufficient scope for method '#{method}'. " <>
            "Required: #{inspect(required_scopes)}, " <>
            "Token has: #{inspect(token_scopes)}, " <>
            "Missing: #{inspect(missing)}"
        )

        {:error, :insufficient_scope, required_scopes, token_scopes}
    end
  end

  @doc """
  Build scope string for WWW-Authenticate header during step-up authorization.

  Per MCP OAuth spec, the scope parameter should include:
  - All currently granted scopes (to prevent losing permissions)
  - Newly required scopes for the operation

  This provides the most user-friendly experience by maintaining existing
  permissions while requesting additional needed scopes.
  """
  @spec build_scope_challenge([String.t()], [String.t()]) :: String.t()
  def build_scope_challenge(current_scopes, required_scopes) do
    # Combine current and required scopes, remove duplicates
    all_scopes =
      (current_scopes ++ required_scopes)
      |> Enum.uniq()
      |> Enum.sort()

    Enum.join(all_scopes, " ")
  end

  @doc """
  Send a 403 Forbidden response with insufficient_scope error.

  Per RFC 6750 Section 3.1 and MCP OAuth spec, this function:
  1. Sets HTTP 403 status
  2. Includes WWW-Authenticate header with:
     - error="insufficient_scope"
     - scope parameter with required scopes
     - resource_metadata URL for discovery
  3. Returns JSON error body with details

  The response guides MCP clients to request additional scopes
  through the step-up authorization flow.
  """
  @spec send_insufficient_scope_response(
          Plug.Conn.t(),
          [String.t()],
          [String.t()],
          String.t() | nil
        ) ::
          Plug.Conn.t()
  def send_insufficient_scope_response(
        conn,
        required_scopes,
        current_scopes,
        description \\ nil
      ) do
    # Build scope challenge that includes both current and required scopes
    scope_challenge = build_scope_challenge(current_scopes, required_scopes)

    # Generate WWW-Authenticate header
    www_authenticate_header =
      WWWAuthenticate.generate_insufficient_scope_header(
        conn,
        scope_challenge,
        description
      )

    # Build error description
    missing_scopes = required_scopes -- current_scopes
    default_description = "Additional scopes required: #{Enum.join(missing_scopes, ", ")}"
    error_description = description || default_description

    conn
    |> Plug.Conn.put_resp_header("www-authenticate", www_authenticate_header)
    |> Plug.Conn.put_status(403)
    |> Phoenix.Controller.json(%{
      "error" => "insufficient_scope",
      "error_description" => error_description,
      "required_scopes" => required_scopes,
      "current_scopes" => current_scopes,
      "missing_scopes" => missing_scopes
    })
    |> Plug.Conn.halt()
  end

  @doc """
  Send a 401 Unauthorized response with scope guidance.

  Used when no valid token is present but we want to guide the client
  about which scopes they'll need.
  """
  @spec send_unauthorized_with_scope(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def send_unauthorized_with_scope(conn, method) do
    required_scopes = get_required_scopes(method)
    scope_string = Enum.join(required_scopes, " ")

    www_authenticate_header =
      if scope_string != "" do
        WWWAuthenticate.generate_header(conn, scope: scope_string)
      else
        WWWAuthenticate.generate_header(conn)
      end

    conn
    |> Plug.Conn.put_resp_header("www-authenticate", www_authenticate_header)
    |> Plug.Conn.put_status(401)
    |> Phoenix.Controller.json(%{
      "error" => "unauthorized",
      "error_description" => "Valid access token required",
      "required_scopes" => required_scopes
    })
    |> Plug.Conn.halt()
  end
end
