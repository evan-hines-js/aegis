defmodule Aegis.MCP.HeaderValidation do
  @moduledoc """
  Shared header validation logic for MCP HTTP requests.

  Provides consistent validation for protocol version, accept headers,
  origin headers, and session management across controllers.
  """

  require Logger
  alias Aegis.MCP.{Authorization, ErrorResponse, SessionCache}

  @supported_protocol_versions ["2025-03-26", "2025-06-18"]
  @default_protocol_version "2025-03-26"

  @type validation_result :: {:ok, any()} | {:error, any()}

  @doc """
  Validate MCP protocol version header.

  Returns the validated version or the default if no header is present.
  """
  @spec validate_protocol_version(Plug.Conn.t()) :: validation_result()
  def validate_protocol_version(conn) do
    case Plug.Conn.get_req_header(conn, "mcp-protocol-version") do
      [] ->
        {:ok, @default_protocol_version}

      [version] when version in @supported_protocol_versions ->
        {:ok, version}

      [version] ->
        ErrorResponse.build_controller_error(
          conn,
          :bad_request,
          ErrorResponse.invalid_request(),
          "Unsupported MCP protocol version: #{version}"
        )

      _multiple ->
        ErrorResponse.build_controller_error(
          conn,
          :bad_request,
          ErrorResponse.invalid_request(),
          "Multiple MCP-Protocol-Version headers not allowed"
        )
    end
  end

  @doc """
  Validate Accept header for appropriate content types.

  For initialize method, always allows JSON. For other methods,
  checks for either JSON or event-stream support.
  """
  @spec validate_accept_header(Plug.Conn.t(), String.t() | nil) :: validation_result()
  def validate_accept_header(conn, method \\ nil)

  def validate_accept_header(conn, "initialize") do
    # For initialize, always return JSON response to establish session first
    # SSE streams should be used for subsequent requests after initialization
    case Plug.Conn.get_req_header(conn, "accept") do
      [] ->
        {:ok, "application/json"}

      accept_headers ->
        accept_string = Enum.join(accept_headers, ", ")

        cond do
          String.contains?(accept_string, "application/json") ->
            {:ok, "application/json"}

          String.contains?(accept_string, "text/event-stream") ->
            # Even if client only accepts SSE, return JSON for initialize
            # This ensures proper session establishment
            {:ok, "application/json"}

          true ->
            # Default to JSON for initialize
            {:ok, "application/json"}
        end
    end
  end

  def validate_accept_header(conn, _method) do
    case Plug.Conn.get_req_header(conn, "accept") do
      [] ->
        {:ok, "application/json"}

      accept_headers ->
        accept_string = Enum.join(accept_headers, ", ")

        supports_json = String.contains?(accept_string, "application/json")
        supports_sse = String.contains?(accept_string, "text/event-stream")

        cond do
          supports_json and supports_sse ->
            # Client supports both - server can choose
            {:ok, "both"}

          supports_json ->
            {:ok, "application/json"}

          supports_sse ->
            {:ok, "text/event-stream"}

          true ->
            ErrorResponse.build_controller_error(
              conn,
              :not_acceptable,
              ErrorResponse.invalid_request(),
              "Accept header must include application/json or text/event-stream"
            )
        end
    end
  end

  @doc """
  Validate Accept header specifically for SSE endpoints.
  """
  @spec validate_sse_accept_header(Plug.Conn.t()) :: validation_result()
  def validate_sse_accept_header(conn) do
    case Plug.Conn.get_req_header(conn, "accept") do
      [] ->
        {:error, :invalid_accept}

      accept_headers ->
        accept_string = Enum.join(accept_headers, ", ")

        if String.contains?(accept_string, "text/event-stream") do
          {:ok, :valid}
        else
          {:error, :invalid_accept}
        end
    end
  end

  @doc """
  Validate session ID header and check session validity.

  For initialize method, creates a new session. For other methods,
  validates the existing session.
  """
  @spec validate_session(Plug.Conn.t(), String.t()) ::
          {:ok, String.t() | nil | :ping} | {:error, atom()}
  def validate_session(conn, method)

  def validate_session(_conn, "initialize") do
    # For initialize, don't create session yet - handler will decide stateful vs stateless
    {:ok, nil}
  end

  def validate_session(conn, "ping") do
    # Per MCP spec, ping requests should be allowed before initialization
    # But we still need to authenticate the client if an API key is provided
    case validate_client_api_key(conn) do
      {:ok, _client_id} ->
        # Valid API key provided - allow ping
        {:ok, :ping}

      {:error, :no_api_key} ->
        # No API key provided - still allow ping per MCP spec
        {:ok, :ping}

      {:error, reason} ->
        # Invalid API key provided - reject
        {:error, reason}
    end
  end

  def validate_session(conn, _method) do
    case Plug.Conn.get_req_header(conn, "mcp-session-id") do
      [session_id] -> validate_session_id(conn, session_id)
      [] -> {:ok, nil}
      _multiple -> {:error, :multiple_session_headers}
    end
  end

  # Validate session ID and check permissions
  defp validate_session_id(conn, session_id) do
    case SessionCache.get(session_id) do
      {:ok, session_data} ->
        validate_session_ownership(conn, session_id, session_data)

      {:error, :not_found} ->
        {:error, :session_not_found}
    end
  end

  # Check if session is remote or local and validate accordingly
  defp validate_session_ownership(conn, session_id, session_data) do
    owner_node = session_data.owner_node

    if owner_node && owner_node != node() do
      # Remote session - trust it
      {:ok, session_id}
    else
      # Local session - validate client_id matches API key
      validate_local_session(conn, session_id, session_data.client_id)
    end
  end

  # Validate that API key belongs to the session's client
  defp validate_local_session(conn, session_id, client_id) do
    case validate_api_key_for_client(conn, client_id) do
      {:ok, _client_id} -> {:ok, session_id}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get the Last-Event-ID header value for SSE resumability.
  """
  @spec get_last_event_id(Plug.Conn.t()) :: integer() | nil
  def get_last_event_id(conn) do
    case Plug.Conn.get_req_header(conn, "last-event-id") do
      [event_id] ->
        case Integer.parse(event_id) do
          {id, ""} -> id
          _ -> nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Get or create an event counter for SSE streams.
  """
  @spec get_or_create_event_counter(String.t(), integer() | nil) :: integer()
  def get_or_create_event_counter(session_id, last_event_id) do
    case last_event_id do
      nil ->
        # New stream, start from 1
        1

      id when is_integer(id) ->
        # Resume from last event ID + 1
        require Logger
        Logger.info("Resuming SSE stream for session #{session_id} from event #{id + 1}")
        id + 1
    end
  end

  @doc """
  List of supported protocol versions.
  """
  def supported_protocol_versions, do: @supported_protocol_versions

  @doc """
  Default protocol version.
  """
  def default_protocol_version, do: @default_protocol_version

  @doc """
  Validate MCP client API key from Authorization header with authentication logging.

  This function should only be used during initial authentication (e.g., initialize method).
  For session validation, use validate_api_key_for_client/2 instead.

  Looks for 'Authorization: Bearer <token>' header and validates it against stored client credentials.
  Returns {:ok, client_id} if valid, {:error, reason} if invalid,
  or {:error, :no_api_key} if no key provided.
  """
  @spec validate_client_api_key(Plug.Conn.t()) ::
          {:ok, String.t()} | {:error, :no_api_key | :invalid_api_key | :client_inactive}
  def validate_client_api_key(conn) do
    case extract_token_from_conn(conn) do
      {:ok, token} -> authenticate_bearer_token(token)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Validate that the provided API key belongs to the expected client.

  This function verifies that the Authorization header contains a valid API key
  that belongs to the specified client_id. Used for session validation where
  we already know the expected client from the session data.

  Does not log authentication events since this is authorization validation,
  not initial authentication.
  """
  @spec validate_api_key_for_client(Plug.Conn.t(), String.t()) ::
          {:ok, String.t()} | {:error, :no_api_key | :invalid_api_key}
  def validate_api_key_for_client(conn, expected_client_id) do
    case extract_token_from_conn(conn) do
      {:ok, token} ->
        case Authorization.validate_token_for_client(token, expected_client_id) do
          {:ok, ^expected_client_id} -> {:ok, expected_client_id}
          {:ok, _different_client_id} -> {:error, :invalid_api_key}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Extract token from Authorization header in conn
  defp extract_token_from_conn(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [] -> {:error, :no_api_key}
      [auth_header] -> extract_bearer_token(auth_header)
      _multiple -> {:error, :invalid_api_key}
    end
  end

  # Extract Bearer token from Authorization header
  defp extract_bearer_token("Bearer " <> token), do: {:ok, String.trim(token)}

  defp extract_bearer_token(token) do
    # Allow raw API keys without Bearer prefix
    trimmed = String.trim(token)

    if String.starts_with?(trimmed, "ak_") do
      {:ok, trimmed}
    else
      {:error, :invalid_api_key}
    end
  end

  # Private helper to authenticate bearer token (JWT or API key)
  defp authenticate_bearer_token(token) do
    case Authorization.authenticate_bearer_token(token) do
      {:ok, client} -> {:ok, client.id}
      {:error, reason} -> {:error, reason}
    end
  end
end
