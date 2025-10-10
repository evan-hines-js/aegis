defmodule Aegis.MCP.AuthorizationErrors do
  @moduledoc """
  Standardized error types and handling for RBAC authorization system.

  Provides consistent error taxonomy across all authorization operations
  and utilities for error normalization and classification.
  """

  @typedoc "Standard authorization error types"
  @type authorization_error ::
          :client_not_found
          | :client_inactive
          | :permission_denied
          | :invalid_resource_type
          | :invalid_api_key
          | :session_not_found
          | :system_error

  @typedoc "Result of authorization operations"
  @type authorization_result ::
          {:ok, :authorized}
          | {:error, authorization_error()}

  @typedoc "Result of client validation operations"
  @type client_result ::
          {:ok, %Aegis.MCP.Client{}}
          | {:error, authorization_error()}

  @typedoc "Result of JWT client validation (returns virtual client map)"
  @type jwt_client_result ::
          {:ok, map()}
          | {:error, authorization_error()}

  @typedoc "Result of permission lookup operations"
  @type permissions_result ::
          {:ok, [map()]}
          | {:error, authorization_error()}

  @doc """
  Normalize various error formats to standard authorization errors.
  """
  @spec normalize_error(term()) :: authorization_error()
  def normalize_error(:not_found), do: :client_not_found
  def normalize_error(:inactive), do: :client_inactive
  def normalize_error(:client_inactive), do: :client_inactive
  def normalize_error(:client_not_found), do: :client_not_found
  def normalize_error(:permission_denied), do: :permission_denied
  def normalize_error(:unauthorized), do: :permission_denied
  def normalize_error(:invalid_request), do: :system_error
  def normalize_error(:session_not_found), do: :session_not_found
  def normalize_error(:invalid_api_key), do: :invalid_api_key
  def normalize_error(:invalid_resource_type), do: :invalid_resource_type
  def normalize_error(_), do: :system_error

  @doc """
  Check if an error is client-related (not permission-related).
  """
  @spec client_error?(authorization_error()) :: boolean()
  def client_error?(error)
      when error in [:client_not_found, :client_inactive, :invalid_api_key, :session_not_found],
      do: true

  def client_error?(_), do: false

  @doc """
  Check if an error is permission-related.
  """
  @spec permission_error?(authorization_error()) :: boolean()
  def permission_error?(error) when error in [:permission_denied, :invalid_resource_type],
    do: true

  def permission_error?(_), do: false

  @doc """
  Check if an error is a system/infrastructure error.
  """
  @spec system_error?(authorization_error()) :: boolean()
  def system_error?(:system_error), do: true
  def system_error?(_), do: false

  @doc """
  Get human-readable error message for an authorization error.
  """
  @spec error_message(authorization_error()) :: String.t()
  def error_message(:client_not_found), do: "Client not found"
  def error_message(:client_inactive), do: "Client account is inactive"
  def error_message(:permission_denied), do: "Insufficient permissions"
  def error_message(:invalid_resource_type), do: "Invalid resource type"
  def error_message(:invalid_api_key), do: "Invalid API key"
  def error_message(:session_not_found), do: "Session not found or expired"
  def error_message(:system_error), do: "Internal system error"

  @doc """
  Convert authorization error to appropriate HTTP status code.
  """
  @spec http_status(authorization_error()) :: non_neg_integer()
  def http_status(error) when error in [:client_not_found, :session_not_found], do: 404

  def http_status(error) when error in [:client_inactive, :permission_denied, :invalid_api_key],
    do: 403

  def http_status(:invalid_resource_type), do: 400
  def http_status(:system_error), do: 500

  @doc """
  Build standardized error result.
  """
  @spec build_error(authorization_error()) :: {:error, authorization_error()}
  def build_error(error) when is_atom(error), do: {:error, error}

  @doc """
  Build standardized success result.
  """
  @spec build_success(term()) :: {:ok, term()}
  def build_success(result), do: {:ok, result}
end
