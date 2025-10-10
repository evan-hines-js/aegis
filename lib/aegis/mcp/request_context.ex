defmodule Aegis.MCP.Auth.RequestContext do
  @moduledoc """
  Helper module for accessing authentication context from Plug.Conn.

  Provides utilities to extract client information that was set
  by the API key authentication plug.
  """

  @doc """
  Get the authenticated client from the connection.

  Returns the client struct that was set by the authentication plug.
  """
  @spec get_client(Plug.Conn.t()) :: map() | nil
  def get_client(conn) do
    Map.get(conn.assigns, :current_client)
  end

  @doc """
  Get the client ID from the connection.
  """
  @spec get_client_id(Plug.Conn.t()) :: String.t() | nil
  def get_client_id(conn) do
    case get_client(conn) do
      %{id: client_id} -> client_id
      _ -> nil
    end
  end

  @doc """
  Get the authentication method used.

  Returns :api_key or nil.
  """
  @spec get_auth_method(Plug.Conn.t()) :: :api_key | nil
  def get_auth_method(conn) do
    Map.get(conn.assigns, :auth_method)
  end

  @doc """
  Build authorization options for passing to Authorization module.

  Returns empty keyword list (reserved for future use).
  """
  @spec build_auth_opts(Plug.Conn.t()) :: keyword()
  def build_auth_opts(_conn) do
    []
  end
end
