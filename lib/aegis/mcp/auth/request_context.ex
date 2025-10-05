defmodule Aegis.MCP.Auth.RequestContext do
  @moduledoc """
  Helper module for accessing authentication context from Plug.Conn.

  Provides utilities to extract client information and JWT claims
  that were set by the OAuthAuthenticationPlug.
  """

  @doc """
  Get the authenticated client from the connection.

  Returns the client struct that was set by OAuthAuthenticationPlug.
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
  Get JWT claims from the connection.

  Returns nil if authentication was via API key rather than OAuth.
  """
  @spec get_jwt_claims(Plug.Conn.t()) :: map() | nil
  def get_jwt_claims(conn) do
    Map.get(conn.assigns, :jwt_claims)
  end

  @doc """
  Get the authentication method used.

  Returns :oauth, :api_key, or nil.
  """
  @spec get_auth_method(Plug.Conn.t()) :: :oauth | :api_key | nil
  def get_auth_method(conn) do
    Map.get(conn.assigns, :auth_method)
  end

  @doc """
  Check if request was authenticated via OAuth.
  """
  @spec oauth_authenticated?(Plug.Conn.t()) :: boolean()
  def oauth_authenticated?(conn) do
    get_auth_method(conn) == :oauth
  end

  @doc """
  Build authorization options for passing to Authorization module.

  Returns keyword list with :jwt_claims if OAuth authenticated.
  """
  @spec build_auth_opts(Plug.Conn.t()) :: keyword()
  def build_auth_opts(conn) do
    case get_jwt_claims(conn) do
      nil -> []
      claims -> [jwt_claims: claims]
    end
  end
end
