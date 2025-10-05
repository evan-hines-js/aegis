defmodule Aegis.MCP.OAuth.Provider do
  @moduledoc """
  OAuth provider detection and endpoint URL building.

  Handles different OAuth provider formats (Keycloak, Okta, Auth0, generic OIDC)
  and constructs appropriate endpoint URLs for authorization, token, userinfo, etc.
  """

  @type provider_type :: :keycloak | :okta | :auth0 | :generic
  @type endpoint_type :: :authorize | :token | :userinfo | :jwks | :registration

  @doc """
  Detect the OAuth provider type from an issuer URL.

  ## Examples

      iex> detect_provider("https://keycloak.example.com/realms/myrealm")
      :keycloak

      iex> detect_provider("https://your-domain.okta.com/oauth2/default")
      :okta

      iex> detect_provider("https://your-domain.auth0.com")
      :auth0
  """
  @spec detect_provider(String.t()) :: provider_type()
  def detect_provider(issuer_url) when is_binary(issuer_url) do
    cond do
      String.contains?(issuer_url, "/realms/") -> :keycloak
      String.contains?(issuer_url, "okta.com") -> :okta
      String.contains?(issuer_url, "auth0.com") -> :auth0
      true -> :generic
    end
  end

  @doc """
  Build an endpoint URL for a specific OAuth provider and endpoint type.

  ## Examples

      iex> build_endpoint("https://keycloak.example.com/realms/myrealm", :authorize)
      "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth"

      iex> build_endpoint("https://your-domain.okta.com/oauth2/default", :token)
      "https://your-domain.okta.com/oauth2/default/v1/token"
  """
  @spec build_endpoint(String.t(), endpoint_type()) :: String.t()
  def build_endpoint(issuer_url, endpoint_type) when is_binary(issuer_url) do
    provider = detect_provider(issuer_url)
    endpoint_path = get_endpoint_path(provider, endpoint_type)
    "#{issuer_url}#{endpoint_path}"
  end

  @doc """
  Get the endpoint path for a specific provider and endpoint type.
  """
  @spec get_endpoint_path(provider_type(), endpoint_type()) :: String.t()
  def get_endpoint_path(:keycloak, :authorize), do: "/protocol/openid-connect/auth"
  def get_endpoint_path(:keycloak, :token), do: "/protocol/openid-connect/token"
  def get_endpoint_path(:keycloak, :userinfo), do: "/protocol/openid-connect/userinfo"
  def get_endpoint_path(:keycloak, :jwks), do: "/protocol/openid-connect/certs"
  def get_endpoint_path(:keycloak, :registration), do: "/clients-registrations/openid-connect"

  def get_endpoint_path(:okta, :authorize), do: "/v1/authorize"
  def get_endpoint_path(:okta, :token), do: "/v1/token"
  def get_endpoint_path(:okta, :userinfo), do: "/v1/userinfo"
  def get_endpoint_path(:okta, :jwks), do: "/v1/keys"
  def get_endpoint_path(:okta, :registration), do: "/v1/clients"

  def get_endpoint_path(:auth0, :authorize), do: "/authorize"
  def get_endpoint_path(:auth0, :token), do: "/oauth/token"
  def get_endpoint_path(:auth0, :userinfo), do: "/userinfo"
  def get_endpoint_path(:auth0, :jwks), do: "/.well-known/jwks.json"
  def get_endpoint_path(:auth0, :registration), do: "/oidc/register"

  # Generic OIDC provider - follow standard paths
  def get_endpoint_path(:generic, :authorize), do: "/authorize"
  def get_endpoint_path(:generic, :token), do: "/token"
  def get_endpoint_path(:generic, :userinfo), do: "/userinfo"
  def get_endpoint_path(:generic, :jwks), do: "/.well-known/jwks.json"
  def get_endpoint_path(:generic, :registration), do: "/register"

  @doc """
  Build all common OAuth endpoints for a provider.

  Returns a map with all endpoint URLs.

  ## Examples

      iex> build_all_endpoints("https://keycloak.example.com/realms/myrealm")
      %{
        authorize: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth",
        token: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token",
        userinfo: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/userinfo",
        jwks: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs",
        registration: "https://keycloak.example.com/realms/myrealm/clients-registrations/openid-connect"
      }
  """
  @spec build_all_endpoints(String.t()) :: %{
          authorize: String.t(),
          token: String.t(),
          userinfo: String.t(),
          jwks: String.t(),
          registration: String.t()
        }
  def build_all_endpoints(issuer_url) when is_binary(issuer_url) do
    %{
      authorize: build_endpoint(issuer_url, :authorize),
      token: build_endpoint(issuer_url, :token),
      userinfo: build_endpoint(issuer_url, :userinfo),
      jwks: build_endpoint(issuer_url, :jwks),
      registration: build_endpoint(issuer_url, :registration)
    }
  end

  @doc """
  Validate that an issuer URL is in a supported format.

  Returns {:ok, issuer_url} if valid, {:error, reason} otherwise.
  """
  @spec validate_issuer_url(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def validate_issuer_url(issuer_url) when is_binary(issuer_url) do
    uri = URI.parse(issuer_url)

    cond do
      uri.scheme not in ["http", "https"] ->
        {:error, :invalid_scheme}

      is_nil(uri.host) or uri.host == "" ->
        {:error, :missing_host}

      true ->
        {:ok, issuer_url}
    end
  end

  def validate_issuer_url(_), do: {:error, :invalid_url}
end
