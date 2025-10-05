defmodule Aegis.MCP.OAuth.WWWAuthenticate do
  @moduledoc """
  Implementation of WWW-Authenticate header for MCP OAuth 2.1 compliance.

  Provides proper WWW-Authenticate headers according to RFC 9728 Section 5.1
  to help MCP clients discover the Protected Resource Metadata endpoint.
  """

  alias Aegis.MCP.OAuth.ProtectedResourceMetadata

  @doc """
  Generate a WWW-Authenticate header for 401 responses.

  According to RFC 9728 and RFC 6750, the WWW-Authenticate header should include:
  - The authentication scheme (Bearer)
  - Optional realm parameter
  - resource_metadata parameter pointing to the metadata endpoint
  - Optional scope parameter indicating required scopes

  Options:
  - scope: String or list of scopes required for the resource
  """
  @spec generate_header(Plug.Conn.t(), keyword()) :: String.t()
  def generate_header(conn, opts \\ []) do
    resource_metadata_url = build_resource_metadata_url(conn)
    realm = get_realm()
    scope = Keyword.get(opts, :scope)

    params = [
      {"realm", realm},
      {"resource_metadata", resource_metadata_url}
    ]

    # Add scope parameter if provided (per RFC 6750 Section 3)
    params = maybe_add_scope_param(params, scope)

    "Bearer " <> build_params_string(params)
  end

  @doc """
  Generate a WWW-Authenticate header with an error parameter.

  Used when there's a specific OAuth error to communicate to the client.

  Options:
  - scope: Optional scope parameter for error responses
  """
  @spec generate_error_header(Plug.Conn.t(), String.t(), String.t() | nil, keyword()) ::
          String.t()
  def generate_error_header(conn, error_code, error_description \\ nil, opts \\ []) do
    resource_metadata_url = build_resource_metadata_url(conn)
    realm = get_realm()
    scope = Keyword.get(opts, :scope)

    params = [
      {"realm", realm},
      {"resource_metadata", resource_metadata_url},
      {"error", error_code}
    ]

    params =
      if error_description do
        params ++ [{"error_description", error_description}]
      else
        params
      end

    # Add scope parameter if provided
    params = maybe_add_scope_param(params, scope)

    "Bearer " <> build_params_string(params)
  end

  @doc """
  Generate WWW-Authenticate header for insufficient scope errors.

  Per RFC 6750 Section 3.1 and MCP OAuth spec, returns HTTP 403 with
  WWW-Authenticate header indicating the scopes needed for the operation.

  The required_scope parameter should include:
  - All currently granted scopes (to prevent losing permissions)
  - Newly required scopes for the operation
  - Optionally related scopes that commonly work together
  """
  @spec generate_insufficient_scope_header(Plug.Conn.t(), String.t(), String.t() | nil) ::
          String.t()
  def generate_insufficient_scope_header(conn, required_scope, error_description \\ nil) do
    resource_metadata_url = build_resource_metadata_url(conn)
    realm = get_realm()

    params = [
      {"realm", realm},
      {"resource_metadata", resource_metadata_url},
      {"error", "insufficient_scope"},
      {"scope", normalize_scope_string(required_scope)}
    ]

    params =
      if error_description do
        params ++ [{"error_description", error_description}]
      else
        params
      end

    "Bearer " <> build_params_string(params)
  end

  # Private helper functions

  defp build_resource_metadata_url(conn) do
    canonical_uri = ProtectedResourceMetadata.get_canonical_resource_uri(conn)
    base_url = get_base_url(canonical_uri)
    mcp_path = get_mcp_path_from_uri(canonical_uri)

    # Build the well-known URI for metadata discovery
    well_known_paths = ProtectedResourceMetadata.get_well_known_paths(mcp_path)
    # Use the first (most specific) path
    metadata_path = List.first(well_known_paths)

    "#{base_url}#{metadata_path}"
  end

  defp get_base_url(canonical_uri) do
    uri = URI.parse(canonical_uri)
    port_string = if uri.port && uri.port not in [80, 443], do: ":#{uri.port}", else: ""
    "#{uri.scheme}://#{uri.host}#{port_string}"
  end

  defp get_mcp_path_from_uri(canonical_uri) do
    uri = URI.parse(canonical_uri)
    uri.path || ""
  end

  defp get_realm do
    # Get realm from configuration or use a default
    config = Application.get_env(:aegis, __MODULE__, [])
    Keyword.get(config, :realm, "Aegis MCP Server")
  end

  defp build_params_string(params) do
    Enum.map_join(params, ", ", fn {key, value} -> ~s(#{key}="#{escape_quote(value)}") end)
  end

  defp escape_quote(value) do
    String.replace(value, "\"", "\\\"")
  end

  # Add scope parameter to params list if scope is provided
  defp maybe_add_scope_param(params, nil), do: params

  defp maybe_add_scope_param(params, scope) when is_binary(scope) do
    params ++ [{"scope", normalize_scope_string(scope)}]
  end

  defp maybe_add_scope_param(params, scopes) when is_list(scopes) do
    scope_string = Enum.join(scopes, " ")
    params ++ [{"scope", scope_string}]
  end

  # Normalize scope string (ensure space-separated, no duplicates)
  defp normalize_scope_string(scope) when is_binary(scope) do
    scope
    |> String.split(~r/[\s,]+/, trim: true)
    |> Enum.uniq()
    |> Enum.join(" ")
  end

  defp normalize_scope_string(scopes) when is_list(scopes) do
    scopes
    |> Enum.uniq()
    |> Enum.join(" ")
  end
end
