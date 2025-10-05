defmodule Aegis.MCP.OAuthTest do
  use ExUnit.Case, async: true
  import Plug.Test

  alias Aegis.MCP.OAuth.{ProtectedResourceMetadata, ResourceValidation, WWWAuthenticate}

  describe "ProtectedResourceMetadata" do
    test "generates valid metadata document" do
      resource_uri = "https://mcp.example.com/mcp"
      metadata = ProtectedResourceMetadata.generate_metadata(resource_uri)

      assert metadata["resource"] == resource_uri
      assert is_list(metadata["authorization_servers"])
      assert metadata["bearer_methods_supported"] == ["header"]
    end

    test "builds canonical URI correctly" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      canonical_uri = ProtectedResourceMetadata.get_canonical_resource_uri(conn)
      assert canonical_uri == "https://mcp.example.com/mcp"
    end

    test "validates resource parameter correctly" do
      canonical_uri = "https://mcp.example.com/mcp"

      # Exact match should work
      assert ProtectedResourceMetadata.validate_resource_parameter(canonical_uri, canonical_uri)

      # Parent URI should work
      assert ProtectedResourceMetadata.validate_resource_parameter(
               "https://mcp.example.com",
               canonical_uri
             )

      # Different URI should not work
      refute ProtectedResourceMetadata.validate_resource_parameter(
               "https://other.example.com/mcp",
               canonical_uri
             )
    end

    test "generates correct well-known paths" do
      # Root MCP endpoint
      paths = ProtectedResourceMetadata.get_well_known_paths("/")
      assert paths == ["/.well-known/oauth-protected-resource"]

      # Path-specific MCP endpoint
      paths = ProtectedResourceMetadata.get_well_known_paths("/mcp")

      assert paths == [
               "/.well-known/oauth-protected-resource/mcp",
               "/.well-known/oauth-protected-resource"
             ]
    end
  end

  describe "WWWAuthenticate" do
    test "generates proper header" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      header = WWWAuthenticate.generate_header(conn)

      assert String.starts_with?(header, "Bearer ")
      assert String.contains?(header, "realm=")
      assert String.contains?(header, "resource_metadata=")
    end

    test "generates error header with error code" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      header = WWWAuthenticate.generate_error_header(conn, "invalid_token", "Token expired")

      assert String.contains?(header, "error=\"invalid_token\"")
      assert String.contains?(header, "error_description=\"Token expired\"")
    end

    test "generates insufficient scope header" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      header = WWWAuthenticate.generate_insufficient_scope_header(conn, "mcp:read")

      assert String.contains?(header, "error=\"insufficient_scope\"")
      assert String.contains?(header, "scope=\"mcp:read\"")
    end
  end

  describe "ResourceValidation" do
    test "validates token audience correctly" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      # Valid audience
      valid_claims = %{"aud" => "https://mcp.example.com/mcp"}
      assert ResourceValidation.validate_token_audience(valid_claims, conn) == :ok

      # Valid audience as array
      valid_claims_array = %{"aud" => ["https://mcp.example.com/mcp", "other-service"]}
      assert ResourceValidation.validate_token_audience(valid_claims_array, conn) == :ok

      # Invalid audience
      invalid_claims = %{"aud" => "https://other.example.com/mcp"}

      assert ResourceValidation.validate_token_audience(invalid_claims, conn) ==
               {:error, :invalid_audience}
    end

    test "validates resource parameter" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      # Valid resource parameter
      assert ResourceValidation.validate_resource_parameter("https://mcp.example.com/mcp", conn) ==
               :ok

      # Invalid resource parameter
      assert ResourceValidation.validate_resource_parameter("https://other.example.com/mcp", conn) ==
               {:error, :invalid_resource}

      # Missing resource parameter
      assert ResourceValidation.validate_resource_parameter(nil, conn) ==
               {:error, :missing_resource}
    end

    test "extracts and validates resource from params" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      # Valid params
      valid_params = %{"resource" => "https://mcp.example.com/mcp"}
      assert ResourceValidation.extract_and_validate_resource(valid_params, conn) == :ok

      # Missing resource
      invalid_params = %{"other" => "value"}

      assert ResourceValidation.extract_and_validate_resource(invalid_params, conn) ==
               {:error, :missing_resource}
    end

    test "gets expected resource URI" do
      conn =
        conn(:get, "/mcp")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "mcp.example.com")
        |> Map.put(:port, 443)

      expected = ResourceValidation.get_expected_resource(conn)
      assert expected == "https://mcp.example.com/mcp"
    end
  end
end
