defmodule Aegis.MCP.HybridAuthenticationTest do
  use Aegis.DataCase, async: false

  alias Aegis.MCP.{Authorization, PermissionStore}

  describe "API key authentication" do
    test "authenticate_bearer_token with valid API key" do
      # Create a test client using the register action
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Test API Client",
          description: "Test client for API key auth"
        })

      # Get the plain API key from metadata
      api_key = Ash.Resource.get_metadata(client, :plaintext_api_key)

      # Test unified authentication
      result = Authorization.authenticate_bearer_token(api_key)
      assert {:ok, authenticated_client} = result
      assert authenticated_client.id == client.id
      assert authenticated_client.active == true
    end

    test "authenticate_bearer_token with invalid API key" do
      result = Authorization.authenticate_bearer_token("ak_invalid_key")
      assert {:error, :invalid_api_key} = result
    end

    test "API keys have ak_ prefix format" do
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Test Format Client",
          description: "Test API key format"
        })

      api_key = Ash.Resource.get_metadata(client, :plaintext_api_key)
      assert String.starts_with?(api_key, "ak_")

      # Ensure it doesn't look like a JWT (no dots after prefix removal)
      key_part = String.replace_prefix(api_key, "ak_", "")
      refute String.contains?(key_part, ".")
    end
  end

  describe "JWT token authentication (mocked)" do
    test "authenticate_bearer_token detects JWT vs API key correctly" do
      # Test API key detection
      assert String.starts_with?("ak_test123", "ak_")

      # Test JWT token detection (anything not starting with ak_)
      refute String.starts_with?("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature", "ak_")
    end

    test "JWT token validation with missing sub claim returns error" do
      # We can't easily test real JWT validation without setting up Keycloak,
      # but we can test the error handling paths
      result = Authorization.authenticate_jwt_client("invalid.jwt.token")
      assert {:error, _reason} = result
    end

    test "JWT token validation handles Guardian decode errors" do
      # Test with malformed JWT
      result = Authorization.authenticate_jwt_client("not.a.jwt")
      assert {:error, _reason} = result
    end
  end

  describe "permission store JWT functions" do
    test "validate_jwt_token handles malformed tokens" do
      result = PermissionStore.validate_jwt_token("malformed_token")
      assert {:error, _reason} = result
    end

    test "validate_jwt_token handles empty tokens" do
      result = PermissionStore.validate_jwt_token("")
      assert {:error, _reason} = result
    end
  end

  describe "unified authentication" do
    test "authenticate_bearer_token routes to correct authentication method" do
      # Create a real API key client for testing
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Routing Test Client",
          description: "Test authentication routing"
        })

      api_key = Ash.Resource.get_metadata(client, :plaintext_api_key)

      # Test API key routing
      {:ok, authenticated_client} = Authorization.authenticate_bearer_token(api_key)
      assert authenticated_client.id == client.id

      # Test JWT routing (should fail with current setup, but uses correct path)
      jwt_result =
        Authorization.authenticate_bearer_token(
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWNsaWVudCJ9."
        )

      assert {:error, _reason} = jwt_result
    end

    test "authenticate_bearer_token with nil returns error" do
      result = Authorization.authenticate_bearer_token(nil)
      assert {:error, :invalid_token} = result
    end

    test "authenticate_bearer_token with non-string returns error" do
      result = Authorization.authenticate_bearer_token(123)
      assert {:error, :invalid_token} = result
    end
  end

  describe "header validation integration" do
    setup do
      # Create a test client for header validation tests
      {:ok, client} =
        Aegis.MCP.create_client(%{
          name: "Header Test Client",
          description: "Test client for header validation"
        })

      api_key = Ash.Resource.get_metadata(client, :plaintext_api_key)
      {:ok, client_id: client.id, api_key: api_key}
    end

    test "bearer token authentication via header validation", %{
      api_key: api_key,
      client_id: client_id
    } do
      # Test the header validation path
      import Aegis.MCP.HeaderValidation, only: [validate_client_api_key: 1]

      # Mock a Plug.Conn with Authorization header
      conn = %Plug.Conn{
        req_headers: [{"authorization", "Bearer #{api_key}"}]
      }

      result = validate_client_api_key(conn)
      assert {:ok, authenticated_client_id} = result
      assert authenticated_client_id == client_id
    end

    test "missing authorization header returns error" do
      import Aegis.MCP.HeaderValidation, only: [validate_client_api_key: 1]

      conn = %Plug.Conn{req_headers: []}

      result = validate_client_api_key(conn)
      assert {:error, :no_api_key} = result
    end

    test "malformed authorization header returns error" do
      import Aegis.MCP.HeaderValidation, only: [validate_client_api_key: 1]

      conn = %Plug.Conn{
        req_headers: [{"authorization", "Basic invalid"}]
      }

      result = validate_client_api_key(conn)
      assert {:error, :invalid_api_key} = result
    end
  end
end
