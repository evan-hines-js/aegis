defmodule Aegis.MCP.ApiKeyUtilsTest do
  use ExUnit.Case, async: true

  alias Aegis.MCP.ApiKeyUtils

  describe "generate_api_key/0" do
    test "generates a valid API key with ak_ prefix" do
      api_key = ApiKeyUtils.generate_api_key()

      assert String.starts_with?(api_key, "ak_")
      assert String.length(api_key) > 10
      # Should not contain dots (JWT prevention)
      refute String.contains?(api_key, ".")
    end

    test "generates unique API keys" do
      key1 = ApiKeyUtils.generate_api_key()
      key2 = ApiKeyUtils.generate_api_key()

      assert key1 != key2
    end
  end

  describe "hash_api_key/1 and verify_api_key/2" do
    test "can hash and verify an API key" do
      api_key = "ak_test_key_123"
      hash = ApiKeyUtils.hash_api_key(api_key)

      # Argon2 hash should be a string starting with $argon2
      assert is_binary(hash)
      assert String.starts_with?(hash, "$argon2")

      # Should be able to verify the correct key
      assert ApiKeyUtils.verify_api_key(api_key, hash) == true
    end

    test "verification fails for wrong API key" do
      api_key = "ak_correct_key"
      wrong_key = "ak_wrong_key"
      hash = ApiKeyUtils.hash_api_key(api_key)

      refute ApiKeyUtils.verify_api_key(wrong_key, hash)
    end

    test "generates different hashes for same API key (due to unique salts)" do
      api_key = "ak_same_key"
      hash1 = ApiKeyUtils.hash_api_key(api_key)
      hash2 = ApiKeyUtils.hash_api_key(api_key)

      # Hashes should be different due to unique salts
      assert hash1 != hash2

      # But both should verify correctly
      assert ApiKeyUtils.verify_api_key(api_key, hash1)
      assert ApiKeyUtils.verify_api_key(api_key, hash2)
    end
  end

  describe "no_api_key_verify/0" do
    test "always returns false and takes some time" do
      start_time = System.monotonic_time()
      result = ApiKeyUtils.no_api_key_verify()
      end_time = System.monotonic_time()

      # Should always return false
      assert result == false

      # Should take some measurable time (timing attack protection)
      elapsed_ms = System.convert_time_unit(end_time - start_time, :native, :millisecond)
      assert elapsed_ms > 0
    end
  end

  describe "integration with generated keys" do
    test "can generate, hash, and verify a key end-to-end" do
      # Generate a real API key
      api_key = ApiKeyUtils.generate_api_key()

      # Hash it
      hash = ApiKeyUtils.hash_api_key(api_key)

      # Verify it works
      assert ApiKeyUtils.verify_api_key(api_key, hash)

      # Verify wrong key doesn't work
      wrong_key = ApiKeyUtils.generate_api_key()
      refute ApiKeyUtils.verify_api_key(wrong_key, hash)
    end
  end
end
