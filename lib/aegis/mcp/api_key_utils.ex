defmodule Aegis.MCP.ApiKeyUtils do
  @moduledoc """
  Shared utilities for API key operations.

  Provides consistent API key generation and hashing across the application.
  """

  # 32 bytes = 256 bits for cryptographically strong API keys
  # This provides sufficient entropy to prevent brute force attacks
  @api_key_byte_length 32

  @doc """
  Generate a secure API key that never looks like a JWT.

  JWTs have exactly 3 parts separated by dots, so we ensure our keys don't match that pattern.

  Uses #{@api_key_byte_length} bytes (256 bits) of cryptographically secure random data
  for strong security against brute force attacks.
  """
  @spec generate_api_key() :: String.t()
  def generate_api_key do
    key =
      @api_key_byte_length
      |> :crypto.strong_rand_bytes()
      |> Base.url_encode64(padding: false)
      |> String.replace("+", "_")
      |> String.replace("/", "-")
      # Remove any dots to prevent JWT confusion
      |> String.replace(".", "_")

    # Prefix with "ak_" to make it clearly an API key and ensure it's not JWT format
    "ak_" <> key
  end

  @doc """
  Hash an API key for storage using Argon2.

  Uses Argon2id (default variant) which provides strong protection against
  both GPU-based attacks and side-channel attacks. This is significantly
  more secure than HMAC for password-like data.

  Configuration:
  - time_cost: 3 (iterations)
  - memory_cost: 65_536 (64 MiB)
  - parallelism: 4 (threads)
  """
  @spec hash_api_key(String.t()) :: String.t()
  def hash_api_key(api_key) do
    # Use conservative Argon2 parameters optimized for API keys
    # These provide strong security while being reasonably fast
    Argon2.hash_pwd_salt(api_key,
      time_cost: 3,
      memory_cost: 65_536,
      parallelism: 4,
      hash_len: 32,
      salt_len: 16
    )
  end

  @doc """
  Generate a fast lookup hash for API key indexing.

  Uses SHA-256 without salt for fast, deterministic lookup.
  This is used only for database indexing, not security.
  """
  @spec lookup_hash(String.t()) :: String.t()
  def lookup_hash(api_key) do
    :crypto.hash(:sha256, api_key)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Verify an API key against a stored Argon2 hash.

  Uses constant-time comparison to prevent timing attacks.
  """
  @spec verify_api_key(String.t(), String.t()) :: boolean()
  def verify_api_key(api_key, hash) do
    Argon2.verify_pass(api_key, hash)
  end

  @doc """
  Generate a fake hash verification to prevent timing attacks when API key doesn't exist.

  This should be called when no API key is found to make the timing
  consistent with actual verification attempts.
  """
  @spec no_api_key_verify() :: false
  def no_api_key_verify do
    Argon2.no_user_verify(
      time_cost: 3,
      memory_cost: 65_536,
      parallelism: 4,
      hash_len: 32,
      salt_len: 16
    )
  end
end
