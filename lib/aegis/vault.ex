defmodule Aegis.Vault do
  @moduledoc """
  Encryption vault for protecting sensitive data in audit logs and other resources.

  This vault encrypts sensitive data like API keys, audit log details, and other
  confidential information stored in the database.
  """

  use Cloak.Vault, otp_app: :aegis
end
