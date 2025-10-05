defmodule Aegis.Accounts do
  @moduledoc false
  use Ash.Domain, otp_app: :aegis, extensions: [AshAdmin.Domain]

  admin do
    show? true
  end

  resources do
    resource Aegis.Accounts.Token
    resource Aegis.Accounts.User
  end
end
