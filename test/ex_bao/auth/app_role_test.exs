defmodule ExBao.Auth.AppRoleTest do
  @moduledoc """
  AppRole against a real server.

  The timing behaviour is pinned in the unit suite, where a lease can be one
  second long. What needs a real server is the other half: that a login
  actually works, and that the whole chain holds — provision a role, log in
  with it, and use the token it gives back to do real work.
  """

  use ExBao.BaoCase, async: false

  alias ExBao.{Auth, Client, Error, TokenServer, Transit}
  alias ExBao.Auth.AppRole

  setup %{client: client} do
    role = unique_key("role")

    # A role that can do exactly what the test needs and nothing else.
    {:ok, _} =
      Client.request(client, :post, "sys/policies/acl/#{role}", %{
        "policy" => """
        path "transit/*" { capabilities = ["create", "read", "update", "list"] }
        path "auth/token/renew-self" { capabilities = ["update"] }
        """
      })

    {:ok, _} =
      Client.request(client, :post, "auth/approle/role/#{role}", %{
        "token_policies" => role,
        "token_ttl" => "60s",
        "token_max_ttl" => "120s"
      })

    {:ok, role_id} = AppRole.read_role_id(client, role)
    {:ok, %{"secret_id" => secret_id}} = AppRole.generate_secret_id(client, role)

    on_exit(fn ->
      Client.request(client, :delete, "auth/approle/role/#{role}")
      Client.request(client, :delete, "sys/policies/acl/#{role}")
    end)

    {:ok, role: role, role_id: role_id, secret_id: secret_id}
  end

  describe "login/2" do
    test "exchanges the two ids for a token", ctx do
      assert {:ok, %Auth{} = auth} =
               AppRole.login(ctx.client,
                 role_id: ctx.role_id,
                 secret_id: ctx.secret_id
               )

      assert is_binary(auth.token)
      assert auth.lease_duration > 0
      assert auth.renewable
      assert ctx.role in auth.policies
    end

    test "the token it returns actually works", ctx do
      {:ok, auth} =
        AppRole.login(ctx.client, role_id: ctx.role_id, secret_id: ctx.secret_id)

      as_role = Client.with_token(ctx.client, auth.token)
      key = unique_key("approle")

      assert {:ok, sealed} = Transit.encrypt(as_role, key, "00912345620")
      assert {:ok, "00912345620"} = Transit.decrypt(as_role, key, sealed)
    end

    # The policy above grants nothing outside transit, so this is the check
    # that the token is really scoped and not quietly a root one.
    test "and only works for what the role is allowed to do", ctx do
      {:ok, auth} =
        AppRole.login(ctx.client, role_id: ctx.role_id, secret_id: ctx.secret_id)

      as_role = Client.with_token(ctx.client, auth.token)

      assert {:error, %Error{kind: :permission_denied}} =
               Client.request(as_role, :get, "sys/policies/acl")
    end

    test "a wrong secret id is refused", ctx do
      assert {:error, %Error{}} =
               AppRole.login(ctx.client,
                 role_id: ctx.role_id,
                 secret_id: "00000000-0000-0000-0000-000000000000"
               )
    end

    # Not a request worth making: sending nil would get a 400 back describing
    # the server's opinion of an empty field instead of the fact that nobody
    # configured it.
    test "a missing credential says so without asking the server", ctx do
      assert {:error, %Error{kind: :invalid_credentials, messages: [message]}} =
               AppRole.login(ctx.client, role_id: ctx.role_id)

      assert message =~ "secret_id"
    end
  end

  describe "the whole chain" do
    test "a supervised token server logs in and does real work", ctx do
      pid =
        start_supervised!(
          {TokenServer,
           name: nil,
           client: ctx.client,
           auth: {:approle, role_id: ctx.role_id, secret_id: ctx.secret_id}}
        )

      assert %{authenticated: true, renewable: true} = TokenServer.status(pid)

      key = unique_key("chain")
      assert {:ok, sealed} = Transit.encrypt(pid, key, "3001234417")
      assert {:ok, "3001234417"} = Transit.decrypt(pid, key, sealed)
    end

    test "and picks up a new secret id without restarting", ctx do
      pid =
        start_supervised!(
          {TokenServer,
           name: nil,
           client: ctx.client,
           auth: {:approle, role_id: ctx.role_id, secret_id: ctx.secret_id}}
        )

      {:ok, %Client{token: first}} = TokenServer.client(pid)
      assert :ok = TokenServer.reauthenticate(pid)
      {:ok, %Client{token: second}} = TokenServer.client(pid)

      refute first == second
    end
  end
end
