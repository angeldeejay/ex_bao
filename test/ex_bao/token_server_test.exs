defmodule ExBao.TokenServerTest do
  @moduledoc """
  The token lifecycle, against a stubbed server.

  The timings here are deliberately loose. These tests assert an *order* of
  events, not a schedule: that a renewal happens before the lease ends, that
  a refusal turns into a login. Tight deadlines would make them fail under
  load — which is exactly when CI runs them — for a reason that has nothing
  to do with the behaviour being checked.

  These are unit tests on purpose: the behaviours worth pinning here are
  *timing* ones — renewing early, backing off, giving up on a token that was
  revoked — and driving them against a real server would mean waiting out
  real leases. The stub lets a lease be one second long.

  What a real server is for is the other half: that a login actually works.
  That lives in the AppRole integration suite.
  """

  use ExUnit.Case, async: false

  alias ExBao.{Client, TokenServer}

  setup do
    # Shared mode, because the process under test is not this one and it
    # makes its first request before a test could hand it permission.
    Req.Test.set_req_test_to_shared()
    Req.Test.set_req_test_from_context(%{async: false})
    :ok
  end

  defp client(stub), do: Client.new(addr: "http://bao.test", plug: {Req.Test, stub})

  defp auth_body(opts) do
    %{
      "auth" => %{
        "client_token" => opts[:token] || "s.first",
        "lease_duration" => opts[:lease] || 3600,
        "renewable" => Keyword.get(opts, :renewable, true),
        "token_policies" => ["default"]
      }
    }
  end

  describe "starting up" do
    test "authenticates on start and hands out a client carrying the token" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      Req.Test.stub(stub, fn conn -> Req.Test.json(conn, auth_body(token: "s.abc")) end)

      pid =
        start_supervised!(
          {TokenServer,
           name: nil, client: client(stub), auth: {:approle, role_id: "r", secret_id: "s"}}
        )

      assert {:ok, %Client{token: "s.abc"}} = TokenServer.client(pid)
    end

    # An application that refuses to boot because OpenBao is down turns a
    # brief outage of a dependency into an outage of its own, and a restart
    # loop at the top of a supervision tree can take the node with it.
    test "starts even when the server is unreachable" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      Req.Test.stub(stub, fn conn -> Req.Test.transport_error(conn, :econnrefused) end)

      pid =
        start_supervised!(
          {TokenServer,
           name: nil, client: client(stub), auth: {:approle, role_id: "r", secret_id: "s"}}
        )

      assert Process.alive?(pid)
      assert {:error, %ExBao.Error{}} = TokenServer.client(pid)
    end

    test "a fixed token needs no login at all" do
      pid =
        start_supervised!(
          {TokenServer, name: nil, client: client(:unused), auth: {:token, "s.fixed"}}
        )

      assert {:ok, %Client{token: "s.fixed"}} = TokenServer.client(pid)
      assert %{authenticated: true, renewable: false} = TokenServer.status(pid)
    end
  end

  describe "renewing" do
    # The point of renewing at a fraction of the lease rather than on expiry:
    # there is room for an attempt to fail and be retried while the current
    # token is still good. With a 1s lease and 0.5, that is ~500ms.
    test "renews before the lease runs out, not when it ends" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      test_pid = self()

      Req.Test.stub(stub, fn conn ->
        send(test_pid, {:hit, conn.request_path})
        Req.Test.json(conn, auth_body(token: "s.renewed", lease: 2))
      end)

      start_supervised!(
        {TokenServer,
         name: nil,
         client: client(stub),
         auth: {:approle, role_id: "r", secret_id: "s"},
         renew_after: 0.5}
      )

      assert_receive {:hit, "/v1/auth/approle/login"}, 5_000
      assert_receive {:hit, "/v1/auth/token/renew-self"}, 5_000
    end

    # A token can be revoked. A loop that only knows how to renew keeps
    # asking about a token that is never coming back; the way out of a
    # refused renewal is a new token, not another renewal.
    test "a refused renewal becomes a fresh login" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      test_pid = self()

      Req.Test.stub(stub, fn conn ->
        send(test_pid, {:hit, conn.request_path})

        case conn.request_path do
          "/v1/auth/token/renew-self" ->
            conn
            |> Plug.Conn.put_status(403)
            |> Req.Test.json(%{"errors" => ["permission denied"]})

          _ ->
            Req.Test.json(conn, auth_body(token: "s.fresh", lease: 2))
        end
      end)

      start_supervised!(
        {TokenServer,
         name: nil,
         client: client(stub),
         auth: {:approle, role_id: "r", secret_id: "s"},
         renew_after: 0.5}
      )

      assert_receive {:hit, "/v1/auth/approle/login"}, 5_000
      assert_receive {:hit, "/v1/auth/token/renew-self"}, 5_000
      # The second login is the recovery: it only happens if the refusal was
      # read as "this token is finished" rather than "try again".
      assert_receive {:hit, "/v1/auth/approle/login"}, 5_000
    end

    # Asking to renew something the server already said is not renewable is
    # asking for a refusal. The only move is to replace it.
    test "a token that is not renewable is replaced, never renewed" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      test_pid = self()

      Req.Test.stub(stub, fn conn ->
        send(test_pid, {:hit, conn.request_path})
        Req.Test.json(conn, auth_body(lease: 2, renewable: false))
      end)

      start_supervised!(
        {TokenServer,
         name: nil,
         client: client(stub),
         auth: {:approle, role_id: "r", secret_id: "s"},
         renew_after: 0.5}
      )

      assert_receive {:hit, "/v1/auth/approle/login"}, 5_000
      assert_receive {:hit, "/v1/auth/approle/login"}, 5_000
      refute_received {:hit, "/v1/auth/token/renew-self"}
    end
  end

  describe "reauthenticate/1" do
    test "throws away the current token and gets another" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      counter = :counters.new(1, [])

      Req.Test.stub(stub, fn conn ->
        :counters.add(counter, 1, 1)
        Req.Test.json(conn, auth_body(token: "s.n#{:counters.get(counter, 1)}"))
      end)

      pid =
        start_supervised!(
          {TokenServer,
           name: nil, client: client(stub), auth: {:approle, role_id: "r", secret_id: "s"}}
        )

      assert {:ok, %Client{token: "s.n1"}} = TokenServer.client(pid)
      assert :ok = TokenServer.reauthenticate(pid)
      assert {:ok, %Client{token: "s.n2"}} = TokenServer.client(pid)
    end
  end

  describe "status/1" do
    # A status endpoint that returns the credential puts the credential in
    # every log line that records a health check.
    test "never includes the token" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      Req.Test.stub(stub, fn conn -> Req.Test.json(conn, auth_body(token: "s.secret")) end)

      pid =
        start_supervised!(
          {TokenServer,
           name: nil, client: client(stub), auth: {:approle, role_id: "r", secret_id: "s"}}
        )

      status = TokenServer.status(pid)

      refute status |> inspect() |> String.contains?("s.secret")
      assert %{authenticated: true, renewable: true} = status
    end

    test "reports how long is left" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      Req.Test.stub(stub, fn conn -> Req.Test.json(conn, auth_body(lease: 3600)) end)

      pid =
        start_supervised!(
          {TokenServer,
           name: nil, client: client(stub), auth: {:approle, role_id: "r", secret_id: "s"}}
        )

      assert %{expires_in: seconds} = TokenServer.status(pid)
      assert seconds > 3500
    end
  end
end
