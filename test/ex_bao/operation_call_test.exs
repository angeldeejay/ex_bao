defmodule ExBao.OperationCallTest do
  @moduledoc """
  What a generated function sends, checked on generated functions — so the
  generator's output is exercised, not a copy of it.
  """

  use ExUnit.Case, async: true

  alias ExBao.Auth.Userpass
  alias ExBao.{Client, KV, PKI, Transit}

  setup do
    stub = :"stub_#{System.unique_integer([:positive])}"
    test_pid = self()

    Req.Test.stub(stub, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      send(test_pid, %{
        method: conn.method,
        path: conn.request_path,
        query: conn.query_string,
        type: conn |> Plug.Conn.get_req_header("content-type") |> List.first(),
        body: if(body == "", do: nil, else: Jason.decode!(body))
      })

      Req.Test.json(conn, %{"data" => %{}})
    end)

    {:ok, client: Client.new(addr: "http://bao.test", plug: {Req.Test, stub}, retry: false)}
  end

  test "path arguments go in the path and options in the body", %{client: c} do
    assert {:ok, _} = Userpass.write_user(c, "ana", password: "p", token_ttl: "1h")

    assert_received %{
      method: "POST",
      path: "/v1/auth/userpass/users/ana",
      body: %{"password" => "p", "token_ttl" => "1h"}
    }
  end

  test ":mount moves the engine and is not sent; a GET's options are its query", %{client: c} do
    assert {:ok, _} = KV.V1.read_path(c, "app/db", mount: "team-kv", list: true)
    assert_received %{method: "GET", path: "/v1/team-kv/app/db", query: "list=true", body: nil}
  end

  test "a path argument that is a path keeps its slashes, and nothing else does", %{client: c} do
    assert {:ok, _} = KV.read_data_path(c, "app/a b")
    assert_received %{path: "/v1/secret/data/app/a%20b"}

    assert {:ok, _} = Userpass.read_user(c, "a/b")
    assert_received %{path: "/v1/auth/userpass/users/a%2Fb"}
  end

  test "a LIST always says list=true", %{client: c} do
    assert {:ok, _} = PKI.list_roles(c)
    assert_received %{method: "GET", path: "/v1/pki/roles", query: "list=true"}
  end

  test "a PATCH says merge-patch, which is what KV requires", %{client: c} do
    assert {:ok, _} = KV.patch_data_path(c, "app", data: %{"k" => "v"})
    assert_received %{method: "PATCH", type: "application/merge-patch+json"}
  end

  test "an option the endpoint does not take is refused before sending", %{client: c} do
    assert_raise ArgumentError, ~r/unknown option\(s\) \[:pasword\]/, fn ->
      Userpass.write_user(c, "ana", pasword: "p")
    end

    refute_received %{}
  end

  test "a required option left out is refused before sending", %{client: c} do
    assert_raise ArgumentError, ~r/missing required option\(s\) \[:certificate_chain\]/, fn ->
      Transit.set_chain(c, "k", version: 1)
    end

    refute_received %{}
  end
end
