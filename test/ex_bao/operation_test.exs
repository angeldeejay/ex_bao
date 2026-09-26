defmodule ExBao.OperationTest do
  use ExUnit.Case, async: true

  alias ExBao.{Auth.AppRole, Client, Operation}

  describe "escaping" do
    test "a segment cannot carry a slash, a query or a traversal" do
      assert Operation.escape("a/../b?c") == "a%2F..%2Fb%3Fc"
    end

    test "a path keeps its slashes and escapes each segment" do
      assert Operation.escape_path("/team/db creds/") == "team/db%20creds"
    end
  end

  describe "mount/2" do
    test "falls back to the default and ignores slashes at the ends" do
      assert Operation.mount([], "transit") == "transit"
      assert Operation.mount([mount: "/team/transit/"], "transit") == "team/transit"
    end
  end

  describe "AppRole's mount" do
    setup do
      stub = :"stub_#{System.unique_integer([:positive])}"
      test_pid = self()

      Req.Test.stub(stub, fn conn ->
        send(test_pid, {:path, conn.request_path})
        Req.Test.json(conn, %{"data" => %{"role_id" => "rid"}})
      end)

      {:ok, client: Client.new(addr: "http://bao.test", plug: {Req.Test, stub})}
    end

    # `:path` is what 0.1.0 called it, and code written against 0.1.0 keeps
    # working.
    test "still answers to :path", %{client: client} do
      assert {:ok, "rid"} = AppRole.read_role_id(client, "web", path: "old")
      assert_received {:path, "/v1/auth/old/role/web/role-id"}
    end

    test ":mount wins when both are given", %{client: client} do
      assert {:ok, "rid"} = AppRole.read_role_id(client, "web", path: "old", mount: "new")
      assert_received {:path, "/v1/auth/new/role/web/role-id"}
    end
  end
end
