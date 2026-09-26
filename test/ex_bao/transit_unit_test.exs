defmodule ExBao.TransitUnitTest do
  @moduledoc """
  The parts of Transit that are about what this client sends, not about what
  the server does with it — so a stub is enough, and a real server would only
  add a boot. Behaviour lives in the integration suite.
  """

  use ExUnit.Case, async: true

  alias ExBao.{Client, Transit}

  # No retries: a 500 would otherwise be asked again, with backoff, and the
  # test would pay for it.
  defp client(stub),
    do: Client.new(addr: "http://bao.test", plug: {Req.Test, stub}, retry: false)

  describe ":references" do
    # `Enum.zip/2` would stop at the shorter list and drop the values it did
    # not cover, which is the opposite of what a reference is for.
    test "a count that does not match the values is refused before sending" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      Req.Test.stub(stub, fn _conn -> flunk("nothing should have been sent") end)

      assert_raise ArgumentError, ~r/3 values and 2 references/, fn ->
        Transit.decrypt_batch(client(stub), "payout", ["a", "b", "c"], references: [1, 2])
      end
    end
  end

  describe "key names" do
    # A name from user input must not be able to address another endpoint.
    test "are escaped into the path" do
      stub = :"stub_#{System.unique_integer([:positive])}"
      test_pid = self()

      Req.Test.stub(stub, fn conn ->
        send(test_pid, {:path, conn.request_path})
        Req.Test.json(conn, %{"data" => %{"ciphertext" => "vault:v1:x"}})
      end)

      assert {:ok, "vault:v1:x"} = Transit.encrypt(client(stub), "a/../b", "v")
      assert_received {:path, "/v1/transit/encrypt/a%2F..%2Fb"}
    end
  end

  describe "ExBao.health/1" do
    test "a standby answers with its status, and that is a health answer" do
      stub = :"stub_#{System.unique_integer([:positive])}"

      Req.Test.stub(stub, fn conn ->
        conn |> Plug.Conn.put_status(473) |> Req.Test.json(%{"standby" => true})
      end)

      assert {:ok, %{"standby" => true}} = ExBao.health(client(stub))
    end

    test "a 500 is still an error, whatever its body" do
      stub = :"stub_#{System.unique_integer([:positive])}"

      Req.Test.stub(stub, fn conn ->
        conn |> Plug.Conn.put_status(500) |> Req.Test.json(%{"errors" => ["boom"]})
      end)

      assert {:error, %ExBao.Error{kind: :server_error}} = ExBao.health(client(stub))
    end
  end
end
