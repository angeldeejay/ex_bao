defmodule ExBao.ClientTest do
  use ExUnit.Case, async: false

  alias ExBao.Client

  setup do
    # These tests are about how configuration is read, so they own the
    # environment and put it back.
    vars = ~w(BAO_ADDR BAO_TOKEN BAO_NAMESPACE)
    before = Map.new(vars, &{&1, System.get_env(&1)})
    Enum.each(vars, &System.delete_env/1)

    on_exit(fn ->
      Enum.each(before, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)

      Application.delete_env(:ex_bao, :addr)
    end)

    :ok
  end

  describe "new/1" do
    test "takes what it is given" do
      client = Client.new(addr: "http://127.0.0.1:8200", token: "t")
      assert client.addr == "http://127.0.0.1:8200"
      assert client.token == "t"
    end

    # A trailing slash would build `//v1/...`, which some proxies answer and
    # others reject. Both spellings have to behave the same.
    test "a trailing slash does not change anything" do
      assert Client.new(addr: "http://x:8200/").addr == "http://x:8200"
    end

    test "falls back to the environment" do
      System.put_env("BAO_ADDR", "http://from-env:8200")
      System.put_env("BAO_TOKEN", "env-token")

      client = Client.new()
      assert client.addr == "http://from-env:8200"
      assert client.token == "env-token"
    end

    # So a release can be pointed elsewhere without being rebuilt.
    test "the environment beats application config" do
      Application.put_env(:ex_bao, :addr, "http://from-config:8200")
      System.put_env("BAO_ADDR", "http://from-env:8200")

      assert Client.new().addr == "http://from-env:8200"
    end

    # So a caller is never fighting the ambient configuration.
    test "an explicit option beats both" do
      Application.put_env(:ex_bao, :addr, "http://from-config:8200")
      System.put_env("BAO_ADDR", "http://from-env:8200")

      assert Client.new(addr: "http://explicit:8200").addr == "http://explicit:8200"
    end

    test "says plainly when there is no address" do
      assert_raise ArgumentError, ~r/no server address/, fn -> Client.new() end
    end

    test "passes unknown options through to the transport" do
      client = Client.new(addr: "http://x:8200", receive_timeout: 1234)
      assert client.options[:receive_timeout] == 1234
    end

    # There is deliberately no global switch for this: a test that needs a
    # self-signed certificate must not be able to disable verification for
    # production by setting one value in the wrong config file.
    test "verification is on unless this client says otherwise" do
      on = Client.new(addr: "https://x:8200")
      refute get_in(on.options, [:connect_options, :transport_opts, :verify])

      off = Client.new(addr: "https://x:8200", verify: false)
      assert get_in(off.options, [:connect_options, :transport_opts, :verify]) == :verify_none
    end
  end

  describe "with_token/2" do
    test "moves the token and nothing else" do
      client = Client.new(addr: "http://x:8200", token: "old", receive_timeout: 99)
      moved = Client.with_token(client, "new")

      assert moved.token == "new"
      assert moved.addr == client.addr
      assert moved.options == client.options
    end
  end
end
