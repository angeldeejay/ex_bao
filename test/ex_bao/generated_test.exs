defmodule ExBao.GeneratedTest do
  @moduledoc """
  Generated modules against a real server.

  Not one test per operation — there are hundreds, and the unit suite
  already checks what each one sends. These are the chains that prove the
  generated layer works end to end: that the paths, the mounts, the
  option names and the PATCH content type are what OpenBao actually
  accepts, not only what its specification says.
  """

  use ExBao.BaoCase, async: false

  alias ExBao.Auth.Userpass
  alias ExBao.{Error, KV, Sys, Transit}

  describe "KV version 2" do
    test "a secret written comes back, and a patch merges into it", %{client: c} do
      path = "gen/#{unique_key()}"
      on_exit(fn -> KV.delete_metadata_path(c, path) end)

      assert {:ok, %{"data" => %{"version" => 1}}} =
               KV.write_data_path(c, path, data: %{"user" => "app", "pass" => "one"})

      assert {:ok, %{"data" => %{"version" => 2}}} =
               KV.patch_data_path(c, path, data: %{"pass" => "two"})

      assert {:ok, %{"data" => %{"data" => %{"user" => "app", "pass" => "two"}}}} =
               KV.read_data_path(c, path)
    end

    test "a secret that is not there is not found", %{client: c} do
      assert {:error, %Error{kind: :not_found}} = KV.read_data_path(c, "gen/#{unique_key()}")
    end
  end

  describe "the rest of Transit" do
    test "an HMAC made by the server verifies against the same input", %{client: c} do
      key = unique_key("gen")
      :ok = Transit.create_key(c, key)
      on_exit(fn -> delete_transit_key(c, key) end)

      input = Base.encode64("00912345620")

      assert {:ok, %{"data" => %{"hmac" => "vault:v1:" <> _ = hmac}}} =
               Transit.generate_hmac(c, key, input: input)

      assert {:ok, %{"data" => %{"valid" => true}}} =
               Transit.verify(c, key, input: input, hmac: hmac)
    end
  end

  describe "an auth method from scratch" do
    test "enable userpass, create a user, log in as them", %{client: c} do
      mount = unique_key("up")
      assert {:ok, nil} = Sys.auth_enable_method(c, mount, type: "userpass")
      on_exit(fn -> Sys.auth_disable_method(c, mount) end)

      assert {:ok, %{"data" => methods}} = Sys.auth_list_enabled_methods(c)
      assert Map.has_key?(methods, mount <> "/")

      assert {:ok, nil} =
               Userpass.write_user(c, "ana",
                 password: "s3cret",
                 token_policies: "default",
                 mount: mount
               )

      anonymous = %{c | token: nil}

      assert {:ok, %{"auth" => %{"client_token" => token}}} =
               Userpass.login(anonymous, "ana", password: "s3cret", mount: mount)

      assert is_binary(token)

      assert {:error, %Error{}} =
               Userpass.login(anonymous, "ana", password: "wrong", mount: mount)
    end
  end
end
