defmodule ExBao.TransitTest do
  @moduledoc """
  Transit against a real server.

  Every assertion here is about behaviour the documentation promises, not
  about the shape of a JSON body — that is what makes this suite worth
  running against four OpenBao versions instead of one.
  """

  use ExBao.BaoCase, async: false

  alias ExBao.{Error, Transit}

  setup %{client: client} do
    key = unique_key("transit")
    :ok = Transit.create_key(client, key)
    on_exit(fn -> delete_transit_key(client, key) end)
    {:ok, key: key}
  end

  describe "sealing and opening" do
    test "a value comes back out exactly as it went in", %{client: c, key: key} do
      {:ok, sealed} = Transit.encrypt(c, key, "00912345620")
      assert {:ok, "00912345620"} = Transit.decrypt(c, key, sealed)
    end

    # The key version is written on the outside, which is what makes rotation
    # possible without a migration.
    test "what comes back says which key version sealed it", %{client: c, key: key} do
      {:ok, sealed} = Transit.encrypt(c, key, "hello")
      assert String.starts_with?(sealed, "vault:v1:")
    end

    # Callers pass values, not encodings of values. Anything that survives a
    # round trip here is a caller who never had to think about base64.
    test "bytes that are not text survive", %{client: c, key: key} do
      raw = <<0, 255, 10, 13, 27, 128>>
      {:ok, sealed} = Transit.encrypt(c, key, raw)
      assert {:ok, ^raw} = Transit.decrypt(c, key, sealed)
    end

    test "an empty value is still a value", %{client: c, key: key} do
      {:ok, sealed} = Transit.encrypt(c, key, "")
      assert {:ok, ""} = Transit.decrypt(c, key, sealed)
    end

    test "accents and emoji survive", %{client: c, key: key} do
      text = "José Muñoz 🇨🇴"
      {:ok, sealed} = Transit.encrypt(c, key, text)
      assert {:ok, ^text} = Transit.decrypt(c, key, sealed)
    end

    # Sealing the same value twice must not produce the same ciphertext, or
    # anyone with the database could tell which rows hold the same account
    # number without opening a single one.
    test "the same value sealed twice looks different", %{client: c, key: key} do
      {:ok, one} = Transit.encrypt(c, key, "3001234417")
      {:ok, two} = Transit.encrypt(c, key, "3001234417")
      refute one == two
    end

    test "a corrupt ciphertext is refused, and says why", %{client: c, key: key} do
      assert {:error, %Error{kind: :invalid_ciphertext}} =
               Transit.decrypt(c, key, "vault:v1:not-really-a-ciphertext")
    end

    # Measured, not assumed, and the opposite of what we had written: OpenBao
    # CREATES the key. A typo in a key name does not fail — it makes a second
    # key and seals under it. The moduledoc says so and says what guards it.
    test "sealing under an unknown key creates it", %{client: c} do
      key = unique_key("upsert")
      on_exit(fn -> delete_transit_key(c, key) end)

      assert {:ok, sealed} = Transit.encrypt(c, key, "x")
      assert String.starts_with?(sealed, "vault:v1:")
      assert {:ok, %{"name" => ^key}} = Transit.read_key(c, key)
    end

    # The guard against the above. OpenBao has no flag for it, so the key is
    # read first and a missing one stops the write before it happens.
    test "unless told to look first", %{client: c} do
      key = unique_key("guarded")

      assert {:error, %Error{kind: :not_found}} =
               Transit.encrypt(c, key, "x", avoid_create_on_missing: true)

      # And it really did not create it -- the point is the absence, not the
      # error message.
      assert {:error, %Error{kind: :not_found}} = Transit.read_key(c, key)
    end

    test "and the guard lets an existing key through", %{client: c, key: key} do
      assert {:ok, sealed} = Transit.encrypt(c, key, "fine", avoid_create_on_missing: true)
      assert {:ok, "fine"} = Transit.decrypt(c, key, sealed)
    end
  end

  describe "batches" do
    test "results come back in the order they were sent", %{client: c, key: key} do
      values = ["first", "second", "third", "fourth"]
      {sealed, []} = c |> Transit.encrypt_batch(key, values) |> Transit.split()
      assert length(sealed) == 4

      {opened, []} = c |> Transit.decrypt_batch(key, sealed) |> Transit.split()
      assert opened == values
    end

    # The property that matters when a page renders a list: one corrupt row
    # must not blank the page.
    # The server answers 400 for the whole batch when one element fails, and
    # puts every result in the body anyway. Reading only the status throws
    # away the ones that worked, which is what this asserts against.
    test "one bad element does not fail the batch", %{client: c, key: key} do
      {[good], []} = c |> Transit.encrypt_batch(key, ["fine"]) |> Transit.split()

      assert {:ok, [{:ok, "fine"}, {:error, %Error{}}]} =
               Transit.decrypt_batch(c, key, [good, "vault:v1:garbage"])
    end

    # The server refuses an empty batch with "missing batch input to
    # process". Mapping over an empty list is not an error anywhere else in
    # Elixir, so it does not become one here: the request is never sent.
    test "an empty batch is an empty answer, not an error", %{client: c, key: key} do
      assert {:ok, []} = Transit.encrypt_batch(c, key, [])
      assert {:ok, []} = Transit.decrypt_batch(c, key, [])
    end

    # References, so a failure can be traced to the row it came from without
    # counting positions. The server echoes them back, errors included, which
    # is the part that matters: the mapping survives anything that reorders.
    test "results can carry a reference instead of a position", %{client: c, key: key} do
      ids = ["dest-42", "dest-77"]

      assert {:ok, [{"dest-42", {:ok, good}}, {"dest-77", {:ok, _}}]} =
               Transit.encrypt_batch(c, key, ["a", "b"], references: ids)

      # The bad one is second, and its reference comes back on the error.
      assert {:ok, [{"dest-42", {:ok, "a"}}, {"dest-77", {:error, %Error{}}}]} =
               Transit.decrypt_batch(c, key, [good, "vault:v1:garbage"], references: ids)
    end

    test "and split keeps them on both sides", %{client: c, key: key} do
      ids = ["dest-42", "dest-77"]
      {:ok, [{_, {:ok, good}}, _]} = Transit.encrypt_batch(c, key, ["a", "b"], references: ids)

      {opened, failed} =
        c
        |> Transit.decrypt_batch(key, [good, "vault:v1:garbage"], references: ids)
        |> Transit.split()

      assert opened == [{"dest-42", "a"}]
      assert [{"dest-77", %Error{kind: :invalid_ciphertext}}] = failed
    end

    test "split separates what worked from what did not", %{client: c, key: key} do
      {:ok, [{:ok, good}]} = Transit.encrypt_batch(c, key, ["fine"])

      {opened, failed} =
        c |> Transit.decrypt_batch(key, [good, "vault:v1:garbage"]) |> Transit.split()

      assert opened == ["fine"]
      assert [%Error{kind: :invalid_ciphertext}] = failed
    end

    # Worse here than for a single value: a mistyped key would seal the whole
    # list under the phantom one.
    test "the guard covers batches too", %{client: c} do
      key = unique_key("guarded_batch")

      assert {:error, %Error{kind: :not_found}} =
               Transit.encrypt_batch(c, key, ["a", "b"], avoid_create_on_missing: true)

      assert {:error, %Error{kind: :not_found}} = Transit.read_key(c, key)
    end
  end

  describe "rotation" do
    test "a rotated key still opens what the old version sealed", %{client: c, key: key} do
      {:ok, sealed_v1} = Transit.encrypt(c, key, "00912345620")
      :ok = Transit.rotate(c, key)

      assert {:ok, "00912345620"} = Transit.decrypt(c, key, sealed_v1)
    end

    test "new values use the new version", %{client: c, key: key} do
      :ok = Transit.rotate(c, key)
      {:ok, sealed} = Transit.encrypt(c, key, "x")

      assert String.starts_with?(sealed, "vault:v2:")
    end

    test "rewrap moves a value to the newest version", %{client: c, key: key} do
      {:ok, v1} = Transit.encrypt(c, key, "00912345620")
      :ok = Transit.rotate(c, key)

      {:ok, v2} = Transit.rewrap(c, key, v1)

      assert String.starts_with?(v2, "vault:v2:")
      assert {:ok, "00912345620"} = Transit.decrypt(c, key, v2)
    end

    test "rewrap works in batches too", %{client: c, key: key} do
      {sealed, []} = c |> Transit.encrypt_batch(key, ["a", "b"]) |> Transit.split()
      :ok = Transit.rotate(c, key)

      {rewrapped, []} = c |> Transit.rewrap_batch(key, sealed) |> Transit.split()

      assert Enum.all?(rewrapped, &String.starts_with?(&1, "vault:v2:"))
    end

    # This is what makes an old key useless, and also what makes anything you
    # forgot to rewrap unreadable. Both halves are the point.
    test "raising the minimum version locks out the old one", %{client: c, key: key} do
      {:ok, v1} = Transit.encrypt(c, key, "left behind")
      :ok = Transit.rotate(c, key)
      :ok = Transit.set_min_decryption_version(c, key, 2)

      assert {:error, %Error{}} = Transit.decrypt(c, key, v1)
    end
  end

  describe "keys" do
    test "reads back its own configuration", %{client: c, key: key} do
      assert {:ok, %{"type" => "aes256-gcm96", "latest_version" => 1}} = Transit.read_key(c, key)
    end

    test "creating one that exists changes nothing", %{client: c, key: key} do
      assert :ok = Transit.create_key(c, key)
      assert {:ok, %{"latest_version" => 1}} = Transit.read_key(c, key)
    end

    test "lists the keys it has", %{client: c, key: key} do
      {:ok, keys} = Transit.list_keys(c)
      assert key in keys
    end

    # Reading does not create, unlike sealing. The asymmetry is the server's.
    test "reading one that does not exist is not found", %{client: c} do
      assert {:error, %Error{kind: :not_found}} = Transit.read_key(c, unique_key("absent"))
    end
  end
end
