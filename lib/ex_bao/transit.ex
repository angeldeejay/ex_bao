defmodule ExBao.Transit do
  @moduledoc """
  Encryption as a service: the key never leaves the server.

  You hand Transit a value and get back a sealed one; you hand it the sealed
  one and get the value. The key is not in your process, not in a memory
  dump, and not in an environment variable someone can list from a container.
  An application compromised at runtime can ask the server to open what it is
  entitled to open — it cannot walk off with the means to open everything.

  ## What a sealed value looks like

      vault:v1:Xo0En3wRbT5urbzKrsXFAhXUmjkqumptoErLc3NIZ9bskIycK3l6

  The `v1` is the key version, written on the outside. That is why rotation
  does not need a migration: a value sealed under v1 still opens after the
  key has rotated to v2, because the value itself says which version it
  needs.

  ## Base64

  Transit speaks base64 on the wire; these functions do not. You pass the
  value and you get the value back. Making every caller encode and decode is
  a way to eventually get it wrong somewhere.

  ## Where it is mounted

  Every function takes `:mount`, `"transit"` by default. A server can mount
  the engine more than once — one mount per tenant, say — and then the mount
  is the only thing that says which one you mean.

  ## Whose job is the key

  Creating and rotating keys lives here too, but that is operational work,
  not runtime work. An application seals and opens; an operator creates and
  rotates.

  ## A sharp edge worth knowing

  **Sealing under a key that does not exist creates it.** That is OpenBao's
  behaviour, not this library's, and it is measured rather than assumed: a
  typo in a key name does not fail, it quietly makes a second key and seals
  under that one. Nothing is lost — the value still opens, because the name
  is in the row — but you now have two keys where you meant one, and only
  one of them is in your rotation procedure.

  There are two guards, and they are not alternatives:

    * **`avoid_create_on_missing: true`** on `encrypt/4` and
      `encrypt_batch/4`. The key is read first, and a missing one fails with
      `:not_found` rather than being created. It costs a round trip, so it is
      off by default: the caller decides where that trade is worth making,
      and sealing somebody's payout details is exactly where it is. The
      token needs `read` on `transit/keys/<name>` for it: without that the
      check answers `:permission_denied`, not `:not_found`.

    * **A policy that does not grant `create` on `transit/keys/*`** to the
      application. Free, and impossible to forget at a call site — but it
      belongs to whoever administers the server rather than to whoever writes
      the call.

  The first catches the typo in your own process, with an error that names
  it. The second catches it even in code that forgot to ask.
  """

  alias ExBao.{Client, Error, Operation}

  import Operation, only: [escape: 1, put: 3, put: 4, unexpected: 1]

  use ExBao.Operation

  @type server :: ExBao.server()
  @type key :: String.t()

  @typedoc """
  One element of a batch: its outcome, and its reference when one was sent.
  """
  @type result ::
          {:ok, binary()}
          | {:error, Error.t()}
          | {String.t(), {:ok, binary()} | {:error, Error.t()}}

  # ── sealing and opening ───────────────────────────────────────────────────

  @doc """
  Seals a value under a key.

      iex> ExBao.Transit.encrypt(server, "payout", "00912345620")
      {:ok, "vault:v1:Xo0En3wRbT5urbzKrsXFAhXUmjkqumptoErLc3NIZ9bskIycK3l6"}

  ## Options

    * `:context` — for keys derived per context. Sealing and opening must use
      the same one; a different context is a different key.
    * `:key_version` — seal under a specific version instead of the newest.
    * `:avoid_create_on_missing` — read the key first and fail with
      `:not_found` rather than let the server create it. Costs one extra
      round trip and needs `read` on the key; see the note on the module.
  """
  @operation "transit-encrypt"
  @spec encrypt(server(), key(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def encrypt(server, key, plaintext, opts \\ []) when is_binary(plaintext) do
    body =
      %{"plaintext" => Base.encode64(plaintext)}
      |> put("context", opts[:context], &Base.encode64/1)
      |> put("key_version", opts[:key_version])

    with {:ok, client} <- Operation.resolve(server),
         :ok <- ensure_exists(client, key, opts),
         {:ok, %{"data" => %{"ciphertext" => ciphertext}}} <-
           Client.request(client, :post, "#{mount(opts)}/encrypt/#{escape(key)}", body) do
      {:ok, ciphertext}
    else
      {:ok, body} -> {:error, unexpected(body)}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Opens a sealed value.

      iex> ExBao.Transit.decrypt(server, "payout", "vault:v1:Xo0En3w...")
      {:ok, "00912345620"}
  """
  @operation "transit-decrypt"
  @spec decrypt(server(), key(), String.t(), keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def decrypt(server, key, ciphertext, opts \\ []) when is_binary(ciphertext) do
    body =
      %{"ciphertext" => ciphertext}
      |> put("context", opts[:context], &Base.encode64/1)

    with {:ok, client} <- Operation.resolve(server),
         {:ok, %{"data" => %{"plaintext" => encoded}}} <-
           Client.request(client, :post, "#{mount(opts)}/decrypt/#{escape(key)}", body),
         {:ok, plaintext} <- decode(encoded) do
      {:ok, plaintext}
    else
      {:ok, body} -> {:error, unexpected(body)}
      {:error, error} -> {:error, error}
    end
  end

  # ── in batches ────────────────────────────────────────────────────────────

  @doc """
  Seals many values in one round trip.

  **Every element comes back wrapped**, whether anything failed or not:
  `{:ok, value}` or `{:error, reason}`. The outer `:ok` does not say the work
  succeeded — it says the request was made and here are the results. What
  failed is inside, where whoever iterates has to see it.

  One bad element therefore does not fail the batch, which is the shape that
  matters when a page renders a list: one corrupt row should not blank the
  page.

      iex> ExBao.Transit.encrypt_batch(server, "payout", ["00912345620", "3001234417"])
      {:ok, [ok: "vault:v1:Xo0En3w...", ok: "vault:v1:9dK2lsP..."]}

  ## Knowing which one failed

  Results are positional, so the fifth answer belongs to the fifth value you
  sent. That holds, but it is a fragile thing to depend on: anything that
  filters or reorders on the way breaks it silently.

  `:references` removes the dependency. Each result comes back carrying the
  reference **the server returned**, errors included:

      iex> Transit.encrypt_batch(server, "payout", values, references: ids)
      {:ok, [{"dest-42", {:ok, "vault:v1:..."}}, {"dest-77", {:error, %Error{}}}]}

  ## Options

    * `:references` — one per value, echoed back with each result. A list
      of a different length raises `ArgumentError` rather than dropping the
      values it does not cover.
    * `:context`, `:avoid_create_on_missing` — as in `encrypt/4`.
  """
  @spec encrypt_batch(server(), key(), [binary()], keyword()) ::
          {:ok, [result()]} | {:error, Error.t()}
  def encrypt_batch(server, key, plaintexts, opts \\ []) when is_list(plaintexts) do
    items = Enum.map(plaintexts, &%{"plaintext" => Base.encode64(&1)})

    # The same guard as `encrypt/4`, and it matters more here: a mistyped key
    # seals the whole list under the phantom one, not a single value.
    with {:ok, client} <- Operation.resolve(server),
         :ok <- ensure_exists(client, key, opts) do
      batch(client, "#{mount(opts)}/encrypt/#{escape(key)}", items, opts, &take(&1, "ciphertext"))
    end
  end

  @doc """
  Opens many sealed values in one round trip. Same wrapping, same references
  and same per-element errors as `encrypt_batch/4`.

      iex> ExBao.Transit.decrypt_batch(server, "payout", [good, corrupted])
      {:ok, [ok: "00912345620", error: %ExBao.Error{kind: :invalid_ciphertext}]}
  """
  @spec decrypt_batch(server(), key(), [String.t()], keyword()) ::
          {:ok, [result()]} | {:error, Error.t()}
  def decrypt_batch(server, key, ciphertexts, opts \\ []) when is_list(ciphertexts) do
    items = Enum.map(ciphertexts, &%{"ciphertext" => &1})

    batch(server, "#{mount(opts)}/decrypt/#{escape(key)}", items, opts, fn item ->
      with {:ok, encoded} <- take(item, "plaintext"), do: decode(encoded)
    end)
  end

  @doc """
  Splits a batch into what worked and what did not.

      iex> {sealed, failed} = Transit.encrypt_batch(server, "payout", values) |> Transit.split()
      iex> sealed
      ["vault:v1:Xo0En3w...", "vault:v1:9dK2lsP..."]
      iex> failed
      []

  With references, both sides keep theirs, so a failure can be traced back to
  the row it came from:

      iex> {sealed, failed} = Transit.decrypt_batch(s, "payout", cts, references: ids) |> Transit.split()
      iex> failed
      [{"dest-77", %ExBao.Error{kind: :invalid_ciphertext}}]

  There is deliberately no `all/1` that collapses a batch into the first
  error. In this domain that is nearly always the wrong move: nine payout
  destinations opening and one failing should paint nine rows and mark one,
  not fail the screen. Something that genuinely needs all or nothing gets it
  from here in one line — `case split(results) do {values, []} -> ...` — and
  has to say so.

  A `{:error, _}` from the call itself passes straight through: that is the
  request failing, not an element, and there is nothing to split.

  Takes the tuple a batch returns or the bare list inside it, so it works
  both piped and on results already unwrapped.
  """
  @spec split({:ok, [result()]} | {:error, Error.t()} | [result()]) ::
          {[binary() | {String.t(), binary()}], [Error.t() | {String.t(), Error.t()}]}
          | {:error, Error.t()}
  def split({:error, %Error{}} = error), do: error

  def split({:ok, results}) when is_list(results), do: split(results)

  def split(results) when is_list(results) do
    {oks, errors} =
      Enum.split_with(results, fn
        {:ok, _value} -> true
        {:error, _reason} -> false
        {_reference, {:ok, _value}} -> true
        {_reference, {:error, _reason}} -> false
      end)

    {Enum.map(oks, &unwrap/1), Enum.map(errors, &unwrap/1)}
  end

  defp unwrap({:ok, value}), do: value
  defp unwrap({:error, reason}), do: reason
  defp unwrap({reference, {:ok, value}}), do: {reference, value}
  defp unwrap({reference, {:error, reason}}), do: {reference, reason}

  # ── rotation ──────────────────────────────────────────────────────────────

  @doc """
  Adds a new version to a key.

  It does not invalidate the old versions: everything already sealed keeps
  opening. New values are sealed under the new version.
  """
  @operation "transit-rotate-key"
  @spec rotate(server(), key(), keyword()) :: :ok | {:error, Error.t()}
  def rotate(server, key, opts \\ []) do
    with {:ok, client} <- Operation.resolve(server),
         {:ok, _body} <-
           Client.request(client, :post, "#{mount(opts)}/keys/#{escape(key)}/rotate", %{}) do
      :ok
    end
  end

  @doc """
  Re-seals a value under the newest key version.

  **The value never comes back out** — the server opens it and seals it again
  internally. That is the difference between rotating with `rewrap` and
  rotating by decrypting and re-encrypting: the second one brings every
  secret you own through your application's memory.

      iex> ExBao.Transit.rewrap(server, "payout", "vault:v1:Xo0En3w...")
      {:ok, "vault:v2:Qm5tRa0..."}
  """
  @operation "transit-rewrap"
  @spec rewrap(server(), key(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def rewrap(server, key, ciphertext, opts \\ []) do
    body =
      %{"ciphertext" => ciphertext}
      |> put("context", opts[:context], &Base.encode64/1)

    with {:ok, client} <- Operation.resolve(server),
         {:ok, %{"data" => %{"ciphertext" => rewrapped}}} <-
           Client.request(client, :post, "#{mount(opts)}/rewrap/#{escape(key)}", body) do
      {:ok, rewrapped}
    else
      {:ok, body} -> {:error, unexpected(body)}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Re-seals many values in one round trip.
  """
  @spec rewrap_batch(server(), key(), [String.t()], keyword()) ::
          {:ok, [result()]} | {:error, Error.t()}
  def rewrap_batch(server, key, ciphertexts, opts \\ []) when is_list(ciphertexts) do
    items = Enum.map(ciphertexts, &%{"ciphertext" => &1})
    batch(server, "#{mount(opts)}/rewrap/#{escape(key)}", items, opts, &take(&1, "ciphertext"))
  end

  @doc """
  Refuses to open anything sealed under a version below this one.

  Run it **after** every stored value has been rewrapped, not before: it is
  what makes a compromised old version useless, and it is also what makes
  anything you forgot to rewrap unreadable.
  """
  @spec set_min_decryption_version(server(), key(), pos_integer(), keyword()) ::
          :ok | {:error, Error.t()}
  def set_min_decryption_version(server, key, version, opts \\ []) when is_integer(version) do
    with {:ok, client} <- Operation.resolve(server),
         {:ok, _body} <-
           Client.request(client, :post, "#{mount(opts)}/keys/#{escape(key)}/config", %{
             "min_decryption_version" => version
           }) do
      :ok
    end
  end

  # ── keys ──────────────────────────────────────────────────────────────────

  @doc """
  Creates a key. Idempotent: creating one that exists changes nothing.

  ## Options

    * `:type` — `:aes256_gcm96` by default, which is the one you want unless
      you know why you want another.
    * `:derived` — derive a per-context key. Sealing then requires a context.
    * `:exportable` — allow the key material to be read out. Off by default,
      and turning it on gives away the property this module exists for.
  """
  @operation "transit-create-key"
  @spec create_key(server(), key(), keyword()) :: :ok | {:error, Error.t()}
  def create_key(server, key, opts \\ []) do
    body =
      %{"type" => opts |> Keyword.get(:type, :aes256_gcm96) |> type_name()}
      |> put("derived", opts[:derived])
      |> put("exportable", opts[:exportable])
      |> put("allow_plaintext_backup", opts[:allow_plaintext_backup])

    with {:ok, client} <- Operation.resolve(server),
         {:ok, _body} <- Client.request(client, :post, "#{mount(opts)}/keys/#{escape(key)}", body) do
      :ok
    end
  end

  @doc """
  Reads a key's configuration. Never its material.
  """
  @operation "transit-read-key"
  @spec read_key(server(), key(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def read_key(server, key, opts \\ []) do
    with {:ok, client} <- Operation.resolve(server),
         {:ok, %{"data" => data}} <-
           Client.request(client, :get, "#{mount(opts)}/keys/#{escape(key)}") do
      {:ok, data}
    else
      {:ok, body} -> {:error, unexpected(body)}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Lists key names.

  An empty Transit mount answers 404, which is not an error here — no keys is
  a valid answer to "which keys are there", and making every caller handle a
  404 that means "none" is how that check gets forgotten.
  """
  @operation "transit-list-keys"
  @spec list_keys(server(), keyword()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def list_keys(server, opts \\ []) do
    with {:ok, client} <- Operation.resolve(server),
         {:ok, body} <- Client.request(client, :get, "#{mount(opts)}/keys?list=true") do
      {:ok, get_in(body, ["data", "keys"]) || []}
    else
      {:error, %Error{kind: :not_found}} -> {:ok, []}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Deletes a key, and with it the ability to open anything sealed under it.

  The server refuses unless the key was configured with `deletion_allowed`,
  which is a guard worth leaving on.
  """
  @operation "transit-delete-key"
  @spec delete_key(server(), key(), keyword()) :: :ok | {:error, Error.t()}
  def delete_key(server, key, opts \\ []) do
    with {:ok, client} <- Operation.resolve(server),
         {:ok, _body} <- Client.request(client, :delete, "#{mount(opts)}/keys/#{escape(key)}") do
      :ok
    end
  end

  # ── plumbing ──────────────────────────────────────────────────────────────

  defp mount(opts), do: Operation.mount(opts, "transit")

  # Reading before writing, when asked. OpenBao has no flag for this — its
  # `encrypt` creates what is missing and there is no way to tell it not to —
  # so the only way to refuse is to look first.
  #
  # Nothing is cached. A cache would have to answer "does this key still
  # exist", and that answer changes the moment an operator deletes one, which
  # is exactly when a stale "yes" would send values at a key that is gone.
  defp ensure_exists(client, key, opts) do
    if Keyword.get(opts, :avoid_create_on_missing, false) do
      with {:ok, _key} <- read_key(client, key, opts), do: :ok
    else
      :ok
    end
  end

  # An empty batch is zero work, not a request. The server answers a 400
  # ("missing batch input to process") and it would be a strange thing to
  # make a caller handle: mapping over an empty list is not an error
  # anywhere else, and it should not become one here.
  defp batch(_server, _path, [], _opts, _extract), do: {:ok, []}

  defp batch(server, path, items, opts, extract) do
    items =
      items
      |> with_context(opts[:context])
      |> with_references(opts[:references])

    with {:ok, client} <- Operation.resolve(server),
         {:ok, results} <-
           results(Client.request(client, :post, path, %{"batch_input" => items})) do
      {:ok, Enum.map(results, &label(&1, extract, opts[:references]))}
    end
  end

  defp with_context(items, nil), do: items

  defp with_context(items, context),
    do: Enum.map(items, &Map.put(&1, "context", Base.encode64(context)))

  defp with_references(items, nil), do: items

  # `Enum.zip/2` stops at the shorter list, so a mismatch would quietly drop
  # the values that had no reference — the very rows a reference is there to
  # keep track of. A caller that got the lengths wrong has a bug, and is told.
  defp with_references(items, references) when length(items) != length(references) do
    raise ArgumentError,
          "got #{length(items)} values and #{length(references)} references: " <>
            ":references needs exactly one per value"
  end

  defp with_references(items, references) do
    items
    |> Enum.zip(references)
    |> Enum.map(fn {item, reference} -> Map.put(item, "reference", to_string(reference)) end)
  end

  # Without references the result is the value on its own, positional. With
  # them it is `{reference, result}`, and the reference is the one the SERVER
  # sent back — not the one we would guess from the position.
  defp label(item, extract, nil), do: extract.(item)
  defp label(item, extract, _references), do: {item["reference"], extract.(item)}

  # **A batch with one bad element answers 400, with every result in the
  # body.** Measured against 2.6.2, and it is the whole reason this function
  # exists: reading only the status throws away the nine that worked because
  # the tenth did not. The status describes the worst element, not the
  # request, so what decides is whether `batch_results` came back.
  defp results({:ok, %{"data" => %{"batch_results" => results}}}), do: {:ok, results}

  defp results({:error, %Error{reason: %{"data" => %{"batch_results" => results}}}}),
    do: {:ok, results}

  defp results({:ok, body}), do: {:error, unexpected(body)}
  defp results({:error, %Error{} = error}), do: {:error, error}

  # Each element of a batch answers with its own field or its own `error`,
  # and the error is prose. `Error.from_response/2` maps it to a kind the
  # same way a whole-request failure is mapped, so a caller matches on one
  # vocabulary rather than two.
  defp take(%{"error" => reason}, _field),
    do: {:error, Error.from_response(400, %{"errors" => [reason]})}

  defp take(item, field) do
    case Map.fetch(item, field) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, unexpected(item)}
    end
  end

  defp decode(encoded) do
    case Base.decode64(encoded) do
      {:ok, plaintext} ->
        {:ok, plaintext}

      :error ->
        {:error,
         %Error{kind: :unknown, messages: ["server returned plaintext that is not base64"]}}
    end
  end

  # `:aes256_gcm96` is `aes256-gcm96`, `:ecdsa_p256` is `ecdsa-p256`: every
  # type OpenBao names maps from its atom by swapping underscores.
  defp type_name(type) when is_atom(type),
    do: type |> Atom.to_string() |> String.replace("_", "-")

  defp type_name(type) when is_binary(type), do: type

  # ── generated by `mix bao.gen` from OpenBao 2.6.2 ──
  # Everything down to the closing marker is rewritten on every run. To
  # curate a function, move it above this block and keep its `@operation`:
  # the next run sees it there and stops generating it.

  @doc ~S"""
  Backup the named key

  `GET /v1/transit/backup/{name}`

  ## Arguments

    * `name` — Name of the key

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-back-up-key"
  @spec back_up_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def back_up_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :get,
      "#{mount(opts)}/backup/#{ExBao.Operation.escape(name)}",
      opts,
      []
    )
  end

  @doc ~S"""
  Securely export named encryption or signing key

  `GET /v1/transit/byok-export/{destination}/{source}`

  ## Arguments

    * `destination` — Destination key to export to; usually the public wrapping key of another Transit instance.
    * `source` — Source key to export; could be any present key within Transit.

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-byok-key"
  @spec byok_key(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def byok_key(server, destination, source, opts \\ []) do
    ExBao.Operation.call(
      server,
      :get,
      "#{mount(opts)}/byok-export/#{ExBao.Operation.escape(destination)}/#{ExBao.Operation.escape(source)}",
      opts,
      []
    )
  end

  @doc ~S"""
  Securely export named encryption or signing key

  `GET /v1/transit/byok-export/{destination}/{source}/{version}`

  ## Arguments

    * `destination` — Destination key to export to; usually the public wrapping key of another Transit instance.
    * `source` — Source key to export; could be any present key within Transit.
    * `version` — Optional version of the key to export, else all key versions are exported.

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-byok-key-version"
  @spec byok_key_version(ExBao.server(), String.t(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def byok_key_version(server, destination, source, version, opts \\ []) do
    ExBao.Operation.call(
      server,
      :get,
      "#{mount(opts)}/byok-export/#{ExBao.Operation.escape(destination)}/#{ExBao.Operation.escape(source)}/#{ExBao.Operation.escape(version)}",
      opts,
      []
    )
  end

  @doc ~S"""
  Configures a new cache of the specified size

  `POST /v1/transit/cache-config`

  Configure caching strategy

  ## Options

    * `:size` (integer) — Size of cache, use 0 for an unlimited cache size, defaults to 0 Defaults to `0`.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-configure-cache"
  @spec configure_cache(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def configure_cache(server, opts \\ []) do
    ExBao.Operation.call(server, :post, "#{mount(opts)}/cache-config", opts, body: [:size])
  end

  @doc ~S"""
  Configure a named encryption key

  `POST /v1/transit/keys/{name}/config`

  ## Arguments

    * `name` — Name of the key

  ## Options

    * `:allow_plaintext_backup` (boolean) — Enables taking a backup of the named key in plaintext format. Once set, this cannot be disabled.
    * `:auto_rotate_period` (seconds) — Amount of time the key should live before being automatically rotated. A value of 0 disables automatic rotation for the key.
    * `:deletion_allowed` (boolean) — Whether to allow deletion of the key
    * `:exportable` (boolean) — Enables export of the key. Once set, this cannot be disabled.
    * `:min_decryption_version` (integer) — If set, the minimum version of the key allowed to be decrypted. For signing keys, the minimum version allowed to be used for verification.
    * `:min_encryption_version` (integer) — If set, the minimum version of the key allowed to be used for encryption; or for signing keys, to be used for signing. If set to zero, only the latest version of the key is allowed.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-configure-key"
  @spec configure_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def configure_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/config",
      opts,
      body: [
        :allow_plaintext_backup,
        :auto_rotate_period,
        :deletion_allowed,
        :exportable,
        :min_decryption_version,
        :min_encryption_version
      ]
    )
  end

  @doc ~S"""
  Configuration common across all keys

  `POST /v1/transit/config/keys`

  ## Options

    * `:disable_upsert` (boolean) — Whether to allow automatic upserting (creation) of keys on the encrypt endpoint.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-configure-keys"
  @spec configure_keys(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def configure_keys(server, opts \\ []) do
    ExBao.Operation.call(server, :post, "#{mount(opts)}/config/keys", opts,
      body: [:disable_upsert]
    )
  end

  @doc ~S"""
  Derives a new key from a base key

  `POST /v1/transit/derive-key/{name}`

  ## Arguments

    * `name` — Name of the output derived key

  ## Options

    * `:base_key_name` (string) — Name of the base key to use for derivation (own private key for ECDH)
    * `:base_key_version` (integer) — The version of the base key to use for derivation. Must be 0 (for latest) or a value greater than or equal to the min_derivation_version configured on the key.
    * `:derived_key_type` (string) — The type of the output derived key. Currently, "aes128-gcm96" , "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305" are supported. Defaults to "aes256-gcm96". Defaults to `"aes256-gcm96"`.
    * `:key_derivation_algorithm` (string) — Key derivation algorithm to use. Valid values are: * ecdh Defaults to "ecdh". Defaults to `"ecdh"`.
    * `:peer_public_key` (string) — The pem-encoded other party's ECC public key
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-derive-key"
  @spec derive_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def derive_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/derive-key/#{ExBao.Operation.escape(name)}",
      opts,
      body: [
        :base_key_name,
        :base_key_version,
        :derived_key_type,
        :key_derivation_algorithm,
        :peer_public_key
      ]
    )
  end

  @doc ~S"""
  Export named encryption or signing key

  `GET /v1/transit/export/{type}/{name}`

  ## Arguments

    * `type` — Type of key to export (encryption-key, signing-key, hmac-key, public-key)
    * `name` — Name of the key

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-export-key"
  @spec export_key(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def export_key(server, type, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :get,
      "#{mount(opts)}/export/#{ExBao.Operation.escape(type)}/#{ExBao.Operation.escape(name)}",
      opts,
      []
    )
  end

  @doc ~S"""
  Export named encryption or signing key

  `GET /v1/transit/export/{type}/{name}/{version}`

  ## Arguments

    * `type` — Type of key to export (encryption-key, signing-key, hmac-key, public-key)
    * `name` — Name of the key
    * `version` — Version of the key

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-export-key-version"
  @spec export_key_version(ExBao.server(), String.t(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def export_key_version(server, type, name, version, opts \\ []) do
    ExBao.Operation.call(
      server,
      :get,
      "#{mount(opts)}/export/#{ExBao.Operation.escape(type)}/#{ExBao.Operation.escape(name)}/#{ExBao.Operation.escape(version)}",
      opts,
      []
    )
  end

  @doc ~S"""
  Generate a data key

  `POST /v1/transit/datakey/{plaintext}/{name}`

  ## Arguments

    * `plaintext` — "plaintext" will return the key in both plaintext and ciphertext; "wrapped" will return the ciphertext only.
    * `name` — The backend key used for encrypting the data key

  ## Options

    * `:associated_data` (string) — When using an AEAD cipher mode, such as AES-GCM, this parameter allows passing associated data (AD/AAD) into the encryption function; this data must be passed on subsequent decryption requests but can be transited in plaintext. On successful decryption, both the ciphertext and the associated data are attested not to have been tampered with.
    * `:bits` (integer) — Number of bits for the key; currently 128, 256, and 512 bits are supported. Defaults to 256. Defaults to `256`.
    * `:context` (string) — Context for key derivation. Required for derived keys.
    * `:key_version` (integer) — The version of the OpenBao key to use for encryption of the data key. Must be 0 (for latest) or a value greater than or equal to the min_encryption_version configured on the key.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-data-key"
  @spec generate_data_key(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def generate_data_key(server, plaintext, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/datakey/#{ExBao.Operation.escape(plaintext)}/#{ExBao.Operation.escape(name)}",
      opts,
      body: [:associated_data, :bits, :context, :key_version]
    )
  end

  @doc ~S"""
  Generate an HMAC for input data using the named key

  `POST /v1/transit/hmac/{name}`

  ## Arguments

    * `name` — The key to use for the HMAC function

  ## Options

    * `:algorithm` (string) — Algorithm to use (POST body parameter). Valid values are: * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 Defaults to "sha2-256". Defaults to `"sha2-256"`.
    * `:batch_input` (array) — Specifies a list of items to be processed in a single batch. When this parameter is set, if the parameter 'input' is also set, it will be ignored. Any batch output will preserve the order of the batch input.
    * `:input` (string) — The base64-encoded input data
    * `:key_version` (integer) — The version of the key to use for generating the HMAC. Must be 0 (for latest) or a value greater than or equal to the min_encryption_version configured on the key.
    * `:urlalgorithm` (string) — Algorithm to use (POST URL parameter)
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-hmac"
  @spec generate_hmac(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def generate_hmac(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/hmac/#{ExBao.Operation.escape(name)}",
      opts,
      body: [:algorithm, :batch_input, :input, :key_version, :urlalgorithm]
    )
  end

  @doc ~S"""
  Generate an HMAC for input data using the named key

  `POST /v1/transit/hmac/{name}/{urlalgorithm}`

  ## Arguments

    * `name` — The key to use for the HMAC function
    * `urlalgorithm` — Algorithm to use (POST URL parameter)

  ## Options

    * `:algorithm` (string) — Algorithm to use (POST body parameter). Valid values are: * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 Defaults to "sha2-256". Defaults to `"sha2-256"`.
    * `:batch_input` (array) — Specifies a list of items to be processed in a single batch. When this parameter is set, if the parameter 'input' is also set, it will be ignored. Any batch output will preserve the order of the batch input.
    * `:input` (string) — The base64-encoded input data
    * `:key_version` (integer) — The version of the key to use for generating the HMAC. Must be 0 (for latest) or a value greater than or equal to the min_encryption_version configured on the key.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-hmac-with-algorithm"
  @spec generate_hmac_with_algorithm(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def generate_hmac_with_algorithm(server, name, urlalgorithm, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/hmac/#{ExBao.Operation.escape(name)}/#{ExBao.Operation.escape(urlalgorithm)}",
      opts,
      body: [:algorithm, :batch_input, :input, :key_version]
    )
  end

  @doc ~S"""
  Generate random bytes

  `POST /v1/transit/random`

  ## Options

    * `:bytes` (integer) — The number of bytes to generate (POST body parameter). Defaults to 32 (256 bits). Defaults to `32`.
    * `:format` (string) — Encoding format to use. Can be "hex" or "base64". Defaults to "base64". Defaults to `"base64"`.
    * `:source` (string) — Which system to source random data from, ether "platform", "seal", or "all". Defaults to `"platform"`.
    * `:urlbytes` (string) — The number of bytes to generate (POST URL parameter)
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-random"
  @spec generate_random(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def generate_random(server, opts \\ []) do
    ExBao.Operation.call(server, :post, "#{mount(opts)}/random", opts,
      body: [:bytes, :format, :source, :urlbytes]
    )
  end

  @doc ~S"""
  Generate random bytes

  `POST /v1/transit/random/{urlbytes}`

  ## Arguments

    * `urlbytes` — The number of bytes to generate (POST URL parameter)

  ## Options

    * `:bytes` (integer) — The number of bytes to generate (POST body parameter). Defaults to 32 (256 bits). Defaults to `32`.
    * `:format` (string) — Encoding format to use. Can be "hex" or "base64". Defaults to "base64". Defaults to `"base64"`.
    * `:source` (string) — Which system to source random data from, ether "platform", "seal", or "all". Defaults to `"platform"`.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-random-with-bytes"
  @spec generate_random_with_bytes(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def generate_random_with_bytes(server, urlbytes, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/random/#{ExBao.Operation.escape(urlbytes)}",
      opts,
      body: [:bytes, :format, :source]
    )
  end

  @doc ~S"""
  Generate random bytes

  `POST /v1/transit/random/{source}`

  ## Arguments

    * `source` — Which system to source random data from, ether "platform", "seal", or "all".

  ## Options

    * `:bytes` (integer) — The number of bytes to generate (POST body parameter). Defaults to 32 (256 bits). Defaults to `32`.
    * `:format` (string) — Encoding format to use. Can be "hex" or "base64". Defaults to "base64". Defaults to `"base64"`.
    * `:urlbytes` (string) — The number of bytes to generate (POST URL parameter)
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-random-with-source"
  @spec generate_random_with_source(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def generate_random_with_source(server, source, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/random/#{ExBao.Operation.escape(source)}",
      opts,
      body: [:bytes, :format, :urlbytes]
    )
  end

  @doc ~S"""
  Generate random bytes

  `POST /v1/transit/random/{source}/{urlbytes}`

  ## Arguments

    * `source` — Which system to source random data from, ether "platform", "seal", or "all".
    * `urlbytes` — The number of bytes to generate (POST URL parameter)

  ## Options

    * `:bytes` (integer) — The number of bytes to generate (POST body parameter). Defaults to 32 (256 bits). Defaults to `32`.
    * `:format` (string) — Encoding format to use. Can be "hex" or "base64". Defaults to "base64". Defaults to `"base64"`.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-generate-random-with-source-and-bytes"
  @spec generate_random_with_source_and_bytes(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def generate_random_with_source_and_bytes(server, source, urlbytes, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/random/#{ExBao.Operation.escape(source)}/#{ExBao.Operation.escape(urlbytes)}",
      opts,
      body: [:bytes, :format]
    )
  end

  @doc ~S"""
  Sign a CSR with a key in transit

  `POST /v1/transit/keys/{name}/csr`

  ## Arguments

    * `name` — Name of the key to sign the CSR with.

  ## Options

    * `:csr` (string) — Optional PEM-encoded CSR template to use as the basis for the new CSR signed by this key. If not set, an empty CSR is used.
    * `:version` (integer) — Version of the key to use for signing. If the version is set to `latest`, or is not set, the current key will be returned
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "get-csr"
  @spec get_csr(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def get_csr(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/csr",
      opts,
      body: [:csr, :version]
    )
  end

  @doc ~S"""
  Generate a hash sum for input data

  `POST /v1/transit/hash`

  ## Options

    * `:algorithm` (string) — Algorithm to use (POST body parameter). Valid values are: * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 Defaults to "sha2-256". Defaults to `"sha2-256"`.
    * `:format` (string) — Encoding format to use. Can be "hex" or "base64". Defaults to "hex". Defaults to `"hex"`.
    * `:input` (string) — The base64-encoded input data
    * `:urlalgorithm` (string) — Algorithm to use (POST URL parameter)
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-hash"
  @spec hash(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def hash(server, opts \\ []) do
    ExBao.Operation.call(server, :post, "#{mount(opts)}/hash", opts,
      body: [:algorithm, :format, :input, :urlalgorithm]
    )
  end

  @doc ~S"""
  Generate a hash sum for input data

  `POST /v1/transit/hash/{urlalgorithm}`

  ## Arguments

    * `urlalgorithm` — Algorithm to use (POST URL parameter)

  ## Options

    * `:algorithm` (string) — Algorithm to use (POST body parameter). Valid values are: * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 Defaults to "sha2-256". Defaults to `"sha2-256"`.
    * `:format` (string) — Encoding format to use. Can be "hex" or "base64". Defaults to "hex". Defaults to `"hex"`.
    * `:input` (string) — The base64-encoded input data
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-hash-with-algorithm"
  @spec hash_with_algorithm(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def hash_with_algorithm(server, urlalgorithm, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/hash/#{ExBao.Operation.escape(urlalgorithm)}",
      opts,
      body: [:algorithm, :format, :input]
    )
  end

  @doc ~S"""
  Imports an externally-generated key into a new transit key

  `POST /v1/transit/keys/{name}/import`

  ## Arguments

    * `name` — The name of the key

  ## Options

    * `:allow_plaintext_backup` (boolean) — Enables taking a backup of the named key in plaintext format. Once set, this cannot be disabled.
    * `:allow_rotation` (boolean) — True if the imported key may be rotated within OpenBao; false otherwise.
    * `:auto_rotate_period` (seconds) — Amount of time the key should live before being automatically rotated. A value of 0 (default) disables automatic rotation for the key. Defaults to `0`.
    * `:ciphertext` (string) — The base64-encoded ciphertext of the keys. The AES key should be encrypted using OAEP with the wrapping key and then concatenated with the import key, wrapped by the AES key.
    * `:context` (string) — Base64 encoded context for key derivation. When reading a key with key derivation enabled, if the key type supports public keys, this will return the public key for the given context.
    * `:derived` (boolean) — Enables key derivation mode. This allows for per-transaction unique keys for encryption operations.
    * `:exportable` (boolean) — Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported.
    * `:hash_function` (string) — The hash function used as a random oracle in the OAEP wrapping of the user-generated, ephemeral AES key. Can be one of "SHA1", "SHA224", "SHA256" (default), "SHA384", or "SHA512" Defaults to `"SHA256"`.
    * `:public_key` (string) — The plaintext PEM public key to be imported. If "ciphertext" is set, this field is ignored.
    * `:type` (string) — The type of key being imported. Currently, "aes128-gcm96" (symmetric), "aes256-gcm96" (symmetric), "ecdsa-p256" (asymmetric), "ecdsa-p384" (asymmetric), "ecdsa-p521" (asymmetric), "ed25519" (asymmetric), "rsa-2048" (asymmetric), "rsa-3072" (asymmetric), "rsa-4096" (asymmetric) are supported. Defaults to "aes256-gcm96". Defaults to `"aes256-gcm96"`.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-import-key"
  @spec import_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def import_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/import",
      opts,
      body: [
        :allow_plaintext_backup,
        :allow_rotation,
        :auto_rotate_period,
        :ciphertext,
        :context,
        :derived,
        :exportable,
        :hash_function,
        :public_key,
        :type
      ]
    )
  end

  @doc ~S"""
  Imports an externally-generated key into an existing imported key

  `POST /v1/transit/keys/{name}/import_version`

  ## Arguments

    * `name` — The name of the key

  ## Options

    * `:ciphertext` (string) — The base64-encoded ciphertext of the keys. The AES key should be encrypted using OAEP with the wrapping key and then concatenated with the import key, wrapped by the AES key.
    * `:hash_function` (string) — The hash function used as a random oracle in the OAEP wrapping of the user-generated, ephemeral AES key. Can be one of "SHA1", "SHA224", "SHA256" (default), "SHA384", or "SHA512" Defaults to `"SHA256"`.
    * `:public_key` (string) — The plaintext public key to be imported. If "ciphertext" is set, this field is ignored.
    * `:version` (integer) — Key version to be updated, if left empty, a new version will be created unless a private key is specified and the 'Latest' key is missing a private key.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-import-key-version"
  @spec import_key_version(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def import_key_version(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/import_version",
      opts,
      body: [:ciphertext, :hash_function, :public_key, :version]
    )
  end

  @doc ~S"""
  Returns the size of the active cache

  `GET /v1/transit/cache-config`

  Configure caching strategy

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-read-cache-configuration"
  @spec read_cache_configuration(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def read_cache_configuration(server, opts \\ []) do
    ExBao.Operation.call(server, :get, "#{mount(opts)}/cache-config", opts, [])
  end

  @doc ~S"""
  Configuration common across all keys

  `GET /v1/transit/config/keys`

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-read-keys-configuration"
  @spec read_keys_configuration(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def read_keys_configuration(server, opts \\ []) do
    ExBao.Operation.call(server, :get, "#{mount(opts)}/config/keys", opts, [])
  end

  @doc ~S"""
  Returns the public key to use for wrapping imported keys

  `GET /v1/transit/wrapping_key`

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-read-wrapping-key"
  @spec read_wrapping_key(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def read_wrapping_key(server, opts \\ []) do
    ExBao.Operation.call(server, :get, "#{mount(opts)}/wrapping_key", opts, [])
  end

  @doc ~S"""
  Restore the named key

  `POST /v1/transit/restore/{name}`

  ## Arguments

    * `name` — If set, this will be the name of the restored key.

  ## Options

    * `:backup` (string) — Backed up key data to be restored. This should be the output from the 'backup/' endpoint.
    * `:force` (boolean) — If set and a key by the given name exists, force the restore operation and override the key. Defaults to `false`.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-restore-and-rename-key"
  @spec restore_and_rename_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def restore_and_rename_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/restore/#{ExBao.Operation.escape(name)}",
      opts,
      body: [:backup, :force]
    )
  end

  @doc ~S"""
  Restore the named key

  `POST /v1/transit/restore`

  ## Options

    * `:backup` (string) — Backed up key data to be restored. This should be the output from the 'backup/' endpoint.
    * `:force` (boolean) — If set and a key by the given name exists, force the restore operation and override the key. Defaults to `false`.
    * `:name` (string) — If set, this will be the name of the restored key.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-restore-key"
  @spec restore_key(ExBao.server(), keyword()) ::
          ExBao.Operation.result()
  def restore_key(server, opts \\ []) do
    ExBao.Operation.call(server, :post, "#{mount(opts)}/restore", opts,
      body: [:backup, :force, :name]
    )
  end

  @doc ~S"""
  Set a certificate chain for a key in transit

  `POST /v1/transit/keys/{name}/set-certificate`

  ## Arguments

    * `name` — Name of the key to import the certificate chain against.

  ## Options

    * `:certificate_chain` (string, required) — PEM encoded certificate chain. It should be composed by one or more concatenated PEM blocks and ordered starting from the end-entity certificate.
    * `:version` (integer) — Version of the key to import the certificate chain against.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "set-chain"
  @spec set_chain(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def set_chain(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/set-certificate",
      opts,
      body: [:certificate_chain, :version],
      required: [:certificate_chain]
    )
  end

  @doc ~S"""
  Generate a signature for input data using the named key

  `POST /v1/transit/sign/{name}`

  ## Arguments

    * `name` — The key to use

  ## Options

    * `:algorithm` (string) — Deprecated: use "hash_algorithm" instead. Defaults to `"sha2-256"`.
    * `:batch_input` (array) — Specifies a list of items for processing. When this parameter is set, any supplied 'input' or 'context' parameters will be ignored. Responses are returned in the 'batch_results' array component of the 'data' element of the response. Any batch output will preserve the order of the batch input
    * `:context` (string) — Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.
    * `:hash_algorithm` (string) — Hash algorithm to use (POST body parameter). Valid values are: * sha1 * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 * none Defaults to "sha2-256". Not valid for all key types, including ed25519. Using none requires setting prehashed=true and signature_algorithm=pkcs1v15, yielding a PKCSv1_5_NoOID instead of the usual PKCSv1_5_DERnull signature. Defaults to `"sha2-256"`.
    * `:input` (string) — The base64-encoded input data
    * `:key_version` (integer) — The version of the key to use for signing. Must be 0 (for latest) or a value greater than or equal to the min_encryption_version configured on the key.
    * `:marshaling_algorithm` (string) — The method by which to marshal the signature. The default is 'asn1' which is used by openssl and X.509. It can also be set to 'jws' which is used for JWT signatures; setting it to this will also cause the encoding of the signature to be url-safe base64 instead of using standard base64 encoding. Currently only valid for ECDSA P-256 key types". Defaults to `"asn1"`.
    * `:prehashed` (boolean) — Set to 'true' when the input is already hashed. If the key type is 'rsa-2048', 'rsa-3072' or 'rsa-4096', then the algorithm used to hash the input should be indicated by the 'algorithm' parameter.
    * `:salt_length` (string) — The salt length used to sign. Currently only applies to the RSA PSS signature scheme. Options are 'auto' (the default used by Golang, causing the salt to be as large as possible when signing), 'hash' (causes the salt length to equal the length of the hash used in the signature), or an integer between the minimum and the maximum permissible salt lengths for the given RSA key size. Defaults to 'auto'. Defaults to `"auto"`.
    * `:signature_algorithm` (string) — The signature algorithm to use for signing. Currently only applies to RSA key types. Options are 'pss' or 'pkcs1v15'. Defaults to 'pss'
    * `:urlalgorithm` (string) — Hash algorithm to use (POST URL parameter)
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-sign"
  @spec sign(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def sign(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/sign/#{ExBao.Operation.escape(name)}",
      opts,
      body: [
        :algorithm,
        :batch_input,
        :context,
        :hash_algorithm,
        :input,
        :key_version,
        :marshaling_algorithm,
        :prehashed,
        :salt_length,
        :signature_algorithm,
        :urlalgorithm
      ]
    )
  end

  @doc ~S"""
  Generate a signature for input data using the named key

  `POST /v1/transit/sign/{name}/{urlalgorithm}`

  ## Arguments

    * `name` — The key to use
    * `urlalgorithm` — Hash algorithm to use (POST URL parameter)

  ## Options

    * `:algorithm` (string) — Deprecated: use "hash_algorithm" instead. Defaults to `"sha2-256"`.
    * `:batch_input` (array) — Specifies a list of items for processing. When this parameter is set, any supplied 'input' or 'context' parameters will be ignored. Responses are returned in the 'batch_results' array component of the 'data' element of the response. Any batch output will preserve the order of the batch input
    * `:context` (string) — Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.
    * `:hash_algorithm` (string) — Hash algorithm to use (POST body parameter). Valid values are: * sha1 * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 * none Defaults to "sha2-256". Not valid for all key types, including ed25519. Using none requires setting prehashed=true and signature_algorithm=pkcs1v15, yielding a PKCSv1_5_NoOID instead of the usual PKCSv1_5_DERnull signature. Defaults to `"sha2-256"`.
    * `:input` (string) — The base64-encoded input data
    * `:key_version` (integer) — The version of the key to use for signing. Must be 0 (for latest) or a value greater than or equal to the min_encryption_version configured on the key.
    * `:marshaling_algorithm` (string) — The method by which to marshal the signature. The default is 'asn1' which is used by openssl and X.509. It can also be set to 'jws' which is used for JWT signatures; setting it to this will also cause the encoding of the signature to be url-safe base64 instead of using standard base64 encoding. Currently only valid for ECDSA P-256 key types". Defaults to `"asn1"`.
    * `:prehashed` (boolean) — Set to 'true' when the input is already hashed. If the key type is 'rsa-2048', 'rsa-3072' or 'rsa-4096', then the algorithm used to hash the input should be indicated by the 'algorithm' parameter.
    * `:salt_length` (string) — The salt length used to sign. Currently only applies to the RSA PSS signature scheme. Options are 'auto' (the default used by Golang, causing the salt to be as large as possible when signing), 'hash' (causes the salt length to equal the length of the hash used in the signature), or an integer between the minimum and the maximum permissible salt lengths for the given RSA key size. Defaults to 'auto'. Defaults to `"auto"`.
    * `:signature_algorithm` (string) — The signature algorithm to use for signing. Currently only applies to RSA key types. Options are 'pss' or 'pkcs1v15'. Defaults to 'pss'
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-sign-with-algorithm"
  @spec sign_with_algorithm(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def sign_with_algorithm(server, name, urlalgorithm, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/sign/#{ExBao.Operation.escape(name)}/#{ExBao.Operation.escape(urlalgorithm)}",
      opts,
      body: [
        :algorithm,
        :batch_input,
        :context,
        :hash_algorithm,
        :input,
        :key_version,
        :marshaling_algorithm,
        :prehashed,
        :salt_length,
        :signature_algorithm
      ]
    )
  end

  @doc ~S"""
  Managed named encryption keys

  `DELETE /v1/transit/keys/{name}/soft-delete`

  ## Arguments

    * `name` — Name of the key

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-soft-delete-key"
  @spec soft_delete_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def soft_delete_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :delete,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/soft-delete",
      opts,
      []
    )
  end

  @doc ~S"""
  Managed named encryption keys

  `POST /v1/transit/keys/{name}/soft-delete-restore`

  ## Arguments

    * `name` — Name of the key

  ## Options

    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-soft-delete-restore-key"
  @spec soft_delete_restore_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def soft_delete_restore_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/soft-delete-restore",
      opts,
      []
    )
  end

  @doc ~S"""
  Trim key versions of a named key

  `POST /v1/transit/keys/{name}/trim`

  ## Arguments

    * `name` — Name of the key

  ## Options

    * `:min_available_version` (integer) — The minimum available version for the key ring. All versions before this version will be permanently deleted. This value can at most be equal to the lesser of 'min_decryption_version' and 'min_encryption_version'. This is not allowed to be set when either 'min_encryption_version' or 'min_decryption_version' is set to zero.
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-trim-key"
  @spec trim_key(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def trim_key(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/keys/#{ExBao.Operation.escape(name)}/trim",
      opts,
      body: [:min_available_version]
    )
  end

  @doc ~S"""
  Verify a signature or HMAC for input data created using the named key

  `POST /v1/transit/verify/{name}`

  ## Arguments

    * `name` — The key to use

  ## Options

    * `:algorithm` (string) — Deprecated: use "hash_algorithm" instead. Defaults to `"sha2-256"`.
    * `:batch_input` (array) — Specifies a list of items for processing. When this parameter is set, any supplied 'input', 'hmac' or 'signature' parameters will be ignored. Responses are returned in the 'batch_results' array component of the 'data' element of the response. Any batch output will preserve the order of the batch input
    * `:context` (string) — Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.
    * `:hash_algorithm` (string) — Hash algorithm to use (POST body parameter). Valid values are: * sha1 * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 * none Defaults to "sha2-256". Not valid for all key types. See note about none on signing path. Defaults to `"sha2-256"`.
    * `:hmac` (string) — The HMAC, including OpenBao header/key version
    * `:input` (string) — The base64-encoded input data to verify
    * `:marshaling_algorithm` (string) — The method by which to unmarshal the signature when verifying. The default is 'asn1' which is used by openssl and X.509; can also be set to 'jws' which is used for JWT signatures in which case the signature is also expected to be url-safe base64 encoding instead of standard base64 encoding. Currently only valid for ECDSA P-256 key types". Defaults to `"asn1"`.
    * `:prehashed` (boolean) — Set to 'true' when the input is already hashed. If the key type is 'rsa-2048', 'rsa-3072' or 'rsa-4096', then the algorithm used to hash the input should be indicated by the 'algorithm' parameter.
    * `:salt_length` (string) — The salt length used to sign. Currently only applies to the RSA PSS signature scheme. Options are 'auto' (the default used by Golang, causing the salt to be as large as possible when signing), 'hash' (causes the salt length to equal the length of the hash used in the signature), or an integer between the minimum and the maximum permissible salt lengths for the given RSA key size. Defaults to 'auto'. Defaults to `"auto"`.
    * `:signature` (string) — The signature, including OpenBao header/key version
    * `:signature_algorithm` (string) — The signature algorithm to use for signature verification. Currently only applies to RSA key types. Options are 'pss' or 'pkcs1v15'. Defaults to 'pss'
    * `:urlalgorithm` (string) — Hash algorithm to use (POST URL parameter)
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-verify"
  @spec verify(ExBao.server(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def verify(server, name, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/verify/#{ExBao.Operation.escape(name)}",
      opts,
      body: [
        :algorithm,
        :batch_input,
        :context,
        :hash_algorithm,
        :hmac,
        :input,
        :marshaling_algorithm,
        :prehashed,
        :salt_length,
        :signature,
        :signature_algorithm,
        :urlalgorithm
      ]
    )
  end

  @doc ~S"""
  Verify a signature or HMAC for input data created using the named key

  `POST /v1/transit/verify/{name}/{urlalgorithm}`

  ## Arguments

    * `name` — The key to use
    * `urlalgorithm` — Hash algorithm to use (POST URL parameter)

  ## Options

    * `:algorithm` (string) — Deprecated: use "hash_algorithm" instead. Defaults to `"sha2-256"`.
    * `:batch_input` (array) — Specifies a list of items for processing. When this parameter is set, any supplied 'input', 'hmac' or 'signature' parameters will be ignored. Responses are returned in the 'batch_results' array component of the 'data' element of the response. Any batch output will preserve the order of the batch input
    * `:context` (string) — Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.
    * `:hash_algorithm` (string) — Hash algorithm to use (POST body parameter). Valid values are: * sha1 * sha2-224 * sha2-256 * sha2-384 * sha2-512 * sha3-224 * sha3-256 * sha3-384 * sha3-512 * none Defaults to "sha2-256". Not valid for all key types. See note about none on signing path. Defaults to `"sha2-256"`.
    * `:hmac` (string) — The HMAC, including OpenBao header/key version
    * `:input` (string) — The base64-encoded input data to verify
    * `:marshaling_algorithm` (string) — The method by which to unmarshal the signature when verifying. The default is 'asn1' which is used by openssl and X.509; can also be set to 'jws' which is used for JWT signatures in which case the signature is also expected to be url-safe base64 encoding instead of standard base64 encoding. Currently only valid for ECDSA P-256 key types". Defaults to `"asn1"`.
    * `:prehashed` (boolean) — Set to 'true' when the input is already hashed. If the key type is 'rsa-2048', 'rsa-3072' or 'rsa-4096', then the algorithm used to hash the input should be indicated by the 'algorithm' parameter.
    * `:salt_length` (string) — The salt length used to sign. Currently only applies to the RSA PSS signature scheme. Options are 'auto' (the default used by Golang, causing the salt to be as large as possible when signing), 'hash' (causes the salt length to equal the length of the hash used in the signature), or an integer between the minimum and the maximum permissible salt lengths for the given RSA key size. Defaults to 'auto'. Defaults to `"auto"`.
    * `:signature` (string) — The signature, including OpenBao header/key version
    * `:signature_algorithm` (string) — The signature algorithm to use for signature verification. Currently only applies to RSA key types. Options are 'pss' or 'pkcs1v15'. Defaults to 'pss'
    * `:mount` — where the engine is mounted, `"transit"` by default.
  """
  @operation "transit-verify-with-algorithm"
  @spec verify_with_algorithm(ExBao.server(), String.t(), String.t(), keyword()) ::
          ExBao.Operation.result()
  def verify_with_algorithm(server, name, urlalgorithm, opts \\ []) do
    ExBao.Operation.call(
      server,
      :post,
      "#{mount(opts)}/verify/#{ExBao.Operation.escape(name)}/#{ExBao.Operation.escape(urlalgorithm)}",
      opts,
      body: [
        :algorithm,
        :batch_input,
        :context,
        :hash_algorithm,
        :hmac,
        :input,
        :marshaling_algorithm,
        :prehashed,
        :salt_length,
        :signature,
        :signature_algorithm
      ]
    )
  end

  # ── end of generated ──
end
