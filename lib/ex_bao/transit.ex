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
      and sealing somebody's payout details is exactly where it is.

    * **A policy that does not grant `create` on `transit/keys/*`** to the
      application. Free, and impossible to forget at a call site — but it
      belongs to whoever administers the server rather than to whoever writes
      the call.

  The first catches the typo in your own process, with an error that names
  it. The second catches it even in code that forgot to ask.
  """

  alias ExBao.{Client, Error, TokenServer}

  @type server :: Client.t() | GenServer.server()
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
      round trip; see the note on the module.
  """
  @spec encrypt(server(), key(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def encrypt(server, key, plaintext, opts \\ []) when is_binary(plaintext) do
    body =
      %{"plaintext" => Base.encode64(plaintext)}
      |> maybe_put("context", opts[:context], &Base.encode64/1)
      |> maybe_put("key_version", opts[:key_version])

    with {:ok, client} <- resolve(server),
         :ok <- ensure_exists(client, key, opts),
         {:ok, %{"data" => %{"ciphertext" => ciphertext}}} <-
           Client.request(client, :post, "transit/encrypt/#{key}", body) do
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
  @spec decrypt(server(), key(), String.t(), keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def decrypt(server, key, ciphertext, opts \\ []) when is_binary(ciphertext) do
    body =
      %{"ciphertext" => ciphertext}
      |> maybe_put("context", opts[:context], &Base.encode64/1)

    with {:ok, client} <- resolve(server),
         {:ok, %{"data" => %{"plaintext" => encoded}}} <-
           Client.request(client, :post, "transit/decrypt/#{key}", body),
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

    * `:references` — one per value, echoed back with each result.
    * `:context`, `:avoid_create_on_missing` — as in `encrypt/4`.
  """
  @spec encrypt_batch(server(), key(), [binary()], keyword()) ::
          {:ok, [result()]} | {:error, Error.t()}
  def encrypt_batch(server, key, plaintexts, opts \\ []) when is_list(plaintexts) do
    items = Enum.map(plaintexts, &%{"plaintext" => Base.encode64(&1)})

    # The same guard as `encrypt/4`, and it matters more here: a mistyped key
    # seals the whole list under the phantom one, not a single value.
    with {:ok, client} <- resolve(server),
         :ok <- ensure_exists(client, key, opts) do
      batch(client, "transit/encrypt/#{key}", items, opts, &take(&1, "ciphertext"))
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

    batch(server, "transit/decrypt/#{key}", items, opts, fn item ->
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
  @spec rotate(server(), key()) :: :ok | {:error, Error.t()}
  def rotate(server, key) do
    with {:ok, client} <- resolve(server),
         {:ok, _body} <- Client.request(client, :post, "transit/keys/#{key}/rotate", %{}) do
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
  @spec rewrap(server(), key(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def rewrap(server, key, ciphertext, opts \\ []) do
    body =
      %{"ciphertext" => ciphertext}
      |> maybe_put("context", opts[:context], &Base.encode64/1)

    with {:ok, client} <- resolve(server),
         {:ok, %{"data" => %{"ciphertext" => rewrapped}}} <-
           Client.request(client, :post, "transit/rewrap/#{key}", body) do
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
          {:ok, [String.t() | {:error, Error.t()}]} | {:error, Error.t()}
  def rewrap_batch(server, key, ciphertexts, opts \\ []) when is_list(ciphertexts) do
    items = Enum.map(ciphertexts, &%{"ciphertext" => &1})
    batch(server, "transit/rewrap/#{key}", items, opts, &take(&1, "ciphertext"))
  end

  @doc """
  Refuses to open anything sealed under a version below this one.

  Run it **after** every stored value has been rewrapped, not before: it is
  what makes a compromised old version useless, and it is also what makes
  anything you forgot to rewrap unreadable.
  """
  @spec set_min_decryption_version(server(), key(), pos_integer()) :: :ok | {:error, Error.t()}
  def set_min_decryption_version(server, key, version) when is_integer(version) do
    with {:ok, client} <- resolve(server),
         {:ok, _body} <-
           Client.request(client, :post, "transit/keys/#{key}/config", %{
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
  @spec create_key(server(), key(), keyword()) :: :ok | {:error, Error.t()}
  def create_key(server, key, opts \\ []) do
    body =
      %{"type" => opts |> Keyword.get(:type, :aes256_gcm96) |> type_name()}
      |> maybe_put("derived", opts[:derived])
      |> maybe_put("exportable", opts[:exportable])
      |> maybe_put("allow_plaintext_backup", opts[:allow_plaintext_backup])

    with {:ok, client} <- resolve(server),
         {:ok, _body} <- Client.request(client, :post, "transit/keys/#{key}", body) do
      :ok
    end
  end

  @doc """
  Reads a key's configuration. Never its material.
  """
  @spec read_key(server(), key()) :: {:ok, map()} | {:error, Error.t()}
  def read_key(server, key) do
    with {:ok, client} <- resolve(server),
         {:ok, %{"data" => data}} <- Client.request(client, :get, "transit/keys/#{key}") do
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
  @spec list_keys(server()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def list_keys(server) do
    with {:ok, client} <- resolve(server),
         {:ok, body} <- Client.request(client, :get, "transit/keys?list=true") do
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
  @spec delete_key(server(), key()) :: :ok | {:error, Error.t()}
  def delete_key(server, key) do
    with {:ok, client} <- resolve(server),
         {:ok, _body} <- Client.request(client, :delete, "transit/keys/#{key}") do
      :ok
    end
  end

  # ── plumbing ──────────────────────────────────────────────────────────────

  # A caller can pass a client directly or the name of a token server. The
  # second is what an application uses; the first is what a test uses, and
  # what a script with a root token uses.
  defp resolve(%Client{} = client), do: {:ok, client}
  defp resolve(server), do: TokenServer.client(server)

  # Reading before writing, when asked. OpenBao has no flag for this — its
  # `encrypt` creates what is missing and there is no way to tell it not to —
  # so the only way to refuse is to look first.
  #
  # Nothing is cached. A cache would have to answer "does this key still
  # exist", and that answer changes the moment an operator deletes one, which
  # is exactly when a stale "yes" would send values at a key that is gone.
  defp ensure_exists(client, key, opts) do
    if Keyword.get(opts, :avoid_create_on_missing, false) do
      with {:ok, _key} <- read_key(client, key), do: :ok
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

    with {:ok, client} <- resolve(server),
         {:ok, results} <-
           results(Client.request(client, :post, path, %{"batch_input" => items})) do
      {:ok, Enum.map(results, &label(&1, extract, opts[:references]))}
    end
  end

  defp with_context(items, nil), do: items

  defp with_context(items, context),
    do: Enum.map(items, &Map.put(&1, "context", Base.encode64(context)))

  defp with_references(items, nil), do: items

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

  defp unexpected(body) do
    %Error{
      kind: :unknown,
      status: 200,
      messages: ["unexpected response shape"],
      reason: body
    }
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
  defp maybe_put(map, _key, nil, _fun), do: map
  defp maybe_put(map, key, value, fun), do: Map.put(map, key, fun.(value))

  defp type_name(type) when is_atom(type),
    do: type |> Atom.to_string() |> String.replace("_", "-") |> fix_type()

  defp type_name(type) when is_binary(type), do: type

  # `:aes256_gcm96` reads as `aes256-gcm96`, not `aes256-gcm-96`.
  defp fix_type("aes128-gcm96"), do: "aes128-gcm96"
  defp fix_type("aes256-gcm96"), do: "aes256-gcm96"
  defp fix_type(other), do: other
end
