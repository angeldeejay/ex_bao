defmodule ExBao.Operation do
  @moduledoc false

  # What every endpoint module needs and none of them should write twice:
  # turning a server into a client, building a path that cannot be steered
  # somewhere else, leaving out what the caller did not say, and naming a
  # response that came back in a shape nobody documented.
  #
  # Internal. The public contract is the modules built on it.

  alias ExBao.{Client, Error, TokenServer}

  @typedoc "What every generated operation answers."
  @type result :: {:ok, map() | String.t() | nil} | {:error, Error.t()}

  # `@operation "<operationId>"` above a function says which endpoint of
  # the OpenAPI specification it covers. Persisted, so a test can hold the
  # modules to the specification: every operation it lists is covered by
  # something, generated or written by hand.
  defmacro __using__(_opts) do
    quote do
      Module.register_attribute(__MODULE__, :operation, accumulate: true, persist: true)
    end
  end

  @doc """
  A client from whatever the caller passed: a client as is, or the current
  one from a token server. The second is what an application uses; the first
  is what a test and a script with a root token use.
  """
  @spec resolve(ExBao.server()) :: {:ok, Client.t()} | {:error, Error.t()}
  def resolve(%Client{} = client), do: {:ok, client}
  def resolve(server), do: TokenServer.client(server)

  @doc "Resolves the server and makes the request."
  @spec request(ExBao.server(), atom(), String.t(), map() | nil) :: result()
  def request(server, method, path, body \\ nil) do
    with {:ok, client} <- resolve(server), do: Client.request(client, method, path, body)
  end

  @doc """
  Makes one generated operation.

  `opts` is what the caller passed: `:mount`, which the path already
  accounts for, and the operation's own fields. `spec` says which fields
  exist and where they go:

    * `:body` / `:query` — the field names the operation accepts.
    * `:required` — the ones it cannot do without.
    * `:fixed_query` — sent every time, as `list=true` on a LIST.
    * `:content_type` — when the endpoint wants something other than JSON.

  A field the operation does not know, or a required one left out, raises
  `ArgumentError` before anything is sent: a typo in an option name is a
  bug in the caller, and the server would at best ignore it silently.
  """
  @spec call(ExBao.server(), atom(), String.t(), keyword(), keyword()) :: result()
  def call(server, method, path, opts, spec) do
    opts = Keyword.delete(opts, :mount)
    body_fields = Keyword.get(spec, :body, [])
    query_fields = Keyword.get(spec, :query, [])

    check!(opts, body_fields ++ query_fields, Keyword.get(spec, :required, []), path)

    {query, body} = Enum.split_with(opts, fn {key, _value} -> key in query_fields end)

    query =
      spec
      |> Keyword.get(:fixed_query, %{})
      |> Map.merge(Map.new(query, fn {key, value} -> {Atom.to_string(key), to_string(value)} end))

    path = if query == %{}, do: path, else: path <> "?" <> URI.encode_query(query)
    body = if method in [:get, :delete], do: nil, else: Map.new(body, &stringify_key/1)
    headers = if type = spec[:content_type], do: [{"content-type", type}], else: []

    with {:ok, client} <- resolve(server), do: Client.request(client, method, path, body, headers)
  end

  defp check!(opts, known, required, path) do
    case Keyword.keys(opts) -- known do
      [] ->
        :ok

      unknown ->
        raise ArgumentError,
              "unknown option(s) #{inspect(unknown)} for #{path}. " <>
                "It accepts :mount and #{inspect(known)}"
    end

    case required -- Keyword.keys(opts) do
      [] -> :ok
      missing -> raise ArgumentError, "missing required option(s) #{inspect(missing)} for #{path}"
    end
  end

  defp stringify_key({key, value}), do: {Atom.to_string(key), value}

  @doc """
  Where an engine is mounted: `:mount` from the options, or the default the
  engine is usually mounted at. Slashes at either end are dropped, so
  `"transit/"` and `"/transit"` mean the same mount. Inner ones are kept: a
  mount can be nested, `"team/transit"`.
  """
  @spec mount(keyword(), String.t()) :: String.t()
  def mount(opts, default), do: opts |> Keyword.get(:mount, default) |> String.trim("/")

  @doc """
  One path segment, escaped. A name from user input must not be able to
  address a different endpoint with a stray `/`, `?` or `..`.
  """
  @spec escape(String.t() | atom() | integer()) :: String.t()
  def escape(segment), do: segment |> to_string() |> URI.encode(&URI.char_unreserved?/1)

  @doc """
  A path that is allowed to have slashes — a KV secret, say. Each segment is
  escaped on its own and the slashes between them are kept.
  """
  @spec escape_path(String.t()) :: String.t()
  def escape_path(path) do
    path |> String.trim("/") |> String.split("/") |> Enum.map_join("/", &escape/1)
  end

  @doc "Puts `value` under `key` unless it is `nil`, which means *not said*."
  @spec put(map(), String.t(), term()) :: map()
  def put(map, _key, nil), do: map
  def put(map, key, value), do: Map.put(map, key, value)

  @doc "As `put/3`, transforming the value first."
  @spec put(map(), String.t(), term(), (term() -> term())) :: map()
  def put(map, _key, nil, _fun), do: map
  def put(map, key, value, fun), do: Map.put(map, key, fun.(value))

  @doc """
  A 2xx whose body is not what the endpoint documents. Reported rather than
  guessed at: a wrong shape handed on as data fails later, somewhere with no
  clue about where it came from.
  """
  @spec unexpected(term()) :: Error.t()
  def unexpected(body) do
    %Error{kind: :unknown, status: 200, messages: ["unexpected response shape"], reason: body}
  end
end
