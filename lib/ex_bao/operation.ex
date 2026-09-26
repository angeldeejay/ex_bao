defmodule ExBao.Operation do
  @moduledoc false

  # What every endpoint module needs and none of them should write twice:
  # turning a server into a client, building a path that cannot be steered
  # somewhere else, leaving out what the caller did not say, and naming a
  # response that came back in a shape nobody documented.
  #
  # Internal. The public contract is the modules built on it.

  alias ExBao.{Client, Error, TokenServer}

  @doc """
  A client from whatever the caller passed: a client as is, or the current
  one from a token server. The second is what an application uses; the first
  is what a test and a script with a root token use.
  """
  @spec resolve(ExBao.server()) :: {:ok, Client.t()} | {:error, Error.t()}
  def resolve(%Client{} = client), do: {:ok, client}
  def resolve(server), do: TokenServer.client(server)

  @doc "Resolves the server and makes the request."
  @spec request(ExBao.server(), atom(), String.t(), map() | nil) ::
          {:ok, map() | nil} | {:error, Error.t()}
  def request(server, method, path, body \\ nil) do
    with {:ok, client} <- resolve(server), do: Client.request(client, method, path, body)
  end

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
