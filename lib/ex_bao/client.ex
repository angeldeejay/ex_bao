defmodule ExBao.Client do
  @moduledoc """
  Where the server is, and how to talk to it.

  A client is a value, not a process. It holds an address, a token and the
  options the transport needs, and it can be built, passed around and thrown
  away without anything having to be started. That matters for testing: a
  test builds one pointing at a fake server and no supervision tree has to
  be involved.

  The process that keeps a token *alive* is `ExBao.TokenServer`, and it is a
  separate thing on purpose. Not every caller needs a renewing token — a
  short script with a root token does not — and making the process mandatory
  would tax the simple case for the benefit of the complex one.

  ## Building one

      # Everything from the environment and application config.
      ExBao.Client.new()

      # Or said explicitly, which is what a test does.
      ExBao.Client.new(addr: "http://127.0.0.1:8200", token: "dev-only-root")

  ## Where configuration comes from

  In this order, first hit wins: the options passed here, then the
  environment, then application config. The environment beats application
  config so a release can be pointed somewhere else without rebuilding it,
  and explicit options beat both so a caller is never fighting the ambient
  configuration.
  """

  alias ExBao.Error

  @type t :: %__MODULE__{
          addr: String.t(),
          token: String.t() | nil,
          namespace: String.t() | nil,
          options: keyword()
        }

  @enforce_keys [:addr]
  defstruct [:addr, :token, :namespace, options: []]

  @doc """
  Builds a client.

  ## Options

    * `:addr` — the server's base URL. From `BAO_ADDR` otherwise.
    * `:token` — a token to send. From `BAO_TOKEN` otherwise.
    * `:namespace` — sent as `X-Vault-Namespace`. From `BAO_NAMESPACE`.
    * `:verify` — `false` turns off certificate verification for **this**
      client. There is deliberately no global switch: a test that needs a
      self-signed certificate should not be able to disable verification for
      production by setting one value in the wrong config file.
    * anything else is handed to `Req`, so `:receive_timeout`, `:retry` and
      `:connect_options` work exactly as documented there.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    {known, rest} = Keyword.split(opts, [:addr, :token, :namespace, :verify])

    %__MODULE__{
      addr: known |> setting(:addr, "BAO_ADDR") |> normalize_addr(),
      token: setting(known, :token, "BAO_TOKEN"),
      namespace: setting(known, :namespace, "BAO_NAMESPACE"),
      options: transport_options(known, rest)
    }
  end

  @doc """
  The same client with a different token.

  Used by `ExBao.TokenServer` after a login or a renewal: the address and the
  transport options are settled once, and only the token moves.
  """
  @spec with_token(t(), String.t()) :: t()
  def with_token(%__MODULE__{} = client, token), do: %{client | token: token}

  @doc false
  @spec request(t(), atom(), String.t(), map() | nil) ::
          {:ok, map() | nil} | {:error, Error.t()}
  def request(%__MODULE__{} = client, method, path, body \\ nil) do
    [
      method: method,
      url: url(client, path),
      headers: headers(client),
      json: body
    ]
    |> Keyword.merge(client.options)
    # `json: nil` would send a literal `null` body, which OpenBao rejects on
    # endpoints that take no parameters.
    |> Keyword.reject(fn {k, v} -> k == :json and is_nil(v) end)
    |> request_safely()
    |> handle()
  end

  # `Req.request/1` can RAISE, not just answer `{:error, reason}` — a bad
  # option, a plug that blew up, a transport that failed in a way Req does
  # not wrap. Uncaught, that takes down whatever called it, and what calls it
  # is usually `ExBao.TokenServer`, whose whole job is to survive the server
  # being unavailable. A crash there turns a dependency being down into a
  # supervision tree restarting.
  #
  # So everything comes back as a value. A raise is still an error, and it
  # still says what happened — it just stops being a way to kill the caller.
  defp request_safely(options) do
    Req.request(options)
  rescue
    exception -> {:error, exception}
  catch
    :exit, reason -> {:error, {:exit, reason}}
  end

  # 204 is a real answer with nothing in it — a successful write that returns
  # no data — and it has to be told apart from a body we failed to parse.
  defp handle({:ok, %Req.Response{status: 204}}), do: {:ok, nil}
  defp handle({:ok, %Req.Response{status: s, body: body}}) when s in 200..299, do: {:ok, body}

  defp handle({:ok, %Req.Response{status: s, body: body}}),
    do: {:error, Error.from_response(s, body)}

  defp handle({:error, reason}), do: {:error, Error.from_transport(reason)}

  defp url(%__MODULE__{addr: addr}, path), do: addr <> "/v1/" <> String.trim_leading(path, "/")

  defp headers(%__MODULE__{} = client) do
    # `X-Vault-Token`, not `X-Bao-Token`: OpenBao kept the header name when it
    # forked, and a client that invents a nicer one does not authenticate.
    [{"x-vault-token", client.token}, {"x-vault-namespace", client.namespace}]
    |> Enum.reject(fn {_name, value} -> is_nil(value) end)
  end

  defp transport_options(known, rest) do
    base = Application.get_all_env(:ex_bao) |> Keyword.take(transport_keys())

    base
    |> Keyword.merge(rest)
    |> maybe_unverified(Keyword.get(known, :verify, true))
  end

  defp transport_keys,
    do: [:receive_timeout, :pool_timeout, :retry, :connect_options, :max_retries]

  defp maybe_unverified(options, true), do: options

  defp maybe_unverified(options, false) do
    connect = Keyword.get(options, :connect_options, [])
    transport = Keyword.get(connect, :transport_opts, [])

    Keyword.put(
      options,
      :connect_options,
      Keyword.put(connect, :transport_opts, Keyword.put(transport, :verify, :verify_none))
    )
  end

  defp setting(opts, key, env_var) do
    with nil <- Keyword.get(opts, key),
         nil <- System.get_env(env_var) do
      Application.get_env(:ex_bao, key)
    end
  end

  # An address with a trailing slash would build `//v1/...`, which some
  # proxies answer and others reject. Trimming it here means no caller has to
  # remember, and the two spellings behave the same.
  defp normalize_addr(nil) do
    raise ArgumentError, """
    ExBao has no server address.

    Set BAO_ADDR, or config :ex_bao, addr: "https://...", or pass it:

        ExBao.Client.new(addr: "https://bao.internal:8200")
    """
  end

  defp normalize_addr(addr) when is_binary(addr), do: String.trim_trailing(addr, "/")
end
