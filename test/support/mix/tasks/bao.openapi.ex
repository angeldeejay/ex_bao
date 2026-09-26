defmodule Mix.Tasks.Bao.Openapi do
  @shortdoc "Captures a server's OpenAPI specification"

  @moduledoc """
  Asks an OpenBao for its own OpenAPI specification and writes it down.

      mix bao.openapi --out priv/openapi/2.6.2.json

  ## Why this exists

  The compatibility matrix says **what broke**. This says **what changed**,
  and they are different questions: a new optional parameter changes the
  specification and breaks nothing, while a change in behaviour breaks things
  without touching the specification at all.

  So a diff here is a *trigger*, never a diagnosis. It says which tests to
  look at when a new OpenBao lands. The tests say whether anything is wrong.

  ## Why it is committed

  A specification fetched into a temporary file can only answer "did it
  fail". One committed under `priv/openapi/` turns the change into a diff in
  a pull request: this path is new, this parameter is gone, this type moved.
  That is a list of work rather than an alarm.

  ## Why the token matters

  **The specification is filtered by the token's policies.** Asked without
  one, OpenBao answers a well-formed document describing nothing: zero paths,
  zero schemas. It does not fail, which is what makes it dangerous — a
  capture that silently produced an empty file would land in the repository
  and the next diff would read as "every path was removed".

  So this task refuses a specification with no paths rather than write it.

  ## Why the mounts matter

  What the server reports depends on which engines are mounted: an engine
  that is not mounted is not described at all. So this task mounts every
  engine and auth method OpenBao ships built in, each at its default path,
  before asking. The specification is then the whole API, and the modules
  generated from it by `mix bao.gen` cover the whole client.

  The set is fixed here rather than read from the server's plugin catalog,
  so a new built-in in a release shows up as a line to add in review, not
  as a silent change in what gets generated.

  ## Options

    * `--out` — where to write it. Required.
    * `--addr` — a server that is already running. Without it, one is started
      from `BAO_TEST_IMAGE` and stopped afterwards.
  """

  use Mix.Task

  @requirements ["app.start"]

  # Lives under `test/support` rather than `lib`: it needs Testcontainers,
  # which is a test dependency, and a Mix task in `lib` compiles in every
  # environment — including the one a user of this library builds in, where
  # that module does not exist. `mix.exs` maps it to MIX_ENV=test.

  @impl Mix.Task
  def run(argv) do
    {opts, _rest} = OptionParser.parse!(argv, strict: [out: :string, addr: :string])

    out = opts[:out] || Mix.raise("--out is required")

    {client, stop} = server(opts[:addr])

    try do
      spec = fetch!(client)
      File.mkdir_p!(Path.dirname(out))
      File.write!(out, spec)

      Mix.shell().info("wrote #{out} (#{byte_size(spec)} bytes, #{count(spec)} paths)")
    after
      stop.()
    end
  end

  defp server(nil) do
    image = System.get_env("BAO_TEST_IMAGE", "openbao/openbao:latest")
    Mix.shell().info("starting #{image}")

    {:ok, _} = Application.ensure_all_started(:testcontainers)
    {:ok, _} = Testcontainers.start_link()

    config =
      image
      |> Testcontainers.Container.new()
      |> Testcontainers.Container.with_cmd(["server", "-dev"])
      |> Testcontainers.Container.with_environment("BAO_DEV_ROOT_TOKEN_ID", "openapi-root")
      |> Testcontainers.Container.with_environment("BAO_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
      |> Testcontainers.Container.with_exposed_port(8200)
      |> Testcontainers.Container.with_waiting_strategy(
        Testcontainers.HttpWaitStrategy.new("/v1/sys/health", 8200, status_code: 200)
      )

    {:ok, container} = Testcontainers.start_container(config)

    host = Testcontainers.get_host(container)
    port = Testcontainers.Container.mapped_port(container, 8200)
    client = ExBao.Client.new(addr: "http://#{host}:#{port}", token: "openapi-root")

    mount_engines(client)

    {client, fn -> Testcontainers.stop_container(container.container_id) end}
  end

  defp server(addr) do
    token =
      System.get_env("BAO_TOKEN") || System.get_env("BAO_TEST_TOKEN") ||
        Mix.raise("""
        No token.

        The specification is filtered by the token's policies, so without one
        the server answers an empty document. Set BAO_TOKEN to a token that
        can see what you want captured — a root token, normally.
        """)

    client = ExBao.Client.new(addr: addr, token: token)
    mount_engines(client)
    {client, fn -> :ok end}
  end

  # Every built-in of 2.6.2, at its default path. `oidc` is left out: it is
  # the `jwt` plugin under another name and describes the same endpoints.
  # `openldap` likewise is `ldap`. KV is mounted twice, because its two
  # versions are different APIs: version 2 is the dev server's `secret/`,
  # version 1 goes at `kv/`.
  #
  # A mount that already exists answers 400 and is left as it is, so this
  # can run against a server that the test suite has already prepared.
  @auth_methods ~w(approle cert jwt kerberos kubernetes ldap radius userpass)
  @secret_engines ~w(transit pki ssh totp database rabbitmq kubernetes ldap)

  defp mount_engines(client) do
    for type <- @auth_methods do
      ExBao.Client.request(client, :post, "sys/auth/#{type}", %{"type" => type})
    end

    for type <- @secret_engines do
      ExBao.Client.request(client, :post, "sys/mounts/#{type}", %{"type" => type})
    end

    ExBao.Client.request(client, :post, "sys/mounts/kv", %{
      "type" => "kv",
      "options" => %{"version" => "1"}
    })

    :ok
  end

  defp fetch!(client) do
    case ExBao.Client.request(client, :get, "sys/internal/specs/openapi") do
      {:ok, %{"paths" => paths} = spec} when map_size(paths) > 0 ->
        # Pretty-printed, because the whole point is to read the diff. A
        # single-line JSON blob changes entirely whenever anything moves.
        # And sorted, for the same reason: a map with more than 32 keys has
        # no stable order, so one more mounted engine reshuffled the whole
        # file and buried the change that mattered.
        spec |> sorted() |> Jason.encode!(pretty: true)

      {:ok, _empty} ->
        Mix.raise("""
        The server described nothing: zero paths.

        That is what a token without policies sees. Writing it would put an
        empty specification in the repository and make the next diff read as
        if every path had been removed.
        """)

      {:error, error} ->
        Mix.raise("could not read the specification: #{Exception.message(error)}")
    end
  end

  @doc false
  def sorted(%{} = map) do
    map
    |> Enum.sort_by(fn {key, _value} -> key end)
    |> Enum.map(fn {key, value} -> {key, sorted(value)} end)
    |> Jason.OrderedObject.new()
  end

  def sorted(list) when is_list(list), do: Enum.map(list, &sorted/1)
  def sorted(value), do: value

  defp count(spec) do
    spec |> Jason.decode!() |> Map.get("paths", %{}) |> map_size()
  end
end
