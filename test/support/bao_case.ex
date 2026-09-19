defmodule ExBao.BaoCase do
  @moduledoc """
  For tests that talk to a real OpenBao.

  The server is **started by the suite**, not by whoever is running it.
  Testcontainers boots the image, waits until it answers, hands back the port
  Docker picked, and tears it down afterwards. Nobody has to remember a
  `docker run`, and nothing is left behind when a test crashes.

  ## Which version

  `BAO_TEST_IMAGE` picks the server, defaulting to the newest supported one.
  That single variable is the whole compatibility matrix: CI runs this suite
  once per value, and a cell is green because these tests passed against that
  exact server.

      BAO_TEST_IMAGE=openbao/openbao:2.4.4 mix test.all

  ## Which tests

  Everything here is tagged `:integration`, so a plain `mix test` skips it and
  runs anywhere with no Docker at all.

  `@tag min_bao: "2.5"` skips a test on servers older than that. It matters
  more than it looks: a feature 2.4 never had is **not** a regression, and a
  matrix that cannot tell "not yet" from "broken" is a matrix everyone learns
  to ignore.

  ## Pointing at a server you already have

  `BAO_TEST_ADDR` skips the container entirely and uses that address. For
  iterating against a long-lived server without paying the boot each run.

  ## On Windows

  Docker Desktop speaks over a named pipe rather than a Unix socket, so
  Testcontainers needs Testcontainers Desktop installed once: it writes the
  `tc.host` the library reads. After that this runs from the host like
  anywhere else. `docker-compose.test.yml` is the other way, and pins the
  Elixir version besides.
  """

  use ExUnit.CaseTemplate

  alias Testcontainers.Container

  @default_image "openbao/openbao:2.6.2"
  @root_token "testcontainers-root"
  @port 8200

  using do
    quote do
      import ExBao.BaoCase
      @moduletag :integration
    end
  end

  setup_all do
    case System.get_env("BAO_TEST_ADDR") do
      nil ->
        start_container()

      addr ->
        # The engines get mounted here too, not only on the container path. A
        # server handed to us is not necessarily prepared: in CI it is a
        # freshly started service with nothing but the dev KV mount, and
        # every test would fail on a missing `transit`.
        token = System.get_env("BAO_TEST_TOKEN", @root_token)
        :ok = enable_engines(ExBao.Client.new(addr: addr, token: token))

        {:ok, addr: addr, token: token}
    end
  end

  setup %{addr: addr, token: token} = context do
    client = ExBao.Client.new(addr: addr, token: token)
    version = server_version(client)

    if needed = context[:min_bao] do
      if older?(version, needed) do
        # Skipped, not failed. See the moduledoc: "not yet" and "broken" are
        # different answers and a matrix has to keep them apart.
        raise ExUnit.AssertionError, message: "needs OpenBao #{needed}, server is #{version}"
      end
    end

    {:ok, client: client, bao_version: version}
  end

  @doc "A key name unique to this test, so tests never collide."
  def unique_key(prefix \\ "t"), do: "#{prefix}_#{System.unique_integer([:positive])}"

  @doc false
  def server_version(client) do
    case ExBao.health(client) do
      {:ok, %{"version" => version}} -> version
      _ -> "0.0.0"
    end
  end

  @doc false
  def older?(version, needed), do: parse(version) < parse(needed)

  defp parse(version) do
    version
    |> to_string()
    |> String.split(~r/[^0-9.]/, parts: 2)
    |> hd()
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
    |> Enum.take(3)
  end

  # Testcontainers itself is started in `test_helper.exs`, once for the whole
  # suite. See the comment there: started in a `setup_all` it dies with that
  # test process, and the `on_exit` below then has nobody to ask.
  defp start_container do
    image = System.get_env("BAO_TEST_IMAGE", @default_image)

    config =
      image
      |> Container.new()
      |> Container.with_cmd(["server", "-dev"])
      |> Container.with_environment("BAO_DEV_ROOT_TOKEN_ID", @root_token)
      # Dev mode binds to 127.0.0.1 inside the container by default, which is
      # unreachable from outside it. This is what makes the mapped port work.
      |> Container.with_environment("BAO_DEV_LISTEN_ADDRESS", "0.0.0.0:#{@port}")
      |> Container.with_exposed_port(@port)
      # Wait for the server to answer, not for the process to exist: an
      # unsealed dev server takes a moment, and a test that races it fails
      # for a reason that has nothing to do with the test.
      |> Container.with_waiting_strategy(
        Testcontainers.HttpWaitStrategy.new("/v1/sys/health", @port, status_code: 200)
      )

    {:ok, container} = Testcontainers.start_container(config)

    on_exit(fn -> Testcontainers.stop_container(container.container_id) end)

    host = Testcontainers.get_host(container)
    port = Container.mapped_port(container, @port)
    addr = "http://#{host}:#{port}"

    :ok = enable_engines(ExBao.Client.new(addr: addr, token: @root_token))

    {:ok, addr: addr, token: @root_token, container: container}
  end

  # A dev server comes with KV mounted and nothing else. The suite needs the
  # same mounts every run, or the OpenAPI it reports — and therefore any diff
  # taken from it — depends on which tests happened to run first.
  defp enable_engines(client) do
    for {path, type} <- [{"transit", "transit"}, {"approle", "approle"}] do
      mount(client, path, type)
    end

    :ok
  end

  defp mount(client, path, "approle") do
    ExBao.Client.request(client, :post, "sys/auth/#{path}", %{"type" => "approle"})
  end

  defp mount(client, path, type) do
    ExBao.Client.request(client, :post, "sys/mounts/#{path}", %{"type" => type})
  end
end
