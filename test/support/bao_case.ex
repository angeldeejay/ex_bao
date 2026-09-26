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

  setup %{addr: addr, token: token} do
    client = ExBao.Client.new(addr: addr, token: token)
    {:ok, client: client, bao_version: server_version(client)}
  end

  @doc """
  A name unique to this test, so tests never collide.

  Unique across runs too, not only within one. `System.unique_integer/1`
  restarts with the VM, so on a server that outlives the suite — the one
  `BAO_TEST_ADDR` points at — a second run would be handed the names of
  the first, along with whatever the first did to them: a key already
  rotated twice makes "raise the minimum version to 2" lock nothing out.
  """
  def unique_key(prefix \\ "t") do
    "#{prefix}_#{run_id()}_#{System.unique_integer([:positive])}"
  end

  defp run_id do
    case :persistent_term.get({__MODULE__, :run_id}, nil) do
      nil ->
        id = 4 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
        :persistent_term.put({__MODULE__, :run_id}, id)
        id

      id ->
        id
    end
  end

  @doc """
  Deletes a Transit key, which the server refuses until the key says it
  may be deleted. Without the first step, cleaning up only looks like it
  happens.
  """
  def delete_transit_key(client, key) do
    {:ok, _} = ExBao.Transit.configure_key(client, key, deletion_allowed: true)
    :ok = ExBao.Transit.delete_key(client, key)
  end

  @doc false
  def server_version(client) do
    case ExBao.health(client) do
      {:ok, %{"version" => version}} -> version
      _ -> "0.0.0"
    end
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
