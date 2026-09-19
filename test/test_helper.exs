# Integration tests need a real server, so they are excluded by default and a
# plain `mix test` runs anywhere, with no Docker at all. `mix test.all`
# includes them.
opts = [exclude: [:integration]]

ExUnit.start(opts)

# Testcontainers has to be started ONCE, for the whole suite, and not inside a
# `setup_all`: started there it is linked to that test process, dies with it,
# and the `on_exit` that stops the container finds nobody home.
#
# Only when integration tests are actually going to run: starting it otherwise
# would make `mix test` require Docker, which is exactly what excluding them
# by default is meant to avoid.
if :integration in (ExUnit.configuration()[:include] || []) and
     is_nil(System.get_env("BAO_TEST_ADDR")) do
  case Testcontainers.start_link() do
    {:ok, _pid} ->
      :ok

    {:error, reason} ->
      IO.puts("""

      Could not reach Docker: #{inspect(reason)}

      Integration tests start their own OpenBao and need a daemon. Either:

        * run them where the socket is — `docker compose -f docker-compose.test.yml run --rm test`
        * or point at a server you already have — BAO_TEST_ADDR=http://127.0.0.1:8200
      """)

      System.halt(1)
  end
end
