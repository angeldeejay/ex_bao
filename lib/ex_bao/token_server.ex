defmodule ExBao.TokenServer do
  @moduledoc """
  Holds a token and keeps it alive, so nothing else has to know one exists.

  This is the piece that makes this a client and not a folder of HTTP calls.
  Everything else here maps one function onto one endpoint; this owns a
  lifecycle.

  ## What it does

  It authenticates on start, then renews **before** the lease runs out rather
  than when it does. `renew_after: 0.7` on a sixty second lease renews at
  forty-two seconds, which leaves room for an attempt to fail and be retried
  while the current token is still valid. Renewing on expiry leaves no room
  for anything: the first failure is an outage.

  If a renewal is refused, it logs in again from scratch. That case is not
  hypothetical — a token can be revoked by an operator, and a loop that only
  knows how to renew will keep asking about a token that is never coming
  back. A renewal failure means *get a new token*, not *try that one again*.

  A renewal that answers but does not move the expiry is treated the same
  way. A token that has reached its maximum TTL keeps "renewing" successfully
  while its lease shrinks to nothing, and the only way past that ceiling is a
  new login.

  A token that says `renewable: false` is never renewed at all: it is
  replaced by a fresh login before it expires, because asking to renew it
  would be asking for something the server already said no to.

  ## When a new login fails

  The current token is kept for as long as it is still valid, and the login
  is retried with a backoff. Renewing early exists to leave room for exactly
  this: an OpenBao that is briefly unreachable at the moment of renewal
  should not cost the application a token that has minutes left in it. The
  one exception is a token the server has refused outright — that one is
  dropped, because it is known not to work.

  ## Nothing waits behind the network

  Logins and renewals run in a separate task, so the server keeps answering
  while one is in flight. A caller that asks for a client while a usable
  token exists gets it at once; a caller that asks while there is none, and a
  login is under way, waits for that login rather than failing a moment
  before it would have succeeded.

  ## What it does not do

  It does not cache secrets. Caching means deciding when to stop trusting the
  cache, and that decision belongs to whoever knows what the value is for — a
  key that rotates yearly and a credential that rotates hourly do not want
  the same answer, and this process has no way to tell them apart.

  ## Using it

      children = [{ExBao.TokenServer, name: MyApp.Bao}]

  Then hand the name to anything that takes a client:

      ExBao.Transit.encrypt(MyApp.Bao, "payout", "00912345620")

  ## When the server is down at boot

  It starts anyway. An application that refuses to boot because OpenBao is
  unreachable turns a dependency being briefly down into an outage of its
  own, and a restart loop at the top of a supervision tree can take the whole
  node with it. Instead it starts unauthenticated, retries with a backoff,
  and calls made in the meantime fail with `kind: :no_token` — which is the
  truth, is recoverable, and says what is wrong.
  """

  use GenServer

  require Logger

  alias ExBao.{Auth, Client, Error}
  alias ExBao.Auth.AppRole

  @default_renew_after 0.7
  @min_backoff 1_000
  @max_backoff 60_000
  # A lease of zero means "does not expire" (a root token). Nothing to renew,
  # so it is left alone rather than renewed in a tight loop.
  @never 0
  # How long `client/1` waits for a login that is already in flight. Longer
  # than Req's own receive timeout, so a slow login answers before this does.
  @default_wait 30_000

  @type name :: GenServer.server()

  # ── the public face ───────────────────────────────────────────────────────

  @doc """
  Starts the server.

  ## Options

    * `:name` — required in practice, since callers refer to it by name.
    * `:client` — an `ExBao.Client` to use instead of building one from the
      environment. Tests pass this.
    * `:auth` — `{:approle, opts}`, or `{:token, token}` for a fixed token.
      When absent, in this order: `BAO_TOKEN`, then `BAO_ROLE_ID` with
      `BAO_SECRET_ID`, then `config :ex_bao, auth:`, then a token the client
      already carries.
    * `:renew_after` — fraction of the lease to spend before renewing.
      Defaults to `0.7`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  The current client, token included, for making a request.

  Answers at once while a usable token exists. When there is none but a
  login is in flight — at boot, typically — it waits up to `timeout`
  milliseconds for that login to finish.

  Returns `{:error, %ExBao.Error{kind: :no_token}}` when there is no token to
  give: the login failed, or no authentication method is configured. The
  failure that caused it, if any, is in `:reason`.
  """
  @spec client(name(), timeout()) :: {:ok, Client.t()} | {:error, Error.t()}
  def client(server, timeout \\ @default_wait), do: GenServer.call(server, :client, timeout)

  @doc """
  Forces a fresh login.

  For when a secret id has been rotated underneath a running system and you
  want the new one picked up without a restart. If the login fails, the
  current token stays in use while it is still valid.
  """
  @spec reauthenticate(name()) :: :ok | {:error, Error.t()}
  def reauthenticate(server), do: GenServer.call(server, :reauthenticate, @default_wait)

  @doc """
  What the server knows about its token. For a health check or a log line.

  Never waits on the network: a health check that hangs because OpenBao does
  is a health check that reports the wrong thing. `authenticating: true`
  means a login is in flight.

  Never includes the token itself: a status endpoint that returns the
  credential is a credential in every log that records the health check.
  """
  @spec status(name()) :: map()
  def status(server), do: GenServer.call(server, :status)

  # ── the process ───────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    client = opts[:client] || Client.new()

    state = %{
      client: client,
      auth: opts[:auth] || default_auth(client),
      renew_after:
        opts[:renew_after] || Application.get_env(:ex_bao, :renew_after) ||
          @default_renew_after,
      token: nil,
      expires_at: nil,
      renewable: false,
      timer: nil,
      backoff: @min_backoff,
      last_error: nil,
      # The login or renewal in flight, as `{%Task{}, :login | :renew}`.
      task: nil,
      # Callers of `reauthenticate/1`, answered when the login finishes.
      reauth_waiters: [],
      # Callers of `client/1` that arrived with no usable token.
      client_waiters: []
    }

    # Not here: `init` blocks the supervisor, and a network call does not
    # belong in the way of a whole tree starting.
    {:ok, state, {:continue, :authenticate}}
  end

  @impl true
  def handle_continue(:authenticate, state), do: {:noreply, login(state)}

  @impl true
  def handle_call(:client, from, state) do
    cond do
      usable?(state) -> {:reply, {:ok, Client.with_token(state.client, state.token)}, state}
      logging_in?(state) -> {:noreply, %{state | client_waiters: [from | state.client_waiters]}}
      true -> {:reply, {:error, no_token(state)}, state}
    end
  end

  def handle_call(:reauthenticate, from, state) do
    state =
      %{state | reauth_waiters: [from | state.reauth_waiters]}
      |> cancel_timer()
      |> cancel_renewal()
      |> login()

    {:noreply, state}
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       authenticated: usable?(state),
       authenticating: logging_in?(state),
       renewable: state.renewable,
       expires_at: state.expires_at,
       expires_in: seconds_left(state.expires_at)
     }, state}
  end

  @impl true
  def handle_info(:renew, %{renewable: true} = state), do: {:noreply, renew(state)}
  # Not renewable: the only move is a fresh login.
  def handle_info(:renew, state), do: {:noreply, login(state)}
  def handle_info(:retry, state), do: {:noreply, login(state)}

  def handle_info({ref, result}, %{task: {%Task{ref: ref}, kind}} = state) do
    Process.demonitor(ref, [:flush])
    {:noreply, finished(%{state | task: nil}, kind, result)}
  end

  # The work never raises — `Client.request/4` turns every failure into a
  # value — so this is a crash nobody planned for. It is still only a failed
  # attempt, and is handled as one rather than taking this process with it.
  def handle_info({:DOWN, ref, :process, _pid, reason}, %{task: {%Task{ref: ref}, kind}} = state) do
    error = %Error{kind: :unknown, messages: ["#{kind} crashed"], reason: reason}
    {:noreply, finished(%{state | task: nil}, kind, {:error, error})}
  end

  def handle_info(_message, state), do: {:noreply, state}

  # ── the work ──────────────────────────────────────────────────────────────

  # Explicit options, then the environment, then application config. The
  # environment beats config so a release can be pointed elsewhere without a
  # rebuild — the same order `ExBao.Client` resolves the address in.
  defp default_auth(client) do
    cond do
      token = System.get_env("BAO_TOKEN") -> {:token, token}
      System.get_env("BAO_ROLE_ID") -> {:approle, []}
      auth = Application.get_env(:ex_bao, :auth) -> auth
      client.token -> {:token, client.token}
      true -> nil
    end
  end

  # A fixed token has no lease we can see and nothing to renew. It is accepted
  # because it is what a script or a dev environment has. No network, so no
  # task.
  defp login(%{auth: {:token, token}} = state) do
    %{state | token: token, renewable: false, expires_at: nil, backoff: @min_backoff}
    |> reply_all(:ok)
  end

  defp login(%{auth: nil} = state) do
    error = %Error{kind: :invalid_credentials, messages: ["no auth method configured"]}
    %{state | last_error: error} |> reply_all({:error, error})
  end

  # One login at a time: a second request joins the one in flight.
  defp login(%{task: {_task, :login}} = state), do: state

  defp login(%{auth: {:approle, opts}} = state) do
    client = state.client
    start(cancel_renewal(state), :login, fn -> AppRole.login(client, opts) end)
  end

  defp renew(%{task: {_task, _kind}} = state), do: state

  defp renew(state) do
    client = Client.with_token(state.client, state.token)

    start(state, :renew, fn ->
      client |> Client.request(:post, "auth/token/renew-self", %{}) |> Auth.from_response()
    end)
  end

  defp start(state, kind, fun) do
    task = Task.Supervisor.async_nolink(ExBao.TaskSupervisor, fun)
    %{state | task: {task, kind}, timer: nil}
  end

  defp finished(state, :login, {:ok, %Auth{} = auth}) do
    state |> apply_auth(auth) |> schedule() |> reply_all(:ok)
  end

  defp finished(state, :login, {:error, %Error{} = error}) do
    Logger.warning("ex_bao: authentication failed (#{Exception.message(error)})")

    %{state | last_error: error}
    |> drop_if_expired()
    |> backoff()
    |> reply_all({:error, error})
  end

  defp finished(state, :renew, {:ok, %Auth{} = auth}) do
    if extends?(state, auth) do
      state |> apply_auth(auth) |> schedule()
    else
      # At its maximum TTL a token keeps renewing "successfully" with a lease
      # that no longer grows, down to zero — which would then read as "never
      # expires" and leave a dead token in place for good.
      Logger.info("ex_bao: token reached its maximum TTL, logging in again")
      login(state)
    end
  end

  # Refused outright: the token is finished and is dropped. Anything else —
  # the server unreachable, a 500 — says nothing about the token, which is
  # kept while it lasts. Either way the answer is a new one.
  defp finished(state, :renew, {:error, %Error{} = error}) do
    Logger.warning("ex_bao: renewal failed (#{Exception.message(error)}), logging in again")

    state =
      if error.kind == :permission_denied,
        do: %{state | token: nil, expires_at: nil},
        else: state

    login(state)
  end

  defp apply_auth(state, %Auth{} = auth) do
    %{
      state
      | token: auth.token,
        renewable: auth.renewable,
        expires_at: expiry(auth.lease_duration),
        backoff: @min_backoff,
        last_error: nil
    }
  end

  # A renewal that does not push the expiry out has not bought anything.
  defp extends?(%{expires_at: nil}, _auth), do: true
  defp extends?(_state, %Auth{lease_duration: @never}), do: false

  defp extends?(state, %Auth{lease_duration: seconds}),
    do: DateTime.diff(expiry(seconds), state.expires_at, :second) > 0

  defp schedule(%{token: nil} = state), do: state
  defp schedule(%{expires_at: nil} = state), do: state

  defp schedule(state) do
    left = max(seconds_left(state.expires_at), 0)
    # Renew after `renew_after` of what is left, never less than a second: a
    # sub-second lease would otherwise schedule a busy loop.
    after_ms = max(round(left * state.renew_after * 1000), 1_000)
    %{state | timer: Process.send_after(self(), :renew, after_ms)}
  end

  defp backoff(state) do
    timer = Process.send_after(self(), :retry, state.backoff)
    %{state | timer: timer, backoff: min(state.backoff * 2, @max_backoff)}
  end

  defp cancel_timer(%{timer: nil} = state), do: state

  defp cancel_timer(%{timer: timer} = state) do
    Process.cancel_timer(timer)
    %{state | timer: nil}
  end

  # A renewal in flight would land after a forced login and overwrite it.
  defp cancel_renewal(%{task: {task, :renew}} = state) do
    Task.shutdown(task, :brutal_kill)
    %{state | task: nil}
  end

  defp cancel_renewal(state), do: state

  defp drop_if_expired(state) do
    if usable?(state), do: state, else: %{state | token: nil, expires_at: nil}
  end

  defp reply_all(state, reauth_reply) do
    Enum.each(state.reauth_waiters, &GenServer.reply(&1, reauth_reply))

    client_reply =
      if usable?(state),
        do: {:ok, Client.with_token(state.client, state.token)},
        else: {:error, no_token(state)}

    Enum.each(state.client_waiters, &GenServer.reply(&1, client_reply))

    %{state | reauth_waiters: [], client_waiters: []}
  end

  defp usable?(%{token: nil}), do: false
  defp usable?(%{expires_at: nil}), do: true
  defp usable?(%{expires_at: at}), do: DateTime.compare(at, DateTime.utc_now()) == :gt

  defp logging_in?(%{task: {_task, :login}}), do: true
  defp logging_in?(_state), do: false

  defp no_token(state) do
    %Error{kind: :no_token, messages: ["no token: not authenticated"], reason: state.last_error}
  end

  defp expiry(@never), do: nil
  defp expiry(seconds), do: DateTime.add(DateTime.utc_now(), seconds, :second)

  defp seconds_left(nil), do: nil
  defp seconds_left(at), do: DateTime.diff(at, DateTime.utc_now(), :second)
end
