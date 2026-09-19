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

  A token that says `renewable: false` is never renewed at all: it is
  replaced by a fresh login before it expires, because asking to renew it
  would be asking for something the server already said no to.

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
  and calls made in the meantime fail with a plain `:no_token` — which is the
  truth, and is recoverable, and says what is wrong.
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

  @type name :: GenServer.server()

  # ── the public face ───────────────────────────────────────────────────────

  @doc """
  Starts the server.

  ## Options

    * `:name` — required in practice, since callers refer to it by name.
    * `:client` — an `ExBao.Client` to use instead of building one from the
      environment. Tests pass this.
    * `:auth` — `{:approle, opts}`, or `{:token, token}` for a fixed token.
      Read from configuration when absent.
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

  Returns `{:error, %ExBao.Error{kind: :permission_denied}}` when there is no
  token yet — at boot, or while re-authentication is failing.
  """
  @spec client(name()) :: {:ok, Client.t()} | {:error, Error.t()}
  def client(server), do: GenServer.call(server, :client)

  @doc """
  Forces a fresh login, discarding the current token.

  For when a secret id has been rotated underneath a running system and you
  want the new one picked up without a restart.
  """
  @spec reauthenticate(name()) :: :ok | {:error, Error.t()}
  def reauthenticate(server), do: GenServer.call(server, :reauthenticate, 30_000)

  @doc """
  What the server knows about its token. For a health check or a log line.

  Never includes the token itself: a status endpoint that returns the
  credential is a credential in every log that records the health check.
  """
  @spec status(name()) :: map()
  def status(server), do: GenServer.call(server, :status)

  # ── the process ───────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      client: opts[:client] || Client.new(),
      auth: opts[:auth] || Application.get_env(:ex_bao, :auth),
      renew_after:
        opts[:renew_after] || Application.get_env(:ex_bao, :renew_after) ||
          @default_renew_after,
      token: nil,
      expires_at: nil,
      renewable: false,
      timer: nil,
      backoff: @min_backoff,
      last_error: nil
    }

    # Authenticating in `handle_continue` and not here keeps `start_link` from
    # blocking the supervisor while a network call happens.
    {:ok, state, {:continue, :authenticate}}
  end

  @impl true
  def handle_continue(:authenticate, state), do: {:noreply, authenticate(state)}

  @impl true
  def handle_call(:client, _from, %{token: nil} = state) do
    {:reply,
     {:error, %Error{kind: :permission_denied, messages: ["no token yet: not authenticated"]}},
     state}
  end

  def handle_call(:client, _from, state) do
    {:reply, {:ok, Client.with_token(state.client, state.token)}, state}
  end

  def handle_call(:reauthenticate, _from, state) do
    state = state |> cancel_timer() |> authenticate()
    reply = if state.token, do: :ok, else: {:error, state.last_error}
    {:reply, reply, state}
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       authenticated: not is_nil(state.token),
       renewable: state.renewable,
       expires_at: state.expires_at,
       expires_in: seconds_left(state.expires_at)
     }, state}
  end

  @impl true
  def handle_info(:renew, %{renewable: true} = state) do
    case Client.request(
           Client.with_token(state.client, state.token),
           :post,
           "auth/token/renew-self",
           %{}
         ) do
      {:ok, body} ->
        {:noreply, state |> apply_auth(Auth.from_response({:ok, body})) |> schedule()}

      {:error, error} ->
        # Not a retry of the renewal: a refused renewal means this token is
        # finished, and the way out is a new one.
        Logger.warning("ex_bao: renewal refused (#{Exception.message(error)}), logging in again")
        {:noreply, authenticate(state)}
    end
  end

  # Not renewable: the only move is a fresh login.
  def handle_info(:renew, state), do: {:noreply, authenticate(state)}

  def handle_info(:retry, state), do: {:noreply, authenticate(state)}

  def handle_info(_message, state), do: {:noreply, state}

  # ── the work ──────────────────────────────────────────────────────────────

  defp authenticate(%{auth: {:token, token}} = state) do
    # A fixed token has no lease we can see and nothing to renew. It is
    # accepted because it is what a script or a dev environment has.
    %{state | token: token, renewable: false, expires_at: nil, backoff: @min_backoff}
  end

  defp authenticate(%{auth: {:approle, opts}} = state) do
    state.client
    |> AppRole.login(opts)
    |> then(&apply_auth(cancel_timer(state), &1))
    |> schedule()
  end

  defp authenticate(%{auth: nil} = state) do
    # No method configured, but the client may still carry a token straight
    # from BAO_TOKEN, which is the common shape in development.
    case state.client.token do
      nil ->
        error = %Error{kind: :invalid_credentials, messages: ["no auth method configured"]}
        %{state | token: nil, last_error: error}

      token ->
        %{state | token: token, renewable: false, expires_at: nil}
    end
  end

  defp apply_auth(state, {:ok, %Auth{} = auth}) do
    %{
      state
      | token: auth.token,
        renewable: auth.renewable,
        expires_at: expiry(auth.lease_duration),
        backoff: @min_backoff,
        last_error: nil
    }
  end

  defp apply_auth(state, {:error, %Error{} = error}) do
    Logger.warning("ex_bao: authentication failed (#{Exception.message(error)})")
    %{state | token: nil, last_error: error} |> backoff()
  end

  defp schedule(%{token: nil} = state), do: state
  defp schedule(%{expires_at: nil} = state), do: state

  defp schedule(state) do
    left = seconds_left(state.expires_at)

    if left <= 0 do
      state
    else
      # Renew after `renew_after` of what is left, never less than a second:
      # a sub-second lease would otherwise schedule a busy loop.
      after_ms = max(round(left * state.renew_after * 1000), 1_000)
      %{state | timer: Process.send_after(self(), :renew, after_ms)}
    end
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

  defp expiry(@never), do: nil
  defp expiry(seconds), do: DateTime.add(DateTime.utc_now(), seconds, :second)

  defp seconds_left(nil), do: nil
  defp seconds_left(at), do: DateTime.diff(at, DateTime.utc_now(), :second)
end
