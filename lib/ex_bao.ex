defmodule ExBao do
  @moduledoc """
  An OpenBao client for Elixir.

  Start here:

    * `ExBao.TokenServer` — authenticates and keeps the token alive. Put it in
      your supervision tree and hand its name to everything else.
    * `ExBao.Transit` — seal and open values without ever holding the key.
    * `ExBao.Auth.AppRole` — how a service authenticates.
    * `ExBao.Client` — where the server is. A value, not a process.
    * `ExBao.Error` — what went wrong, in a shape you can match on.

  ## The short version

      # in your supervision tree
      {ExBao.TokenServer, name: MyApp.Bao}

      # anywhere
      {:ok, sealed} = ExBao.Transit.encrypt(MyApp.Bao, "payout", "00912345620")
      {:ok, "00912345620"} = ExBao.Transit.decrypt(MyApp.Bao, "payout", sealed)
  """

  @doc """
  Whether the server is up, unsealed and answering.

  Takes a client rather than a token server: a health check has to work
  before anything is authenticated, and this endpoint needs no token.
  """
  @spec health(ExBao.Client.t()) :: {:ok, map()} | {:error, ExBao.Error.t()}
  def health(%ExBao.Client{} = client) do
    case ExBao.Client.request(client, :get, "sys/health") do
      {:ok, body} ->
        {:ok, body}

      # A server that is up but not active answers with a non-2xx status and
      # a real body: 429 standby, 472 disaster-recovery secondary, 473
      # performance standby, 474 standby that cannot reach its active node,
      # 501 not initialised, 503 sealed. That is a health *answer*, not a
      # failed request, so it is reported as one. Any other status is not
      # something `sys/health` says about itself, and stays an error.
      {:error, %ExBao.Error{status: status, reason: body}}
      when is_map(body) and status in [429, 472, 473, 474, 501, 503] ->
        {:ok, body}

      {:error, error} ->
        {:error, error}
    end
  end
end
