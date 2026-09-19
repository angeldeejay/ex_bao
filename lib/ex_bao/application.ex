defmodule ExBao.Application do
  @moduledoc """
  Starts nothing by default.

  A library that starts a connection on load decides for its host when to
  authenticate and what to do when that fails. `ExBao.TokenServer` goes in
  *your* supervision tree, where you choose its place, its name and what
  happens when it restarts.
  """

  use Application

  @impl true
  def start(_type, _args) do
    Supervisor.start_link([], strategy: :one_for_one, name: ExBao.Supervisor)
  end
end
