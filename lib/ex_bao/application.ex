defmodule ExBao.Application do
  @moduledoc """
  Starts no connection.

  A library that authenticates on load decides for its host when to do it
  and what to do when that fails. `ExBao.TokenServer` goes in *your*
  supervision tree, where you choose its place, its name and what happens
  when it restarts.

  What does start here is `ExBao.TaskSupervisor`, where token servers run
  their logins and renewals. It holds nothing until one of them asks.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [{Task.Supervisor, name: ExBao.TaskSupervisor}]
    Supervisor.start_link(children, strategy: :one_for_one, name: ExBao.Supervisor)
  end
end
