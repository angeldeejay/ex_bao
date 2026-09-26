defmodule ExBao.Auth.AppRole do
  @moduledoc """
  Logging in with AppRole, which is how a service authenticates.

  A role id names *which* service and is not secret — it is fine in a
  configuration file. A secret id is the credential and is not. Splitting
  them is the point of the method: the part that identifies can be deployed
  with the code, and the part that authenticates can be delivered separately
  and rotated without a release.

  What comes back is a token with a lease. Keeping that token alive is
  `ExBao.TokenServer`'s job, not this module's — here you log in once and get
  told how long it lasts.
  """

  alias ExBao.{Auth, Client, Error, Operation}

  @doc """
  Exchanges a role id and a secret id for a token.

  ## Options

    * `:role_id` — required. From `BAO_ROLE_ID` otherwise.
    * `:secret_id` — required. From `BAO_SECRET_ID` otherwise.
    * `:mount` — where the method is mounted, `"approle"` by default. A
      server can mount the same method twice under different paths, and then
      the mount is the only thing that says which one you mean. `:path` is
      still accepted for it, as it was in 0.1.0.

  ## Examples

      iex> ExBao.Auth.AppRole.login(client, role_id: "db02de0...", secret_id: "6a17...")
      {:ok, %ExBao.Auth{token: "s.wOrM...", lease_duration: 2_764_800, renewable: true}}
  """
  @spec login(Client.t(), keyword()) :: {:ok, Auth.t()} | {:error, Error.t()}
  def login(%Client{} = client, opts \\ []) do
    with {:ok, role_id} <- fetch(opts, :role_id, "BAO_ROLE_ID"),
         {:ok, secret_id} <- fetch(opts, :secret_id, "BAO_SECRET_ID") do
      client
      |> Client.request(:post, "auth/#{mount(opts)}/login", %{
        "role_id" => role_id,
        "secret_id" => secret_id
      })
      |> then(&Auth.from_response/1)
    end
  end

  @doc """
  Reads the role id of a role. Useful when provisioning, not at runtime.

  Takes a client or a token server, and `:mount` as `login/2` does.
  """
  @spec read_role_id(ExBao.server(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def read_role_id(server, role, opts \\ []) do
    case Operation.request(server, :get, role_path(opts, role, "role-id")) do
      {:ok, %{"data" => %{"role_id" => role_id}}} -> {:ok, role_id}
      {:ok, other} -> {:error, Operation.unexpected(other)}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Issues a new secret id for a role. Useful when provisioning, not at runtime.

  Takes a client or a token server, and `:mount` as `login/2` does.
  """
  @spec generate_secret_id(ExBao.server(), String.t(), keyword()) ::
          {:ok, map()} | {:error, Error.t()}
  def generate_secret_id(server, role, opts \\ []) do
    case Operation.request(server, :post, role_path(opts, role, "secret-id"), %{}) do
      {:ok, %{"data" => data}} -> {:ok, data}
      {:ok, other} -> {:error, Operation.unexpected(other)}
      {:error, error} -> {:error, error}
    end
  end

  # `:path` was the option's name in 0.1.0. It keeps working, and `:mount`
  # wins when both are given, since it is the name every module shares.
  defp mount(opts), do: Operation.mount(opts, Keyword.get(opts, :path, "approle"))

  # The role name is escaped: one from user input must not be able to
  # address a different endpoint. The mount is not, since a method mounted
  # under `team/approle` legitimately has a slash in it.
  defp role_path(opts, role, leaf),
    do: "auth/#{mount(opts)}/role/#{Operation.escape(role)}/#{leaf}"

  # A missing credential is not a request worth making: sending `nil` would
  # get a 400 back and the error would describe the server's opinion of an
  # empty field instead of the fact that nobody configured it.
  defp fetch(opts, key, env_var) do
    case Keyword.get(opts, key) || System.get_env(env_var) ||
           Application.get_env(:ex_bao, key) do
      nil ->
        {:error,
         %Error{
           kind: :invalid_credentials,
           messages: ["missing #{key}: pass it, or set #{env_var}"]
         }}

      value ->
        {:ok, value}
    end
  end
end
