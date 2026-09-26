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

  alias ExBao.{Auth, Client, Error}

  @doc """
  Exchanges a role id and a secret id for a token.

  ## Options

    * `:role_id` — required. From `BAO_ROLE_ID` otherwise.
    * `:secret_id` — required. From `BAO_SECRET_ID` otherwise.
    * `:path` — where the method is mounted, `"approle"` by default. A server
      can mount the same method twice under different paths, and then the
      path is the only thing that says which one you mean.

  ## Examples

      iex> ExBao.Auth.AppRole.login(client, role_id: "db02de0...", secret_id: "6a17...")
      {:ok, %ExBao.Auth{token: "s.wOrM...", lease_duration: 2_764_800, renewable: true}}
  """
  @spec login(Client.t(), keyword()) :: {:ok, Auth.t()} | {:error, Error.t()}
  def login(%Client{} = client, opts \\ []) do
    with {:ok, role_id} <- fetch(opts, :role_id, "BAO_ROLE_ID"),
         {:ok, secret_id} <- fetch(opts, :secret_id, "BAO_SECRET_ID") do
      path = Keyword.get(opts, :path, "approle")

      client
      |> Client.request(:post, "auth/#{path}/login", %{
        "role_id" => role_id,
        "secret_id" => secret_id
      })
      |> then(&Auth.from_response/1)
    end
  end

  @doc """
  Reads the role id of a role. Useful when provisioning, not at runtime.
  """
  @spec read_role_id(Client.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def read_role_id(%Client{} = client, role, opts \\ []) do
    path = Keyword.get(opts, :path, "approle")

    case Client.request(client, :get, role_path(path, role, "role-id")) do
      {:ok, %{"data" => %{"role_id" => role_id}}} -> {:ok, role_id}
      {:ok, other} -> {:error, Error.from_response(200, other)}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Issues a new secret id for a role. Useful when provisioning, not at runtime.
  """
  @spec generate_secret_id(Client.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, Error.t()}
  def generate_secret_id(%Client{} = client, role, opts \\ []) do
    path = Keyword.get(opts, :path, "approle")

    case Client.request(client, :post, role_path(path, role, "secret-id"), %{}) do
      {:ok, %{"data" => data}} -> {:ok, data}
      {:ok, other} -> {:error, Error.from_response(200, other)}
      {:error, error} -> {:error, error}
    end
  end

  # The role name is escaped: one from user input must not be able to
  # address a different endpoint. The mount path is not, since a method
  # mounted under `team/approle` legitimately has a slash in it.
  defp role_path(path, role, leaf),
    do: "auth/#{path}/role/#{URI.encode(role, &URI.char_unreserved?/1)}/#{leaf}"

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
