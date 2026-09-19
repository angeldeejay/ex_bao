defmodule ExBao.Auth do
  @moduledoc """
  What a login gave back: a token, how long it lasts, and whether it renews.

  `renewable` is the field that decides how `ExBao.TokenServer` behaves, and
  it is not a detail: a token that cannot be renewed has to be *replaced*
  before it expires, by logging in again. A loop that only knows how to renew
  will keep asking until the token dies under it.
  """

  alias ExBao.Error

  @type t :: %__MODULE__{
          token: String.t(),
          accessor: String.t() | nil,
          lease_duration: non_neg_integer(),
          renewable: boolean(),
          policies: [String.t()],
          metadata: map()
        }

  @enforce_keys [:token]
  defstruct [
    :token,
    :accessor,
    lease_duration: 0,
    renewable: false,
    policies: [],
    metadata: %{}
  ]

  @doc false
  @spec from_response({:ok, map() | nil} | {:error, Error.t()}) ::
          {:ok, t()} | {:error, Error.t()}
  def from_response({:error, %Error{}} = error), do: error

  def from_response({:ok, %{"auth" => auth}}) when is_map(auth) do
    {:ok,
     %__MODULE__{
       token: auth["client_token"],
       accessor: auth["accessor"],
       lease_duration: auth["lease_duration"] || 0,
       renewable: auth["renewable"] || false,
       policies: auth["token_policies"] || auth["policies"] || [],
       metadata: auth["metadata"] || %{}
     }}
  end

  # A 200 whose body has no `auth` is not a login, whatever else it contains.
  # Saying so beats returning a struct with a nil token that fails later,
  # somewhere with no clue about where it came from.
  def from_response({:ok, body}) do
    {:error,
     %Error{
       kind: :unknown,
       status: 200,
       messages: ["response carried no auth block"],
       reason: body
     }}
  end
end
