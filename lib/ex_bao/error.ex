defmodule ExBao.Error do
  @moduledoc """
  What went wrong, in a shape a caller can match on.

  OpenBao answers a failure with a status and a list of messages, and the
  messages are prose meant for a human — they change between versions and
  they are not a contract. Matching on them is how a client breaks silently
  when the server is upgraded.

  So every failure carries a `:kind`, which is ours and stable, and keeps the
  server's own words in `:messages` for whoever is reading a log. A caller
  matches the kind; a human reads the messages.

      case ExBao.Transit.decrypt(server, "payout", ciphertext) do
        {:ok, plaintext} -> plaintext
        {:error, %ExBao.Error{kind: :invalid_ciphertext}} -> :corrupt_row
        {:error, %ExBao.Error{kind: :sealed}} -> :try_again_later
      end

  `:no_token` never comes from the server: it is `ExBao.TokenServer` saying
  it has no token to hand out yet — at boot, or while a login is failing.
  It is kept apart from `:permission_denied` because the two call for
  different things: one is waited out, the other is a policy to fix.

  `:unknown` is deliberately in the list: a kind we have not mapped is still
  an error, and swallowing it into something adjacent would be worse than
  saying plainly that we do not recognise it.
  """

  @type kind ::
          :invalid_credentials
          | :permission_denied
          | :no_token
          | :not_found
          | :invalid_ciphertext
          | :invalid_request
          | :sealed
          | :rate_limited
          | :server_error
          | :transport
          | :unknown

  @type t :: %__MODULE__{
          kind: kind(),
          status: pos_integer() | nil,
          messages: [String.t()],
          reason: term()
        }

  defexception [:kind, :status, :messages, :reason]

  @impl true
  def message(%__MODULE__{kind: kind, status: status, messages: messages}) do
    said = if messages in [nil, []], do: "", else: ": " <> Enum.join(messages, "; ")
    where = if status, do: " (HTTP #{status})", else: ""
    "openbao #{kind}#{where}#{said}"
  end

  @doc """
  Builds an error from a response the server did answer.

  The status is what decides the kind, with one exception: a 400 means
  "the request was wrong" and the reason it was wrong is only in the prose.
  Telling `invalid_ciphertext` apart from a malformed body matters to a
  caller — one is a corrupt row and the other is a bug — so that single case
  reads the messages, and reads them loosely enough to survive a rewording.
  """
  @spec from_response(pos_integer(), term()) :: t()
  def from_response(status, body) do
    messages = messages(body)

    %__MODULE__{
      kind: kind(status, messages),
      status: status,
      messages: messages,
      reason: body
    }
  end

  @doc """
  Builds an error for a request that never got an answer.

  A refused connection, a DNS failure, a timeout. There is no status because
  nothing replied, and that is exactly the distinction worth keeping: a
  `:transport` error says nothing about whether the operation happened.
  """
  @spec from_transport(term()) :: t()
  def from_transport(reason) do
    %__MODULE__{kind: :transport, status: nil, messages: [inspect(reason)], reason: reason}
  end

  defp kind(400, messages) do
    cond do
      said?(messages, ["invalid ciphertext", "unable to decrypt", "ciphertext"]) ->
        :invalid_ciphertext

      said?(messages, ["invalid role", "invalid secret", "failed to validate"]) ->
        :invalid_credentials

      true ->
        :invalid_request
    end
  end

  defp kind(status, _messages) when status in [401, 403], do: :permission_denied
  defp kind(404, _messages), do: :not_found
  defp kind(429, _messages), do: :rate_limited
  # 503 is how a sealed server answers, and it is not a server error: it is a
  # server that is up and refusing on purpose, which a caller may want to wait
  # out rather than treat as a bug.
  defp kind(503, _messages), do: :sealed
  defp kind(status, _messages) when status >= 500, do: :server_error
  defp kind(_status, _messages), do: :unknown

  defp said?(messages, needles) do
    said = messages |> Enum.join(" ") |> String.downcase()
    Enum.any?(needles, &String.contains?(said, &1))
  end

  # OpenBao answers `{"errors": [...]}`, but not always: a plugin can answer
  # with a bare string, and an upstream proxy can answer with HTML. Anything
  # that is not the documented shape is kept as one inspected line rather
  # than dropped, because an unreadable error still beats an empty one.
  defp messages(%{"errors" => errors}) when is_list(errors), do: Enum.map(errors, &to_string/1)
  defp messages(%{"errors" => error}), do: [to_string(error)]
  defp messages(body) when is_binary(body), do: [body]
  defp messages(nil), do: []
  defp messages(body), do: [inspect(body)]
end
