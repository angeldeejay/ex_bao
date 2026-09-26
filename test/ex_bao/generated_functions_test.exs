defmodule ExBao.GeneratedFunctionsTest do
  @moduledoc """
  Every generated function, called against the operation it came from.

  The generator writes hundreds of functions and a mistake in it would be
  repeated in all of them, so each one is held to its own operation: called
  with its required options, it must send the method and the path the
  specification names — mount included — and the query it always requires;
  called without them, it must refuse before sending. A stub answers, so
  this needs no server and runs in the unit suite.
  """

  use ExUnit.Case, async: true

  alias ExBao.Client
  alias Mix.Tasks.Bao.Gen

  @spec_file "priv/openapi/*.json"
             |> Path.wildcard()
             |> Enum.max_by(&(&1 |> Path.basename(".json") |> Version.parse!()), Version)

  setup_all do
    functions = @spec_file |> File.read!() |> Jason.decode!() |> Gen.generated()
    {:ok, functions: functions}
  end

  test "there is something to check", %{functions: functions} do
    assert length(functions) > 700
  end

  test "each one sends its own method and path", %{functions: functions} do
    stub = :"stub_#{System.unique_integer([:positive])}"
    test_pid = self()

    Req.Test.stub(stub, fn conn ->
      send(test_pid, {:sent, conn.method, conn.request_path, conn.query_string})
      Req.Test.json(conn, %{})
    end)

    client = Client.new(addr: "http://bao.test", plug: {Req.Test, stub}, retry: false)

    mismatches =
      for op <- functions,
          mismatch = check(op, client),
          do: mismatch

    assert mismatches == []
  end

  defp check(op, client) do
    names = Regex.scan(~r/\{(\w+)\}/, op.path) |> Enum.map(&List.last/1)
    args = Enum.map(names, &"#{&1}-arg")
    required = Enum.map(op.body["required"] || [], &{String.to_atom(&1), "x"})

    fun = String.to_atom(op.name)

    # Once with no options at all. It works when nothing is required, and
    # when something is, it is refused before anything is sent — either
    # way the call without options is a real path, not an untested default.
    if required == [] do
      {:ok, _} = apply(op.module, fun, [client | args])
      assert_received {:sent, _method, _path, _query}
    else
      assert_raise ArgumentError, fn -> apply(op.module, fun, [client | args]) end
      refute_received {:sent, _method, _path, _query}
    end

    {:ok, _} = apply(op.module, fun, [client | args] ++ [required])

    expected_path =
      names
      |> Enum.zip(args)
      |> Enum.reduce("/v1" <> op.path, fn {name, arg}, path ->
        String.replace(path, "{#{name}}", arg)
      end)

    expected_method = String.upcase(op.method)

    # What the specification says must always be sent: `list=true` on a
    # LIST, and `scan=true` on the recursive ones.
    fixed =
      for %{"in" => "query", "required" => true, "name" => name} <- op.parameters,
          into: %{},
          do: {name, "true"}

    receive do
      {:sent, ^expected_method, ^expected_path, query} ->
        if URI.decode_query(query) != fixed,
          do: "#{inspect(op.module)}.#{op.name}: sent query #{inspect(query)}"

      {:sent, method, path, _query} ->
        "#{inspect(op.module)}.#{op.name}: sent #{method} #{path}, " <>
          "expected #{expected_method} #{expected_path}"
    after
      1_000 -> "#{inspect(op.module)}.#{op.name}: sent nothing"
    end
  end
end
