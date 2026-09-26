defmodule ExBao.CoverageTest do
  @moduledoc """
  The client against the specification it was generated from.

  Every operation the newest captured specification lists has to be covered
  by some function — generated, or written by hand and marked with the
  `@operation` it covers. A release that adds an endpoint fails here until
  `mix bao.gen` has run, which is the point: coverage is checked, not
  claimed.
  """

  use ExUnit.Case, async: true

  alias Mix.Tasks.Bao.Gen

  @spec_file "priv/openapi/*.json"
             |> Path.wildcard()
             |> Enum.max_by(&(&1 |> Path.basename(".json") |> Version.parse!()), Version)

  test "every operation in #{@spec_file} is covered" do
    wanted =
      @spec_file
      |> File.read!()
      |> Jason.decode!()
      |> Gen.operations()
      |> MapSet.new(& &1.key)

    covered = MapSet.new(covered())

    assert MapSet.difference(wanted, covered) |> Enum.sort() == []
    # And nothing claims an operation the specification does not have: a
    # marker with a typo would otherwise hide the operation it meant.
    assert MapSet.difference(covered, wanted) |> Enum.sort() == []
  end

  test "no operation is covered twice" do
    duplicates =
      covered()
      |> Enum.frequencies()
      |> Enum.filter(fn {_key, count} -> count > 1 end)

    assert duplicates == []
  end

  defp covered do
    {:ok, modules} = :application.get_key(:ex_bao, :modules)

    for module <- modules,
        {:operation, keys} <- module.__info__(:attributes),
        key <- keys,
        do: key
  end
end
