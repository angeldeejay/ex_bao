defmodule ExBao.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/angeldeejay/ex_bao"

  def project do
    [
      app: :ex_bao,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      test_coverage: [tool: ExCoveralls],
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        # Out of `_build` so CI can cache it without dragging the whole
        # build directory along.
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ],

      # Hex
      description:
        "An OpenBao client for Elixir: the whole API, generated from OpenBao's own " <>
          "specification, with Transit and AppRole designed on top and a supervised " <>
          "token that renews itself before it expires.",
      package: package(),

      # Docs
      name: "ExBao",
      source_url: @source_url,
      docs: docs()
    ]
  end

  def cli do
    [
      preferred_envs: [
        # It starts a container to ask it something, so it needs the test
        # dependencies. Declared here so nobody has to type MIX_ENV.
        "bao.openapi": :test,
        # Lives next to it in test/support, so it is never in the package.
        "bao.gen": :test,
        # `check` ends in `test`, and Mix does not switch environment part
        # way through an alias.
        check: :test,
        "coveralls.all": :test,
        "coveralls.html.all": :test,
        "test.integration": :test,
        "test.all": :test,
        coveralls: :test,
        "coveralls.html": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {ExBao.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:req, "~> 0.5"},
      {:jason, "~> 1.4"},

      # Tooling. None of it ships with the package.
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test},

      # The integration suite starts its own OpenBao, one per version under
      # test. Nobody has to `docker run` anything by hand, and nothing is
      # left running when a test crashes.
      {:testcontainers, "~> 2.4", only: :test},

      # `Req.Test` needs it, and Req declares it optional. Test only: nothing
      # in the library itself knows what a Plug is.
      {:plug, "~> 1.16", only: :test}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      # `priv` is deliberately absent. It holds the Dialyzer PLT -- a local
      # build artefact, megabytes of it -- and the captured OpenAPI
      # specifications, which are how this repository tracks what changed
      # between OpenBao releases. Neither is of any use to somebody who
      # installs the library, and a package carries its weight to every
      # consumer forever.
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"],
      groups_for_modules: [
        Core: [ExBao.Client, ExBao.Error, ExBao.TokenServer],
        "Secrets engines": [
          ExBao.Transit,
          ExBao.KV,
          ExBao.KV.V1,
          ExBao.PKI,
          ExBao.SSH,
          ExBao.TOTP,
          ExBao.Database,
          ExBao.RabbitMQ,
          ExBao.Kubernetes,
          ExBao.LDAP,
          ExBao.Cubbyhole
        ],
        "Auth methods": [
          ExBao.Auth,
          ExBao.Auth.AppRole,
          ExBao.Auth.Token,
          ExBao.Auth.Cert,
          ExBao.Auth.JWT,
          ExBao.Auth.Kerberos,
          ExBao.Auth.Kubernetes,
          ExBao.Auth.LDAP,
          ExBao.Auth.Radius,
          ExBao.Auth.Userpass
        ],
        System: [ExBao.Sys, ExBao.Identity]
      ]
    ]
  end

  # `test` stays offline so it runs anywhere; the integration suite is opt-in
  # and needs a server, which is what `--include integration` says out loud.
  defp aliases do
    [
      "test.integration": ["test --only integration"],
      "test.all": ["test --include integration"],
      # Coverage is only meaningful with the integration suite: Transit is
      # exercised there, and measuring without it reports 0% for the module
      # the library exists for.
      "coveralls.all": ["coveralls --include integration"],
      "coveralls.html.all": ["coveralls.html --include integration"],
      # Everything that can be checked without a server. `test.all` and
      # `coveralls.all` need one, so they are not in here: a `check` that
      # demands Docker is a `check` people stop running.
      check: [
        "format --check-formatted",
        "deps.unlock --check-unused",
        "compile --warnings-as-errors",
        "credo --strict",
        "dialyzer",
        "test"
      ]
    ]
  end
end
