# ExBao

An [OpenBao](https://openbao.org) client for Elixir: Transit, AppRole, and a
supervised token that renews itself before it expires.

[![Hex.pm](https://img.shields.io/hexpm/v/ex_bao.svg)](https://hex.pm/packages/ex_bao)
[![Hex.pm](https://img.shields.io/hexpm/dt/ex_bao.svg)](https://hex.pm/packages/ex_bao)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/ex_bao)

OpenBao is the Linux Foundation fork of HashiCorp Vault. This client targets
OpenBao's own API and is tested against every supported release — see
[Compatibility](#compatibility).

## Installation

1. Add `ex_bao` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_bao, "~> 0.1"}
  ]
end
```

2. Add the token server to your supervision tree. It authenticates on start
   and keeps the token alive, so nothing else in your application has to know
   a token exists:

```elixir
def start(_type, _args) do
  children = [
    {ExBao.TokenServer, name: MyApp.Bao}
  ]

  Supervisor.start_link(children, strategy: :one_for_one, name: MyApp.Supervisor)
end
```

## Configuration

Configuration is read from the environment first, then from application
config. The environment wins, so a release can be pointed at a different
server without rebuilding it.

Environment variables:

* `BAO_ADDR` — the server, e.g. `https://bao.internal:8200`
* `BAO_TOKEN` — a token, when you already have one
* `BAO_ROLE_ID` and `BAO_SECRET_ID` — AppRole credentials, when you do not
* `BAO_CACERT` — path to a PEM bundle that signs the server's certificate
* `BAO_NAMESPACE` — namespace to send with every request, if you use them

Application variables, for whatever the environment does not set:

```elixir
config :ex_bao,
  addr: "https://bao.internal:8200",
  auth: {:approle, role_id: "...", secret_id: "..."},
  # Renew once this much of the lease is gone. 0.7 renews a 60s lease at 42s,
  # which leaves room for a failed attempt and a retry before it expires.
  renew_after: 0.7,
  # Passed straight to Req, which passes them to Finch.
  receive_timeout: 5_000,
  retry: :safe_transient
```

TLS options go under `:connect_options`, which reaches Finch unchanged:

```elixir
config :ex_bao,
  connect_options: [
    transport_opts: [
      cacertfile: "/etc/ssl/certs/bao-ca.pem",
      verify: :verify_peer
    ]
  ]
```

Verification is **on** by default. Turning it off is a per-client option and
never a global one, so a test that needs a self-signed certificate cannot
quietly disable it for production too:

```elixir
client = ExBao.Client.new(addr: "https://localhost:8200", verify: false)
```

## Usage

### Authenticating

The token server does this on start and again whenever the lease is running
out. You only call it directly when you are managing the token yourself:

```elixir
iex> ExBao.Auth.AppRole.login(client, role_id: "db02de0...", secret_id: "6a17...")
{:ok, %ExBao.Auth{token: "s.wOrM...", lease_duration: 2_764_800, renewable: true}}
```

Errors are tagged, never bare strings, so a caller can match on the one it
knows how to handle:

```elixir
iex> ExBao.Auth.AppRole.login(client, role_id: "nope", secret_id: "nope")
{:error, %ExBao.Error{status: 400, kind: :invalid_credentials, messages: ["invalid role or secret ID"]}}
```

### Sealing and opening

Transit encrypts without ever handing you the key. What comes back carries
the key version on the outside — `vault:v1:` — so a rotated key can open what
an older one sealed:

```elixir
iex> ExBao.Transit.encrypt(server, "payout", "00912345620")
{:ok, "vault:v1:Xo0En3wRbT5urbzKrsXFAhXUmjkqumptoErLc3NIZ9bskIycK3l6"}

iex> ExBao.Transit.decrypt(server, "payout", "vault:v1:Xo0En3wRbT5urbzKrsXFAhXUmjkqumptoErLc3NIZ9bskIycK3l6")
{:ok, "00912345620"}
```

Base64 is handled for you in both directions: you pass and receive the plain
value, not an encoding of it.

### Doing it in batches

One round trip instead of one per item, which matters when a page renders a
list. **Every element comes back wrapped**, whether anything failed or not:

```elixir
iex> ExBao.Transit.encrypt_batch(server, "payout", ["00912345620", "3001234417"])
{:ok, [ok: "vault:v1:Xo0En3w...", ok: "vault:v1:9dK2lsP..."]}

iex> ExBao.Transit.decrypt_batch(server, "payout", ["vault:v1:Xo0En3w...", "vault:v1:corrupted"])
{:ok, [ok: "00912345620", error: %ExBao.Error{kind: :invalid_ciphertext}]}
```

The outer `:ok` does not mean the work succeeded — it means the request was
made and here are the results. What failed is inside, where whoever iterates
has to see it. One corrupt row does not blank the page.

`split/1` separates the two sides:

```elixir
iex> {sealed, failed} = ExBao.Transit.encrypt_batch(server, "payout", values) |> ExBao.Transit.split()
```

Results are positional, so the fifth answer belongs to the fifth value. That
holds — but it is fragile to depend on, since anything that filters or
reorders on the way breaks it silently. `:references` removes the dependency
by having the server echo a label back with each result, **errors included**:

```elixir
iex> ExBao.Transit.decrypt_batch(server, "payout", ciphertexts, references: ids)
{:ok, [{"dest-42", {:ok, "00912345620"}}, {"dest-77", {:error, %ExBao.Error{}}}]}

iex> ... |> ExBao.Transit.split()
{[{"dest-42", "00912345620"}], [{"dest-77", %ExBao.Error{kind: :invalid_ciphertext}}]}
```

### Rotating a key

Rotation adds a version; it does not invalidate the old one. `rewrap` re-seals
an existing ciphertext under the newest version **without the plaintext ever
leaving the server**:

```elixir
iex> ExBao.Transit.rotate(server, "payout")
:ok

iex> ExBao.Transit.rewrap(server, "payout", "vault:v1:Xo0En3w...")
{:ok, "vault:v2:Qm5tRa0..."}
```

Set the minimum version allowed for decryption once every row has moved:

```elixir
iex> ExBao.Transit.set_min_decryption_version(server, "payout", 2)
:ok
```

### Managing keys

```elixir
iex> ExBao.Transit.create_key(server, "payout", type: :aes256_gcm96)
:ok
```

**Sealing under a key that does not exist creates it** — that is OpenBao's
behaviour, so a typo in a key name does not fail, it quietly makes a second
key. `avoid_create_on_missing: true` reads the key first and fails with
`:not_found` instead, at the cost of one round trip:

```elixir
iex> ExBao.Transit.encrypt(server, "payoutt", "00912345620", avoid_create_on_missing: true)
{:error, %ExBao.Error{kind: :not_found}}
```

The other guard is a policy that does not grant `create` on `transit/keys/*`
to the application. They are not alternatives: the option catches it where
it happened, the policy catches it in code that forgot to ask.

```elixir

iex> ExBao.Transit.read_key(server, "payout")
{:ok, %{type: "aes256-gcm96", latest_version: 2, min_decryption_version: 1, keys: %{1 => ..., 2 => ...}}}

iex> ExBao.Transit.list_keys(server)
{:ok, ["payout", "totp"]}
```

## Compatibility

Every release is tested against each supported OpenBao series by running the
integration suite inside a container that holds that exact server. A cell is
green because the tests ran and passed there, not because the API looked
similar.

| OpenBao | Transit | AppRole | Batch | Rewrap |
|---------|---------|---------|-------|--------|
| 2.6.2   | ✅      | ✅      | ✅    | ✅     |
| 2.5.x   | —       | —       | —     | —      |
| 2.4.x   | —       | —       | —     | —      |

A dash means **not measured yet**, not "does not work". The matrix is written
and has only ever run against 2.6.2; the other rows fill in when it runs. A
table that claimed green on a version nobody tested would be the same kind of
guess this project exists to avoid.

Changes to OpenBao's published OpenAPI specification are tracked in
`priv/openapi/`, one file per version. A diff there says **what to look at**
when a new release lands; the matrix above says **what actually broke**. They
are not the same question, and only the second one is an answer.

## Running the tests

```console
$ mix test        # unit only. No Docker, no network, runs anywhere.
$ mix test.all    # adds the integration suite, which starts its own OpenBao.
```

The integration suite uses [Testcontainers][tc]: it boots the server, waits
until it answers, and tears it down afterwards. Nothing is left running when a
test crashes.

On **Linux and macOS** the Docker socket is where the library looks for it.

On **Windows** it is not — Docker Desktop speaks over a named pipe — so
install [Testcontainers Desktop][tcd] once. It writes the `tc.host` the
library reads and exposes a local endpoint, after which `mix test.all` runs
from the host like anywhere else.

### In a container instead

```console
$ docker compose -f docker-compose.test.yml run --rm test
```

Elixir in a Linux container with the host's Docker socket mounted in, so the
servers the suite starts are siblings of it rather than children. Useful for
pinning the Elixir version, and for a machine where installing anything else
is not an option.

**Against a server you already have**, skipping containers entirely:

```console
$ BAO_TEST_ADDR=http://127.0.0.1:8200 BAO_TEST_TOKEN=root mix test.all
```

[tc]: https://github.com/testcontainers/testcontainers-elixir
[tcd]: https://testcontainers.com/desktop/

### A note on `hackney`

`mix deps.get` reports CVEs in `hackney`, which arrives through
`testcontainers → tesla`. It is a **test-only** dependency: it is not in the
published package, and nothing in this library uses it — the client runs on
`Req`/Finch. Nobody who installs `ex_bao` pulls it in.

## Notes

### On the token server

`ExBao.TokenServer` is the reason this library exists as more than a wrapper
around HTTP calls. It authenticates on start, renews at `renew_after` of the
lease rather than on expiry, and re-authenticates from scratch if a renewal is
refused — a token can be revoked, and a renewal loop that only knows how to
renew will spin forever against a token that will never come back.

If that new login fails too — OpenBao briefly unreachable, say — the current
token stays in use for as long as it is still valid, and the login is retried
with a backoff. That margin is the whole point of renewing early. Logins and
renewals run in a task of their own, so a slow server never makes a caller
time out waiting on the process that holds the token.

It does **not** cache secrets. A client that caches has to decide when to stop
trusting the cache, and that decision belongs to the caller who knows what the
value is for.

### On what is not here yet

This is an alpha. Transit and AppRole are implemented by hand because they are
the ones worth designing. The rest of OpenBao's API — 292 paths and 444
operations as of 2.6.2 — will be generated from the server's own OpenAPI
specification rather than transcribed from another client, so that it stays
honest across versions.

## Releasing

```console
$ mix hex.publish
```
