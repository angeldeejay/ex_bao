# Changelog

## 0.1.0 — 2026-09-19

First cut. Transit and AppRole, written by hand because they are the ones
worth designing; the rest of the API will be generated from the server's own
OpenAPI specification.

### Added

* `ExBao.Transit` — encrypt, decrypt, rewrap and rotate, each with a batch
  form. Base64 is handled in both directions, so callers pass values.
* `ExBao.Auth.AppRole` — login, plus reading a role id and issuing a secret
  id for provisioning.
* `ExBao.TokenServer` — a supervised token that authenticates on start,
  renews at a fraction of the lease rather than on expiry, and logs in again
  when a renewal is refused. Starts even when the server is unreachable.
* `ExBao.Error` — every failure carries a stable `:kind` to match on, and the
  server's own prose for whoever reads the log.
* `mix bao.openapi` — captures a server's OpenAPI specification.
* `Transit.split/1`, which separates a batch into what worked and what did
  not. There is deliberately no `all/1`: collapsing a batch to its first
  error is nearly always wrong here.
* `:references` on every batch call. The server echoes a label back with each
  result, errors included, so a failure can be traced to the row it came from
  without depending on position.
* `avoid_create_on_missing:` on `encrypt/4` and `encrypt_batch/4`, which reads
  the key first rather than letting the server create one from a typo.

### Measured, not assumed

Behaviour found by running against a real 2.6.2, and worth knowing:

* **Sealing under a key that does not exist creates it.** A typo in a key
  name does not fail — it makes a second key.
* **A batch with one bad element answers 400 and returns every result.**
  Reading only the status throws away the ones that worked.
* **An empty batch is refused** with "missing batch input to process", so the
  request is never sent.
* **The OpenAPI specification is filtered by the token's policies.** Asked
  without one, the server describes nothing and does not say so.

### Infrastructure

* CI runs the toolchain the job names rather than one `erlef/setup-beam`
  picks from `ImageOS`, and reaches OpenBao through `services:` instead of
  starting containers from inside a container. Testcontainers stays for local
  development, where there is a socket and no service network.
* `mix test.all` and `mix coveralls.all` for the suite that needs a server;
  plain `mix test` and `mix check` need neither Docker nor network.
* A release workflow on `v*` tags: it refuses a tag that disagrees with
  `mix.exs`, runs the integration suite against a real server, prints the
  package contents, and waits on the `hex` environment before publishing.
* The published package carries `lib` and its documents only. `priv` holds a
  Dialyzer PLT and the captured specifications — 5.8 MB of nothing a consumer
  needs.
