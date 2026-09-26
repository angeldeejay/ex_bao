# Roadmap

Where ExBao stands against OpenBao's API, and what comes next.

## How to read this

The API is measured against the OpenAPI specification captured from OpenBao
2.6.2 with every built-in engine and auth method mounted,
[`priv/openapi/2.6.2.json`](priv/openapi/2.6.2.json). Each of its operations is
in one of two states:

* **Curated** — written by hand, above the generated block of its module. It
  knows what the specification cannot say: encodings, batch semantics, error
  shapes, sharp edges measured against a real server.
* **Generated** — written by `mix bao.gen`. One function per endpoint, faithful
  to the specification: path parameters as arguments, fields as validated
  options, the server's JSON returned untouched.

There is no third state. `ExBao.CoverageTest` fails when an operation in the
specification is covered by nothing, so *missing* cannot happen silently.

This document is a snapshot. The tables below describe the tree as of the
commit that last changed them; the coverage test is the live check.

## Coverage summary

**761 operations: 11 curated, 750 generated, 0 missing.**

| Area | Module | Default mount | Operations | Curated | Generated |
|------|--------|---------------|-----------:|--------:|----------:|
| Secrets engines | `ExBao.Transit` | `transit` | 42 | 8 | 34 |
| Secrets engines | `ExBao.KV` | `secret` | 15 | 0 | 15 |
| Secrets engines | `ExBao.KV.V1` | `kv` | 3 | 0 | 3 |
| Secrets engines | `ExBao.PKI` | `pki` | 154 | 0 | 154 |
| Secrets engines | `ExBao.SSH` | `ssh` | 26 | 0 | 26 |
| Secrets engines | `ExBao.TOTP` | `totp` | 6 | 0 | 6 |
| Secrets engines | `ExBao.Database` | `database` | 17 | 0 | 17 |
| Secrets engines | `ExBao.RabbitMQ` | `rabbitmq` | 8 | 0 | 8 |
| Secrets engines | `ExBao.Kubernetes` | `kubernetes` | 9 | 0 | 9 |
| Secrets engines | `ExBao.LDAP` | `ldap` | 23 | 0 | 23 |
| Secrets engines | `ExBao.Cubbyhole` | `cubbyhole` (fixed) | 3 | 0 | 3 |
| Auth methods | `ExBao.Auth.AppRole` | `approle` | 51 | 3 | 48 |
| Auth methods | `ExBao.Auth.Token` | `token` (fixed) | 21 | 0 | 21 |
| Auth methods | `ExBao.Auth.Cert` | `cert` | 11 | 0 | 11 |
| Auth methods | `ExBao.Auth.JWT` | `jwt` | 17 | 0 | 17 |
| Auth methods | `ExBao.Auth.Kerberos` | `kerberos` | 10 | 0 | 10 |
| Auth methods | `ExBao.Auth.Kubernetes` | `kubernetes` | 7 | 0 | 7 |
| Auth methods | `ExBao.Auth.LDAP` | `ldap` | 11 | 0 | 11 |
| Auth methods | `ExBao.Auth.Radius` | `radius` | 8 | 0 | 8 |
| Auth methods | `ExBao.Auth.Userpass` | `userpass` | 7 | 0 | 7 |
| System | `ExBao.Sys` | `sys` (fixed) | 207 | 0 | 207 |
| System | `ExBao.Identity` | `identity` (fixed) | 105 | 0 | 105 |
| **Total** | | | **761** | **11** | **750** |

*Fixed* mounts cannot be moved, so their modules take no `:mount` option.

### Curated operations

| Module | Function | Method | Path | Notes |
|--------|----------|--------|------|-------|
| `ExBao.Auth.AppRole` | `generate_secret_id` | POST | `/auth/approle/role/{role_name}/secret-id` | Returns `data` |
| `ExBao.Auth.AppRole` | `login` | POST | `/auth/approle/login` | Returns `%ExBao.Auth{}`; credentials from env/config |
| `ExBao.Auth.AppRole` | `read_role_id` | GET | `/auth/approle/role/{role_name}/role-id` | Returns the id |
| `ExBao.Transit` | `create_key` | POST | `/transit/keys/{name}` | Partial: `type`, `derived`, `exportable`, `allow_plaintext_backup` only |
| `ExBao.Transit` | `decrypt` | POST | `/transit/decrypt/{name}` | Base64 handled; `decrypt_batch/4` too |
| `ExBao.Transit` | `delete_key` | DELETE | `/transit/keys/{name}` |  |
| `ExBao.Transit` | `encrypt` | POST | `/transit/encrypt/{name}` | Base64 handled; `encrypt_batch/4` too; `avoid_create_on_missing` |
| `ExBao.Transit` | `list_keys` | GET | `/transit/keys` | An empty mount is `{:ok, []}`, not a 404 |
| `ExBao.Transit` | `read_key` | GET | `/transit/keys/{name}` | Returns `data` |
| `ExBao.Transit` | `rewrap` | POST | `/transit/rewrap/{name}` | `rewrap_batch/4` too |
| `ExBao.Transit` | `rotate` | POST | `/transit/keys/{name}/rotate` |  |

`Transit.set_min_decryption_version/4` is curated too, over part of
`transit-configure-key`; the whole operation is the generated
`Transit.configure_key/3`.

## Implementation plan

Nothing below has started. Each step is meant to land as its own pull
request, in this order unless something more urgent comes up.

### 1. Release 0.2.0

Everything above is merged but unreleased: the published package is still
0.1.0.

* Bump `@version` in `mix.exs` to `0.2.0` and date the `Unreleased` section
  of `CHANGELOG.md`.
* Tag `v0.2.0`; the release workflow checks the tag against `mix.exs`, runs
  the integration suite and waits on the `hex` environment before publishing.
* 0.2.0 rather than 0.1.1: `ExBao.TokenServer` now answers `kind: :no_token`
  where it answered `:permission_denied`, and `ExBao.health/1` reports more
  statuses as errors.

### 2. Finish Transit

The engine this library started with should not be half curated.

* `create_key/3` accepts only four of `transit-create-key`'s fields. Accept
  all of them (`auto_rotate_period`, `key_size`, `convergent_encryption`, …),
  keeping atoms for `:type`.
* `set_min_decryption_version/4` stays as the one-purpose shortcut; point its
  documentation at the generated `configure_key/3` for everything else.
* Curate the generated functions that make every caller deal with base64,
  exactly what `encrypt/4` exists to avoid: `generate_hmac`, `sign`,
  `verify`, `hash`, `generate_data_key` and `generate_random`. Raw binaries
  in, raw binaries out, with batch forms where the endpoint has them.

### 3. Every auth method in the token server

`ExBao.TokenServer` authenticates with `{:approle, opts}` or `{:token, t}`
only. The generated modules can already log in with any method; the token
server cannot use them.

* Accept `{:userpass, …}`, `{:ldap, …}`, `{:kubernetes, …}`, `{:jwt, …}` and
  `{:cert, …}`, each mapped to its generated `login` and turned into
  `%ExBao.Auth{}`.
* `{:kubernetes, role: …}` reads the service account token from its standard
  path by default, since that is the reason to use it.
* Curate those `login` functions to return `%ExBao.Auth{}`, as
  `AppRole.login/2` does.

### 4. Leases for dynamic secrets

`ExBao.Database`, `ExBao.RabbitMQ`, `ExBao.Kubernetes`, `ExBao.LDAP` and
`ExBao.PKI` hand out credentials with a lease. Today the caller gets the raw
JSON and has to renew or revoke through `ExBao.Sys` by hand.

* A small, explicit lease value: id, duration, renewable, and the data.
* `renew/2` and `revoke/2` over the generated `sys/leases` operations.
* Possibly a supervised lease keeper on the `TokenServer` model — renew at a
  fraction of the lease, report when renewal is refused. Only if a real
  consumer needs it; it must not become a secret cache.

### 5. Curate the engines people reach for first

In order of expected use:

* **KV v2** — `read/3` returning the data and metadata apart, `write/4`
  with check-and-set, `list/3`, soft delete and destroy by version.
* **PKI** — `issue/4` returning certificate, private key and chain as
  fields rather than a map.
* **Auth.Token** — `lookup_self`, `create`, `revoke` as the typed shapes
  tokens deserve.

Each curation moves functions above the generated block and marks them with
`@operation`; the generator stops producing them on its next run.

### 6. Response wrapping

OpenBao can answer any request with a single-use wrapping token instead of
the secret (`X-Vault-Wrap-TTL`). The generated operations cannot ask for it.

* Add `:wrap_ttl` to `ExBao.Operation.call/5`, available on every generated
  function without regenerating them, and an unwrap helper over the
  generated `Sys.unwrap`.

### 7. Keeping up with OpenBao

The process exists; make it cheaper and harder to skip.

* A CI step that runs `mix bao.gen` and fails on a diff, so generated code
  can never drift from the committed specification.
* `mix bao.roadmap`, writing the coverage tables of this document from the
  same data the generator uses, so it is regenerated rather than edited.
* On each OpenBao release: capture its specification with `mix bao.openapi`,
  run `mix bao.gen`, review the diff — new functions, removed options —
  and let the coverage test confirm nothing is left uncovered.

### Out of scope

* **Typed responses for everything.** Only 232 of the 761 operations
  describe their response at all. Types are added where an operation is
  curated, not inferred for all of them.
* **Plugins that do not ship with OpenBao.** The specification describes
  what is mounted; an external plugin is covered once it is mounted during
  the capture.

## Appendix: coverage by operation

Every operation in the specification and the function that covers it,
grouped by module. Curated functions come first in each group.

### Secrets engines (by operation)

<details>
<summary><code>ExBao.Transit</code> — 42 operations, 8 curated</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `create_key` | POST | `/transit/keys/{name}` | **curated** | Managed named encryption keys |
| `decrypt` | POST | `/transit/decrypt/{name}` | **curated** | Decrypt a ciphertext value using a named key |
| `delete_key` | DELETE | `/transit/keys/{name}` | **curated** | Managed named encryption keys |
| `encrypt` | POST | `/transit/encrypt/{name}` | **curated** | Encrypt a plaintext value or a batch of plaintext blocks using a named key |
| `list_keys` | GET | `/transit/keys` | **curated** | Managed named encryption keys |
| `read_key` | GET | `/transit/keys/{name}` | **curated** | Managed named encryption keys |
| `rewrap` | POST | `/transit/rewrap/{name}` | **curated** | Rewrap ciphertext |
| `rotate` | POST | `/transit/keys/{name}/rotate` | **curated** | Rotate named encryption key |
| `back_up_key` | GET | `/transit/backup/{name}` | generated | Backup the named key |
| `byok_key` | GET | `/transit/byok-export/{destination}/{source}` | generated | Securely export named encryption or signing key |
| `byok_key_version` | GET | `/transit/byok-export/{destination}/{source}/{version}` | generated | Securely export named encryption or signing key |
| `configure_cache` | POST | `/transit/cache-config` | generated | Configures a new cache of the specified size |
| `configure_key` | POST | `/transit/keys/{name}/config` | generated | Configure a named encryption key |
| `configure_keys` | POST | `/transit/config/keys` | generated | Configuration common across all keys |
| `derive_key` | POST | `/transit/derive-key/{name}` | generated | Derives a new key from a base key |
| `export_key` | GET | `/transit/export/{type}/{name}` | generated | Export named encryption or signing key |
| `export_key_version` | GET | `/transit/export/{type}/{name}/{version}` | generated | Export named encryption or signing key |
| `generate_data_key` | POST | `/transit/datakey/{plaintext}/{name}` | generated | Generate a data key |
| `generate_hmac` | POST | `/transit/hmac/{name}` | generated | Generate an HMAC for input data using the named key |
| `generate_hmac_with_algorithm` | POST | `/transit/hmac/{name}/{urlalgorithm}` | generated | Generate an HMAC for input data using the named key |
| `generate_random` | POST | `/transit/random` | generated | Generate random bytes |
| `generate_random_with_bytes` | POST | `/transit/random/{urlbytes}` | generated | Generate random bytes |
| `generate_random_with_source` | POST | `/transit/random/{source}` | generated | Generate random bytes |
| `generate_random_with_source_and_bytes` | POST | `/transit/random/{source}/{urlbytes}` | generated | Generate random bytes |
| `get_csr` | POST | `/transit/keys/{name}/csr` | generated | Sign a CSR with a key in transit |
| `hash` | POST | `/transit/hash` | generated | Generate a hash sum for input data |
| `hash_with_algorithm` | POST | `/transit/hash/{urlalgorithm}` | generated | Generate a hash sum for input data |
| `import_key` | POST | `/transit/keys/{name}/import` | generated | Imports an externally-generated key into a new transit key |
| `import_key_version` | POST | `/transit/keys/{name}/import_version` | generated | Imports an externally-generated key into an existing imported key |
| `read_cache_configuration` | GET | `/transit/cache-config` | generated | Returns the size of the active cache |
| `read_keys_configuration` | GET | `/transit/config/keys` | generated | Configuration common across all keys |
| `read_wrapping_key` | GET | `/transit/wrapping_key` | generated | Returns the public key to use for wrapping imported keys |
| `restore_and_rename_key` | POST | `/transit/restore/{name}` | generated | Restore the named key |
| `restore_key` | POST | `/transit/restore` | generated | Restore the named key |
| `set_chain` | POST | `/transit/keys/{name}/set-certificate` | generated | Set a certificate chain for a key in transit |
| `sign` | POST | `/transit/sign/{name}` | generated | Generate a signature for input data using the named key |
| `sign_with_algorithm` | POST | `/transit/sign/{name}/{urlalgorithm}` | generated | Generate a signature for input data using the named key |
| `soft_delete_key` | DELETE | `/transit/keys/{name}/soft-delete` | generated | Managed named encryption keys |
| `soft_delete_restore_key` | POST | `/transit/keys/{name}/soft-delete-restore` | generated | Managed named encryption keys |
| `trim_key` | POST | `/transit/keys/{name}/trim` | generated | Trim key versions of a named key |
| `verify` | POST | `/transit/verify/{name}` | generated | Verify a signature or HMAC for input data created using the named key |
| `verify_with_algorithm` | POST | `/transit/verify/{name}/{urlalgorithm}` | generated | Verify a signature or HMAC for input data created using the named key |

</details>

<details>
<summary><code>ExBao.KV</code> — 15 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `delete_data_path` | DELETE | `/secret/data/{path}` | generated | Write, Patch, Read, and Delete data in the Key-Value Store. |
| `delete_metadata_path` | DELETE | `/secret/metadata/{path}` | generated | Allows interaction with key metadata and settings in the KV store. |
| `patch_data_path` | PATCH | `/secret/data/{path}` | generated | Write, Patch, Read, and Delete data in the Key-Value Store. |
| `patch_metadata_path` | PATCH | `/secret/metadata/{path}` | generated | Allows interaction with key metadata and settings in the KV store. |
| `read_config` | GET | `/secret/config` | generated | Read the backend level settings. |
| `read_data_path` | GET | `/secret/data/{path}` | generated | Write, Patch, Read, and Delete data in the Key-Value Store. |
| `read_metadata_path` | GET | `/secret/metadata/{path}` | generated | Allows interaction with key metadata and settings in the KV store. |
| `read_subkeys_path` | GET | `/secret/subkeys/{path}` | generated | Read the structure of a secret entry from the Key-Value store with the values removed. |
| `scan_detailed_metadata_path` | GET | `/secret/detailed-metadata/{path}` | generated | Allows listing detailed information about key metadata in the KV store. |
| `write_config` | POST | `/secret/config` | generated | Configure backend level settings that are applied to every key in the key-value store. |
| `write_data_path` | POST | `/secret/data/{path}` | generated | Write, Patch, Read, and Delete data in the Key-Value Store. |
| `write_delete_path` | POST | `/secret/delete/{path}` | generated | Marks one or more versions as deleted in the KV store. |
| `write_destroy_path` | POST | `/secret/destroy/{path}` | generated | Permanently removes one or more versions in the KV store |
| `write_metadata_path` | POST | `/secret/metadata/{path}` | generated | Allows interaction with key metadata and settings in the KV store. |
| `write_undelete_path` | POST | `/secret/undelete/{path}` | generated | Undeletes one or more versions from the KV store. |

</details>

<details>
<summary><code>ExBao.KV.V1</code> — 3 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `delete_path` | DELETE | `/kv/{path}` | generated | Pass-through secret storage to the storage backend, allowing you to read/write arbitrary… |
| `read_path` | GET | `/kv/{path}` | generated | Pass-through secret storage to the storage backend, allowing you to read/write arbitrary… |
| `write_path` | POST | `/kv/{path}` | generated | Pass-through secret storage to the storage backend, allowing you to read/write arbitrary… |

</details>

<details>
<summary><code>ExBao.PKI</code> — 154 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure_acme` | POST | `/pki/config/acme` | generated | Configuration of ACME Endpoints |
| `configure_auto_tidy` | POST | `/pki/config/auto-tidy` | generated | Modifies the current configuration for automatic tidy execution. |
| `configure_ca` | POST | `/pki/config/ca` | generated | Set the CA certificate and private key used for generated credentials. |
| `configure_cluster` | POST | `/pki/config/cluster` | generated | Set cluster-local configuration, including address to this PR cluster. |
| `configure_crl` | POST | `/pki/config/crl` | generated | Configure the CRL expiration. |
| `configure_issuers` | POST | `/pki/config/issuers` | generated | Read and set the default issuer certificate for signing. |
| `configure_keys` | POST | `/pki/config/keys` | generated | Read and set the default key used for signing |
| `configure_urls` | POST | `/pki/config/urls` | generated | Set the URLs for the issuing CA, CRL and Delta CRL distribution points, and OCSP servers. |
| `cross_sign_intermediate` | POST | `/pki/intermediate/cross-sign` | generated | Generate a new CSR and private key used for signing. |
| `delete_cel_role` | DELETE | `/pki/cel/roles/{name}` | generated | Manage the cel roles that can be created with this backend. |
| `delete_eab_key` | DELETE | `/pki/eab/{key_id}` | generated | Delete an external account binding id prior to its use within an ACME account |
| `delete_issuer` | DELETE | `/pki/issuer/{issuer_ref}` | generated | Fetch a single issuer certificate. |
| `delete_key` | DELETE | `/pki/key/{key_ref}` | generated | Fetch a single issuer key |
| `delete_role` | DELETE | `/pki/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `delete_root` | DELETE | `/pki/root` | generated | Deletes the root CA key to allow a new one to be generated. |
| `generate_eab_key` | POST | `/pki/acme/new-eab` | generated | Generate external account bindings to be used for ACME |
| `generate_eab_key_for_issuer` | POST | `/pki/issuer/{issuer_ref}/acme/new-eab` | generated | Generate external account bindings to be used for ACME |
| `generate_eab_key_for_issuer_and_role` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/new-eab` | generated | Generate external account bindings to be used for ACME |
| `generate_eab_key_for_role` | POST | `/pki/roles/{role}/acme/new-eab` | generated | Generate external account bindings to be used for ACME |
| `generate_exported_key` | POST | `/pki/keys/generate/exported` | generated | Generate a new private key used for signing. |
| `generate_intermediate` | POST | `/pki/intermediate/generate/{exported}` | generated | Generate a new CSR and private key used for signing. |
| `generate_internal_key` | POST | `/pki/keys/generate/internal` | generated | Generate a new private key used for signing. |
| `generate_kms_key` | POST | `/pki/keys/generate/kms` | generated | Generate a new private key used for signing. |
| `generate_root` | POST | `/pki/root/generate/{exported}` | generated | Generate a new CA certificate and private key used for signing. |
| `import_key` | POST | `/pki/keys/import` | generated | Import the specified key. |
| `issue_with_cel_role` | POST | `/pki/cel/issue/{role}` | generated | Request a certificate using a certain cel role with the provided details. |
| `issue_with_role` | POST | `/pki/issue/{role}` | generated | Request a certificate using a certain role with the provided details. |
| `issuer_issue_with_role` | POST | `/pki/issuer/{issuer_ref}/issue/{role}` | generated | Request a certificate using a certain role with the provided details. |
| `issuer_read_crl` | GET | `/pki/issuer/{issuer_ref}/crl` | generated | Fetch an issuer's Certificate Revocation Log (CRL). |
| `issuer_read_crl_delta` | GET | `/pki/issuer/{issuer_ref}/crl/delta` | generated | Fetch an issuer's Certificate Revocation Log (CRL). |
| `issuer_read_crl_delta_der` | GET | `/pki/issuer/{issuer_ref}/crl/delta/der` | generated | Fetch an issuer's Certificate Revocation Log (CRL). |
| `issuer_read_crl_delta_pem` | GET | `/pki/issuer/{issuer_ref}/crl/delta/pem` | generated | Fetch an issuer's Certificate Revocation Log (CRL). |
| `issuer_read_crl_der` | GET | `/pki/issuer/{issuer_ref}/crl/der` | generated | Fetch an issuer's Certificate Revocation Log (CRL). |
| `issuer_read_crl_pem` | GET | `/pki/issuer/{issuer_ref}/crl/pem` | generated | Fetch an issuer's Certificate Revocation Log (CRL). |
| `issuer_resign_crls` | POST | `/pki/issuer/{issuer_ref}/resign-crls` | generated | Combine and sign with the provided issuer different CRLs |
| `issuer_sign_intermediate` | POST | `/pki/issuer/{issuer_ref}/sign-intermediate` | generated | Issue an intermediate CA certificate based on the provided CSR. |
| `issuer_sign_revocation_list` | POST | `/pki/issuer/{issuer_ref}/sign-revocation-list` | generated | Generate and sign a CRL based on the provided parameters. |
| `issuer_sign_self_issued` | POST | `/pki/issuer/{issuer_ref}/sign-self-issued` | generated | Re-issue a self-signed certificate based on the provided certificate. |
| `issuer_sign_verbatim` | POST | `/pki/issuer/{issuer_ref}/sign-verbatim` | generated | Issue a certificate directly based on the provided CSR. |
| `issuer_sign_verbatim_with_role` | POST | `/pki/issuer/{issuer_ref}/sign-verbatim/{role}` | generated | Issue a certificate directly based on the provided CSR. |
| `issuer_sign_with_role` | POST | `/pki/issuer/{issuer_ref}/sign/{role}` | generated | Request certificates using a certain role with the provided details. |
| `issuers_generate_intermediate` | POST | `/pki/issuers/generate/intermediate/{exported}` | generated | Generate a new CSR and private key used for signing. |
| `issuers_generate_root` | POST | `/pki/issuers/generate/root/{exported}` | generated | Generate a new CA certificate and private key used for signing. |
| `issuers_import_bundle` | POST | `/pki/issuers/import/bundle` | generated | Import the specified issuing certificates. |
| `issuers_import_cert` | POST | `/pki/issuers/import/cert` | generated | Import the specified issuing certificates. |
| `list_cel_roles` | GET | `/pki/cel/roles` | generated | List the existing CEL roles in this backend |
| `list_certs` | GET | `/pki/certs` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `list_certs_detailed` | GET | `/pki/certs/detailed` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `list_eab_keys` | GET | `/pki/eab` | generated | list external account bindings to be used for ACME |
| `list_issuers` | GET | `/pki/issuers` | generated | Fetch a list of CA certificates. |
| `list_keys` | GET | `/pki/keys` | generated | Fetch a list of all issuer keys |
| `list_revoked_certs` | GET | `/pki/certs/revoked` | generated | List all revoked serial numbers within the local cluster |
| `list_roles` | GET | `/pki/roles` | generated | List the existing roles in this backend |
| `patch_cel_role` | PATCH | `/pki/cel/roles/{name}` | generated | Manage the cel roles that can be created with this backend. |
| `patch_issuer` | PATCH | `/pki/issuer/{issuer_ref}` | generated | Fetch a single issuer certificate. |
| `patch_role` | PATCH | `/pki/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `query_ocsp` | POST | `/pki/ocsp` | generated | Query a certificate's revocation status through OCSP' |
| `query_ocsp_with_get_req` | GET | `/pki/ocsp/{req}` | generated | Query a certificate's revocation status through OCSP' |
| `read_acme_configuration` | GET | `/pki/config/acme` | generated | Configuration of ACME Endpoints |
| `read_acme_directory` | GET | `/pki/acme/directory` | generated | An endpoint implementing the standard ACME protocol |
| `read_acme_new_nonce` | GET | `/pki/acme/new-nonce` | generated | An endpoint implementing the standard ACME protocol |
| `read_auto_tidy_configuration` | GET | `/pki/config/auto-tidy` | generated | Modifies the current configuration for automatic tidy execution. |
| `read_ca_chain_pem` | GET | `/pki/ca_chain` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_ca_der` | GET | `/pki/ca` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_ca_pem` | GET | `/pki/ca/pem` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cel_role` | GET | `/pki/cel/roles/{name}` | generated | Manage the cel roles that can be created with this backend. |
| `read_cert` | GET | `/pki/cert/{serial}` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cert_ca_chain` | GET | `/pki/cert/ca_chain` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cert_crl` | GET | `/pki/cert/crl` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cert_delta_crl` | GET | `/pki/cert/delta-crl` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cert_raw_der` | GET | `/pki/cert/{serial}/raw` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cert_raw_pem` | GET | `/pki/cert/{serial}/raw/pem` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_cluster_configuration` | GET | `/pki/config/cluster` | generated | Set cluster-local configuration, including address to this PR cluster. |
| `read_crl_configuration` | GET | `/pki/config/crl` | generated | Configure the CRL expiration. |
| `read_crl_delta` | GET | `/pki/crl/delta` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_crl_delta_pem` | GET | `/pki/crl/delta/pem` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_crl_der` | GET | `/pki/crl` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_crl_pem` | GET | `/pki/crl/pem` | generated | Fetch a CA, CRL, CA Chain, or non-revoked certificate. |
| `read_issuer` | GET | `/pki/issuer/{issuer_ref}` | generated | Fetch a single issuer certificate. |
| `read_issuer_der` | GET | `/pki/issuer/{issuer_ref}/der` | generated | Fetch a single issuer certificate. |
| `read_issuer_issuer_ref_acme_directory` | GET | `/pki/issuer/{issuer_ref}/acme/directory` | generated | An endpoint implementing the standard ACME protocol |
| `read_issuer_issuer_ref_acme_new_nonce` | GET | `/pki/issuer/{issuer_ref}/acme/new-nonce` | generated | An endpoint implementing the standard ACME protocol |
| `read_issuer_issuer_ref_roles_role_acme_directory` | GET | `/pki/issuer/{issuer_ref}/roles/{role}/acme/directory` | generated | An endpoint implementing the standard ACME protocol |
| `read_issuer_issuer_ref_roles_role_acme_new_nonce` | GET | `/pki/issuer/{issuer_ref}/roles/{role}/acme/new-nonce` | generated | An endpoint implementing the standard ACME protocol |
| `read_issuer_json` | GET | `/pki/issuer/{issuer_ref}/json` | generated | Fetch a single issuer certificate. |
| `read_issuer_pem` | GET | `/pki/issuer/{issuer_ref}/pem` | generated | Fetch a single issuer certificate. |
| `read_issuers_configuration` | GET | `/pki/config/issuers` | generated | Read and set the default issuer certificate for signing. |
| `read_key` | GET | `/pki/key/{key_ref}` | generated | Fetch a single issuer key |
| `read_keys_configuration` | GET | `/pki/config/keys` | generated | Read and set the default key used for signing |
| `read_role` | GET | `/pki/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `read_roles_role_acme_directory` | GET | `/pki/roles/{role}/acme/directory` | generated | An endpoint implementing the standard ACME protocol |
| `read_roles_role_acme_new_nonce` | GET | `/pki/roles/{role}/acme/new-nonce` | generated | An endpoint implementing the standard ACME protocol |
| `read_urls_configuration` | GET | `/pki/config/urls` | generated | Set the URLs for the issuing CA, CRL and Delta CRL distribution points, and OCSP servers. |
| `replace_root` | POST | `/pki/root/replace` | generated | Read and set the default issuer certificate for signing. |
| `revoke` | POST | `/pki/revoke` | generated | Revoke a certificate by serial number or with explicit certificate. When calling /revoke-… |
| `revoke_issuer` | POST | `/pki/issuer/{issuer_ref}/revoke` | generated | Revoke the specified issuer certificate. |
| `revoke_with_key` | POST | `/pki/revoke-with-key` | generated | Revoke a certificate by serial number or with explicit certificate. When calling /revoke-… |
| `root_sign_intermediate` | POST | `/pki/root/sign-intermediate` | generated | Issue an intermediate CA certificate based on the provided CSR. |
| `root_sign_self_issued` | POST | `/pki/root/sign-self-issued` | generated | Re-issue a self-signed certificate based on the provided certificate. |
| `rotate_crl` | GET | `/pki/crl/rotate` | generated | Force a rebuild of the CRL. |
| `rotate_delta_crl` | GET | `/pki/crl/rotate-delta` | generated | Force a rebuild of the delta CRL. |
| `rotate_root` | POST | `/pki/root/rotate/{exported}` | generated | Generate a new CA certificate and private key used for signing. |
| `set_signed_intermediate` | POST | `/pki/intermediate/set-signed` | generated | Provide the signed intermediate CA cert. |
| `sign_verbatim` | POST | `/pki/sign-verbatim` | generated | Issue a certificate directly based on the provided CSR. |
| `sign_verbatim_with_role` | POST | `/pki/sign-verbatim/{role}` | generated | Issue a certificate directly based on the provided CSR. |
| `sign_with_cel_role` | POST | `/pki/cel/sign/{role}` | generated | Request certificates using a certain CEL role with the provided details. |
| `sign_with_role` | POST | `/pki/sign/{role}` | generated | Request certificates using a certain role with the provided details. |
| `tidy` | POST | `/pki/tidy` | generated | Tidy up the backend by removing expired certificates, revocation information, or both. |
| `tidy_cancel` | POST | `/pki/tidy-cancel` | generated | Cancels a currently running tidy operation. |
| `tidy_status` | GET | `/pki/tidy-status` | generated | Returns the status of the tidy operation. |
| `write_acme_account_kid` | POST | `/pki/acme/account/{kid}` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_authorization_auth_id` | POST | `/pki/acme/authorization/{auth_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_challenge_auth_id_challenge_type` | POST | `/pki/acme/challenge/{auth_id}/{challenge_type}` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_new_account` | POST | `/pki/acme/new-account` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_new_order` | POST | `/pki/acme/new-order` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_order_order_id` | POST | `/pki/acme/order/{order_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_order_order_id_cert` | POST | `/pki/acme/order/{order_id}/cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_order_order_id_finalize` | POST | `/pki/acme/order/{order_id}/finalize` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_orders` | POST | `/pki/acme/orders` | generated | An endpoint implementing the standard ACME protocol |
| `write_acme_revoke_cert` | POST | `/pki/acme/revoke-cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_cel_role` | POST | `/pki/cel/roles/{name}` | generated | Manage the cel roles that can be created with this backend. |
| `write_issuer` | POST | `/pki/issuer/{issuer_ref}` | generated | Fetch a single issuer certificate. |
| `write_issuer_issuer_ref_acme_account_kid` | POST | `/pki/issuer/{issuer_ref}/acme/account/{kid}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_authorization_auth_id` | POST | `/pki/issuer/{issuer_ref}/acme/authorization/{auth_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_challenge_auth_id_challenge_type` | POST | `/pki/issuer/{issuer_ref}/acme/challenge/{auth_id}/{challenge_type}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_new_account` | POST | `/pki/issuer/{issuer_ref}/acme/new-account` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_new_order` | POST | `/pki/issuer/{issuer_ref}/acme/new-order` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_order_order_id` | POST | `/pki/issuer/{issuer_ref}/acme/order/{order_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_order_order_id_cert` | POST | `/pki/issuer/{issuer_ref}/acme/order/{order_id}/cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_order_order_id_finalize` | POST | `/pki/issuer/{issuer_ref}/acme/order/{order_id}/finalize` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_orders` | POST | `/pki/issuer/{issuer_ref}/acme/orders` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_acme_revoke_cert` | POST | `/pki/issuer/{issuer_ref}/acme/revoke-cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_account_kid` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/account/{kid}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_authorization_auth_id` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/authorization/{auth_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_challenge_auth_id_challenge_type` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/challenge/{auth_id}/{challenge_type}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_new_account` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/new-account` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_new_order` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/new-order` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_order_order_id` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/order/{order_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_order_order_id_cert` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/order/{order_id}/cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_order_order_id_finalize` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/order/{order_id}/finalize` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_orders` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/orders` | generated | An endpoint implementing the standard ACME protocol |
| `write_issuer_issuer_ref_roles_role_acme_revoke_cert` | POST | `/pki/issuer/{issuer_ref}/roles/{role}/acme/revoke-cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_key` | POST | `/pki/key/{key_ref}` | generated | Fetch a single issuer key |
| `write_role` | POST | `/pki/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `write_roles_role_acme_account_kid` | POST | `/pki/roles/{role}/acme/account/{kid}` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_authorization_auth_id` | POST | `/pki/roles/{role}/acme/authorization/{auth_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_challenge_auth_id_challenge_type` | POST | `/pki/roles/{role}/acme/challenge/{auth_id}/{challenge_type}` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_new_account` | POST | `/pki/roles/{role}/acme/new-account` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_new_order` | POST | `/pki/roles/{role}/acme/new-order` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_order_order_id` | POST | `/pki/roles/{role}/acme/order/{order_id}` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_order_order_id_cert` | POST | `/pki/roles/{role}/acme/order/{order_id}/cert` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_order_order_id_finalize` | POST | `/pki/roles/{role}/acme/order/{order_id}/finalize` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_orders` | POST | `/pki/roles/{role}/acme/orders` | generated | An endpoint implementing the standard ACME protocol |
| `write_roles_role_acme_revoke_cert` | POST | `/pki/roles/{role}/acme/revoke-cert` | generated | An endpoint implementing the standard ACME protocol |

</details>

<details>
<summary><code>ExBao.SSH</code> — 26 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure_default_ca` | POST | `/ssh/config/ca` | generated | Configure the default SSH issuer used for signing and verification operations. |
| `configure_zero_address` | POST | `/ssh/config/zeroaddress` | generated | Assign zero address as default CIDR block for select roles. |
| `delete_issuer` | DELETE | `/ssh/issuer/{issuer_ref}` | generated | Fetch a single issuer. |
| `delete_role` | DELETE | `/ssh/roles/{role}` | generated | Manage the 'roles' that can be created with this backend. |
| `delete_zero_address_configuration` | DELETE | `/ssh/config/zeroaddress` | generated | Assign zero address as default CIDR block for select roles. |
| `generate_credentials` | POST | `/ssh/creds/{role}` | generated | Creates a credential for establishing SSH connection with the remote host. |
| `get_issuer` | GET | `/ssh/issuer/{issuer_ref}/public_key` | generated | Fetch a single issuer. |
| `issue_certificate` | POST | `/ssh/issue/{role}` | generated | Request a certificate using a certain role with the provided details. |
| `list_issuers` | GET | `/ssh/issuers` | generated | Fetch a list of all issuers. |
| `list_roles` | GET | `/ssh/roles` | generated | Manage the 'roles' that can be created with this backend. |
| `list_roles_by_ip` | POST | `/ssh/lookup` | generated | List all the roles associated with the given IP address. |
| `purge_ca` | DELETE | `/ssh/config/ca` | generated | Configure the default SSH issuer used for signing and verification operations. |
| `read_default_ca` | GET | `/ssh/config/ca` | generated | Configure the default SSH issuer used for signing and verification operations. |
| `read_issuer` | GET | `/ssh/issuer/{issuer_ref}` | generated | Fetch a single issuer. |
| `read_public_key` | GET | `/ssh/public_key` | generated | Retrieve the 'default' issuer's public key. |
| `read_read` | GET | `/ssh/config/issuers` | generated | Configure or read the default SSH certificate issuer. |
| `read_role` | GET | `/ssh/roles/{role}` | generated | Manage the 'roles' that can be created with this backend. |
| `read_zero_address_configuration` | GET | `/ssh/config/zeroaddress` | generated | Assign zero address as default CIDR block for select roles. |
| `sign_certificate` | POST | `/ssh/sign/{role}` | generated | Request signing an SSH key using a certain role with the provided details. |
| `submit_issuer` | POST | `/ssh/issuers/import` | generated | Submit a new issuer with an optional explicit name. |
| `submit_issuers_import_issuer_name` | POST | `/ssh/issuers/import/{issuer_name}` | generated | Submit a new issuer with an optional explicit name. |
| `tidy_dynamic_host_keys` | DELETE | `/ssh/tidy/dynamic-keys` | generated | This endpoint removes the stored host keys used for the removed Dynamic Key feature, if p… |
| `update_issuer` | POST | `/ssh/issuer/{issuer_ref}` | generated | Fetch a single issuer. |
| `verify_otp` | POST | `/ssh/verify` | generated | Validate the OTP provided by OpenBao SSH Agent. |
| `write_issuer_config` | POST | `/ssh/config/issuers` | generated | Configure or read the default SSH certificate issuer. |
| `write_role` | POST | `/ssh/roles/{role}` | generated | Manage the 'roles' that can be created with this backend. |

</details>

<details>
<summary><code>ExBao.TOTP</code> — 6 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `create_key` | POST | `/totp/keys/{name}` | generated | Manage the keys that can be created with this backend. |
| `delete_key` | DELETE | `/totp/keys/{name}` | generated | Manage the keys that can be created with this backend. |
| `generate_code` | GET | `/totp/code/{name}` | generated | Request time-based one-time use password or validate a password for a certain key. |
| `list_keys` | GET | `/totp/keys` | generated | Manage the keys that can be created with this backend. |
| `read_key` | GET | `/totp/keys/{name}` | generated | Manage the keys that can be created with this backend. |
| `validate_code` | POST | `/totp/code/{name}` | generated | Request time-based one-time use password or validate a password for a certain key. |

</details>

<details>
<summary><code>ExBao.Database</code> — 17 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure_connection` | POST | `/database/config/{name}` | generated | Configure connection details to a database plugin. |
| `delete_connection_configuration` | DELETE | `/database/config/{name}` | generated | Configure connection details to a database plugin. |
| `delete_role` | DELETE | `/database/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `delete_static_role` | DELETE | `/database/static-roles/{name}` | generated | Manage the static roles that can be created with this backend. |
| `generate_credentials` | GET | `/database/creds/{name}` | generated | Request database credentials for a certain role. |
| `list_connections` | GET | `/database/config` | generated | Configure connection details to a database plugin. |
| `list_roles` | GET | `/database/roles` | generated | Manage the roles that can be created with this backend. |
| `list_static_roles` | GET | `/database/static-roles` | generated | Manage the static roles that can be created with this backend. |
| `read_connection_configuration` | GET | `/database/config/{name}` | generated | Configure connection details to a database plugin. |
| `read_role` | GET | `/database/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `read_static_role` | GET | `/database/static-roles/{name}` | generated | Manage the static roles that can be created with this backend. |
| `read_static_role_credentials` | GET | `/database/static-creds/{name}` | generated | Request database credentials for a certain static role. These credentials are rotated per… |
| `reset_connection` | POST | `/database/reset/{name}` | generated | Resets a database plugin. |
| `rotate_root_credentials` | POST | `/database/rotate-root/{name}` | generated | Request to rotate the root credentials for a certain database connection. |
| `rotate_static_role_credentials` | POST | `/database/rotate-role/{name}` | generated | Request to rotate the credentials for a static user account. |
| `write_role` | POST | `/database/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `write_static_role` | POST | `/database/static-roles/{name}` | generated | Manage the static roles that can be created with this backend. |

</details>

<details>
<summary><code>ExBao.RabbitMQ</code> — 8 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure_connection` | POST | `/rabbitmq/config/connection` | generated | Configure the connection URI, username, and password to talk to RabbitMQ management HTTP… |
| `configure_lease` | POST | `/rabbitmq/config/lease` | generated | Configure the lease parameters for generated credentials |
| `delete_role` | DELETE | `/rabbitmq/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `list_roles` | GET | `/rabbitmq/roles` | generated | Manage the roles that can be created with this backend. |
| `read_lease_configuration` | GET | `/rabbitmq/config/lease` | generated | Configure the lease parameters for generated credentials |
| `read_role` | GET | `/rabbitmq/roles/{name}` | generated | Manage the roles that can be created with this backend. |
| `request_credentials` | GET | `/rabbitmq/creds/{name}` | generated | Request RabbitMQ credentials for a certain role. |
| `write_role` | POST | `/rabbitmq/roles/{name}` | generated | Manage the roles that can be created with this backend. |

</details>

<details>
<summary><code>ExBao.Kubernetes</code> — 9 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `check_configuration` | GET | `/kubernetes/check` | generated | Checks the Kubernetes configuration is valid. |
| `configure` | POST | `/kubernetes/config` | generated | Configure the Kubernetes secret engine plugin. |
| `delete_configuration` | DELETE | `/kubernetes/config` | generated | Configure the Kubernetes secret engine plugin. |
| `delete_role` | DELETE | `/kubernetes/roles/{name}` | generated | Manage the roles that can be created with this secrets engine. |
| `generate_credentials` | POST | `/kubernetes/creds/{name}` | generated | Request Kubernetes service account credentials for a given OpenBao role. |
| `list_roles` | GET | `/kubernetes/roles` | generated | List the existing roles in this secrets engine. |
| `read_configuration` | GET | `/kubernetes/config` | generated | Configure the Kubernetes secret engine plugin. |
| `read_role` | GET | `/kubernetes/roles/{name}` | generated | Manage the roles that can be created with this secrets engine. |
| `write_role` | POST | `/kubernetes/roles/{name}` | generated | Manage the roles that can be created with this secrets engine. |

</details>

<details>
<summary><code>ExBao.LDAP</code> — 23 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure` | POST | `/ldap/config` | generated | Configure the LDAP secrets engine plugin. |
| `delete_configuration` | DELETE | `/ldap/config` | generated | Configure the LDAP secrets engine plugin. |
| `delete_dynamic_role` | DELETE | `/ldap/role/{name}` | generated | Manage the static roles that can be created with this backend. |
| `delete_static_role` | DELETE | `/ldap/static-role/{name}` | generated | Manage the static roles that can be created with this backend. |
| `library_check_in` | POST | `/ldap/library/{name}/check-in` | generated | Check service accounts in to the library. |
| `library_check_out` | POST | `/ldap/library/{name}/check-out` | generated | Check a service account out from the library. |
| `library_check_status` | GET | `/ldap/library/{name}/status` | generated | Check the status of the service accounts in a library set. |
| `library_configure` | POST | `/ldap/library/{name}` | generated | Update a library set. |
| `library_delete` | DELETE | `/ldap/library/{name}` | generated | Delete a library set. |
| `library_force_check_in` | POST | `/ldap/library/manage/{name}/check-in` | generated | Check service accounts in to the library. |
| `library_list` | GET | `/ldap/library` | generated | List the name of each set of service accounts currently stored. |
| `library_read` | GET | `/ldap/library/{name}` | generated | Read a library set. |
| `list_dynamic_roles` | GET | `/ldap/role` | generated | List all the dynamic roles OpenBao is currently managing in LDAP. |
| `list_static_roles` | GET | `/ldap/static-role` | generated | This path lists all the static roles OpenBao is currently managing within the LDAP system. |
| `read_configuration` | GET | `/ldap/config` | generated | Configure the LDAP secrets engine plugin. |
| `read_dynamic_role` | GET | `/ldap/role/{name}` | generated | Manage the static roles that can be created with this backend. |
| `read_static_role` | GET | `/ldap/static-role/{name}` | generated | Manage the static roles that can be created with this backend. |
| `request_dynamic_role_credentials` | GET | `/ldap/creds/{name}` | generated | Request LDAP credentials for a dynamic role. These credentials are created within the LDA… |
| `request_static_role_credentials` | GET | `/ldap/static-cred/{name}` | generated | Request LDAP credentials for a certain static role. These credentials are rotated periodi… |
| `rotate_root_credentials` | POST | `/ldap/rotate-root` | generated | Request to rotate the root credentials OpenBao uses for the LDAP administrator account. |
| `rotate_static_role` | POST | `/ldap/rotate-role/{name}` | generated | Request to rotate the credentials for a static user account. |
| `write_dynamic_role` | POST | `/ldap/role/{name}` | generated | Manage the static roles that can be created with this backend. |
| `write_static_role` | POST | `/ldap/static-role/{name}` | generated | Manage the static roles that can be created with this backend. |

</details>

<details>
<summary><code>ExBao.Cubbyhole</code> — 3 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `delete` | DELETE | `/cubbyhole/{path}` | generated | Deletes the secret at the specified location. |
| `read` | GET | `/cubbyhole/{path}` | generated | Retrieve the secret at the specified location. |
| `write` | POST | `/cubbyhole/{path}` | generated | Store a secret at the specified location. |

</details>

### Auth methods (by operation)

<details>
<summary><code>ExBao.Auth.AppRole</code> — 51 operations, 3 curated</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `generate_secret_id` | POST | `/auth/approle/role/{role_name}/secret-id` | **curated** | Generate a SecretID against this role. |
| `login` | POST | `/auth/approle/login` | **curated** | Issue a token based on the credentials supplied |
| `read_role_id` | GET | `/auth/approle/role/{role_name}/role-id` | **curated** | Returns the 'role_id' of the role. |
| `delete_bind_secret_id` | DELETE | `/auth/approle/role/{role_name}/bind-secret-id` | generated | Impose secret_id to be presented during login using this role. |
| `delete_bound_cidr_list` | DELETE | `/auth/approle/role/{role_name}/bound-cidr-list` | generated | Deprecated: Comma separated list of CIDR blocks, if set, specifies blocks of IP addresses… |
| `delete_period` | DELETE | `/auth/approle/role/{role_name}/period` | generated | Updates the value of 'period' on the role |
| `delete_policies` | DELETE | `/auth/approle/role/{role_name}/policies` | generated | Policies of the role. |
| `delete_role` | DELETE | `/auth/approle/role/{role_name}` | generated | Register an role with the backend. |
| `delete_secret_id_bound_cidrs` | DELETE | `/auth/approle/role/{role_name}/secret-id-bound-cidrs` | generated | Comma separated list of CIDR blocks, if set, specifies blocks of IP addresses which can p… |
| `delete_secret_id_num_uses` | DELETE | `/auth/approle/role/{role_name}/secret-id-num-uses` | generated | Use limit of the SecretID generated against the role. |
| `delete_secret_id_ttl` | DELETE | `/auth/approle/role/{role_name}/secret-id-ttl` | generated | Duration in seconds of the SecretID generated against the role. |
| `delete_token_bound_cidrs` | DELETE | `/auth/approle/role/{role_name}/token-bound-cidrs` | generated | Comma separated string or list of CIDR blocks. If set, specifies the blocks of IP address… |
| `delete_token_max_ttl` | DELETE | `/auth/approle/role/{role_name}/token-max-ttl` | generated | Duration in seconds, the maximum lifetime of the tokens issued by using the SecretIDs tha… |
| `delete_token_num_uses` | DELETE | `/auth/approle/role/{role_name}/token-num-uses` | generated | Number of times issued tokens can be used |
| `delete_token_ttl` | DELETE | `/auth/approle/role/{role_name}/token-ttl` | generated | Duration in seconds, the lifetime of the token issued by using the SecretID that is gener… |
| `destroy_secret_id` | POST | `/auth/approle/role/{role_name}/secret-id/destroy` | generated | Invalidate an issued secret_id |
| `destroy_secret_id2` | DELETE | `/auth/approle/role/{role_name}/secret-id/destroy` | generated | Invalidate an issued secret_id |
| `destroy_secret_id_by_accessor` | POST | `/auth/approle/role/{role_name}/secret-id-accessor/destroy` | generated |  |
| `destroy_secret_id_by_accessor2` | DELETE | `/auth/approle/role/{role_name}/secret-id-accessor/destroy` | generated |  |
| `list_roles` | GET | `/auth/approle/role` | generated | Lists all the roles registered with the backend. |
| `list_secret_ids` | GET | `/auth/approle/role/{role_name}/secret-id` | generated | Generate a SecretID against this role. |
| `look_up_secret_id` | POST | `/auth/approle/role/{role_name}/secret-id/lookup` | generated | Read the properties of an issued secret_id |
| `look_up_secret_id_by_accessor` | POST | `/auth/approle/role/{role_name}/secret-id-accessor/lookup` | generated |  |
| `read_bind_secret_id` | GET | `/auth/approle/role/{role_name}/bind-secret-id` | generated | Impose secret_id to be presented during login using this role. |
| `read_bound_cidr_list` | GET | `/auth/approle/role/{role_name}/bound-cidr-list` | generated | Deprecated: Comma separated list of CIDR blocks, if set, specifies blocks of IP addresses… |
| `read_local_secret_ids` | GET | `/auth/approle/role/{role_name}/local-secret-ids` | generated | Enables cluster local secret IDs |
| `read_period` | GET | `/auth/approle/role/{role_name}/period` | generated | Updates the value of 'period' on the role |
| `read_policies` | GET | `/auth/approle/role/{role_name}/policies` | generated | Policies of the role. |
| `read_role` | GET | `/auth/approle/role/{role_name}` | generated | Register an role with the backend. |
| `read_secret_id_bound_cidrs` | GET | `/auth/approle/role/{role_name}/secret-id-bound-cidrs` | generated | Comma separated list of CIDR blocks, if set, specifies blocks of IP addresses which can p… |
| `read_secret_id_num_uses` | GET | `/auth/approle/role/{role_name}/secret-id-num-uses` | generated | Use limit of the SecretID generated against the role. |
| `read_secret_id_ttl` | GET | `/auth/approle/role/{role_name}/secret-id-ttl` | generated | Duration in seconds of the SecretID generated against the role. |
| `read_token_bound_cidrs` | GET | `/auth/approle/role/{role_name}/token-bound-cidrs` | generated | Comma separated string or list of CIDR blocks. If set, specifies the blocks of IP address… |
| `read_token_max_ttl` | GET | `/auth/approle/role/{role_name}/token-max-ttl` | generated | Duration in seconds, the maximum lifetime of the tokens issued by using the SecretIDs tha… |
| `read_token_num_uses` | GET | `/auth/approle/role/{role_name}/token-num-uses` | generated | Number of times issued tokens can be used |
| `read_token_ttl` | GET | `/auth/approle/role/{role_name}/token-ttl` | generated | Duration in seconds, the lifetime of the token issued by using the SecretID that is gener… |
| `tidy_secret_id` | POST | `/auth/approle/tidy/secret-id` | generated | Trigger the clean-up of expired SecretID entries. |
| `write_bind_secret_id` | POST | `/auth/approle/role/{role_name}/bind-secret-id` | generated | Impose secret_id to be presented during login using this role. |
| `write_bound_cidr_list` | POST | `/auth/approle/role/{role_name}/bound-cidr-list` | generated | Deprecated: Comma separated list of CIDR blocks, if set, specifies blocks of IP addresses… |
| `write_custom_secret_id` | POST | `/auth/approle/role/{role_name}/custom-secret-id` | generated | Assign a SecretID of choice against the role. |
| `write_period` | POST | `/auth/approle/role/{role_name}/period` | generated | Updates the value of 'period' on the role |
| `write_policies` | POST | `/auth/approle/role/{role_name}/policies` | generated | Policies of the role. |
| `write_role` | POST | `/auth/approle/role/{role_name}` | generated | Register an role with the backend. |
| `write_role_id` | POST | `/auth/approle/role/{role_name}/role-id` | generated | Returns the 'role_id' of the role. |
| `write_secret_id_bound_cidrs` | POST | `/auth/approle/role/{role_name}/secret-id-bound-cidrs` | generated | Comma separated list of CIDR blocks, if set, specifies blocks of IP addresses which can p… |
| `write_secret_id_num_uses` | POST | `/auth/approle/role/{role_name}/secret-id-num-uses` | generated | Use limit of the SecretID generated against the role. |
| `write_secret_id_ttl` | POST | `/auth/approle/role/{role_name}/secret-id-ttl` | generated | Duration in seconds of the SecretID generated against the role. |
| `write_token_bound_cidrs` | POST | `/auth/approle/role/{role_name}/token-bound-cidrs` | generated | Comma separated string or list of CIDR blocks. If set, specifies the blocks of IP address… |
| `write_token_max_ttl` | POST | `/auth/approle/role/{role_name}/token-max-ttl` | generated | Duration in seconds, the maximum lifetime of the tokens issued by using the SecretIDs tha… |
| `write_token_num_uses` | POST | `/auth/approle/role/{role_name}/token-num-uses` | generated | Number of times issued tokens can be used |
| `write_token_ttl` | POST | `/auth/approle/role/{role_name}/token-ttl` | generated | Duration in seconds, the lifetime of the token issued by using the SecretID that is gener… |

</details>

<details>
<summary><code>ExBao.Auth.Token</code> — 21 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `create` | POST | `/auth/token/create` | generated | The token create path is used to create new tokens. |
| `create_against_role` | POST | `/auth/token/create/{role_name}` | generated | This token create path is used to create new tokens adhering to the given role. |
| `create_orphan` | POST | `/auth/token/create-orphan` | generated | The token create path is used to create new orphan tokens. |
| `delete_role` | DELETE | `/auth/token/roles/{role_name}` | generated |  |
| `list_accessors` | GET | `/auth/token/accessors` | generated | List token accessors, which can then be be used to iterate and discover their properties… |
| `list_roles` | GET | `/auth/token/roles` | generated | This endpoint lists configured roles. |
| `look_up_by_accessor` | POST | `/auth/token/lookup-accessor` | generated | This endpoint will lookup a token associated with the given accessor and its properties.… |
| `look_up_get` | GET | `/auth/token/lookup` | generated | This endpoint will lookup a token and its properties. |
| `look_up_self_get` | GET | `/auth/token/lookup-self` | generated | This endpoint will lookup a token and its properties. |
| `look_up_self_update` | POST | `/auth/token/lookup-self` | generated | This endpoint will lookup a token and its properties. |
| `look_up_update` | POST | `/auth/token/lookup` | generated | This endpoint will lookup a token and its properties. |
| `read_role` | GET | `/auth/token/roles/{role_name}` | generated |  |
| `renew` | POST | `/auth/token/renew` | generated | This endpoint will renew the given token and prevent expiration. |
| `renew_accessor` | POST | `/auth/token/renew-accessor` | generated | This endpoint will renew a token associated with the given accessor and its properties. R… |
| `renew_self` | POST | `/auth/token/renew-self` | generated | This endpoint will renew the token used to call it and prevent expiration. |
| `revoke` | POST | `/auth/token/revoke` | generated | This endpoint will delete the given token and all of its child tokens. |
| `revoke_accessor` | POST | `/auth/token/revoke-accessor` | generated | This endpoint will delete the token associated with the accessor and all of its child tok… |
| `revoke_orphan` | POST | `/auth/token/revoke-orphan` | generated | This endpoint will delete the token and orphan its child tokens. |
| `revoke_self` | POST | `/auth/token/revoke-self` | generated | This endpoint will delete the token used to call it and all of its child tokens. |
| `tidy` | POST | `/auth/token/tidy` | generated | This endpoint performs cleanup tasks that can be run if certain error conditions have occ… |
| `write_role` | POST | `/auth/token/roles/{role_name}` | generated |  |

</details>

<details>
<summary><code>ExBao.Auth.Cert</code> — 11 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure` | POST | `/auth/cert/config` | generated |  |
| `delete_certificate` | DELETE | `/auth/cert/certs/{name}` | generated | Manage trusted certificates used for authentication. |
| `delete_crl` | DELETE | `/auth/cert/crls/{name}` | generated | Manage Certificate Revocation Lists checked during authentication. |
| `list_certificates` | GET | `/auth/cert/certs` | generated | Manage trusted certificates used for authentication. |
| `list_crls` | GET | `/auth/cert/crls` | generated | Manage Certificate Revocation Lists checked during authentication. |
| `login` | POST | `/auth/cert/login` | generated |  |
| `read_certificate` | GET | `/auth/cert/certs/{name}` | generated | Manage trusted certificates used for authentication. |
| `read_configuration` | GET | `/auth/cert/config` | generated |  |
| `read_crl` | GET | `/auth/cert/crls/{name}` | generated | Manage Certificate Revocation Lists checked during authentication. |
| `write_certificate` | POST | `/auth/cert/certs/{name}` | generated | Manage trusted certificates used for authentication. |
| `write_crl` | POST | `/auth/cert/crls/{name}` | generated | Manage Certificate Revocation Lists checked during authentication. |

</details>

<details>
<summary><code>ExBao.Auth.JWT</code> — 17 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure` | POST | `/auth/jwt/config` | generated | Configure the JWT authentication backend. |
| `delete_role` | DELETE | `/auth/jwt/role/{name}` | generated | Delete an existing role. |
| `delete_role_cel` | DELETE | `/auth/jwt/cel/role/{name}` | generated | Manage the CEL roles that can be created with this backend. |
| `list_cel` | GET | `/auth/jwt/cel/role` | generated | List the existing CEL roles in this backend |
| `list_roles` | GET | `/auth/jwt/role` | generated | Lists all the roles registered with the backend. |
| `login` | POST | `/auth/jwt/login` | generated | Authenticates to OpenBao using a JWT (or OIDC) token. |
| `login_cel` | POST | `/auth/jwt/cel/login` | generated | Authenticates to OpenBao using a JWT (or OIDC) token against a CEL role. |
| `oidc_callback` | GET | `/auth/jwt/oidc/callback` | generated | Callback endpoint to complete an OIDC login. |
| `oidc_callback_form_post` | POST | `/auth/jwt/oidc/callback` | generated | Callback endpoint to handle form_posts. |
| `oidc_request_authorization_url` | POST | `/auth/jwt/oidc/auth_url` | generated | Request an authorization URL to start an OIDC login flow. |
| `patch_role` | PATCH | `/auth/jwt/cel/role/{name}` | generated | Manage the CEL roles that can be created with this backend. |
| `read_configuration` | GET | `/auth/jwt/config` | generated | Read the current JWT authentication backend configuration. |
| `read_role` | GET | `/auth/jwt/role/{name}` | generated | Read an existing role. |
| `read_role_cel` | GET | `/auth/jwt/cel/role/{name}` | generated | Manage the CEL roles that can be created with this backend. |
| `write_oidc_poll` | POST | `/auth/jwt/oidc/poll` | generated | Poll endpoint to complete an OIDC login. |
| `write_role` | POST | `/auth/jwt/role/{name}` | generated | Register an role with the backend. |
| `write_role_cel` | POST | `/auth/jwt/cel/role/{name}` | generated | Manage the CEL roles that can be created with this backend. |

</details>

<details>
<summary><code>ExBao.Auth.Kerberos</code> — 10 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure` | POST | `/auth/kerberos/config` | generated | Configures the Kerberos keytab and service account. |
| `configure_ldap` | POST | `/auth/kerberos/config/ldap` | generated | Configure the LDAP server to connect to, along with its options. |
| `delete_group` | DELETE | `/auth/kerberos/groups/{name}` | generated | Manage users allowed to authenticate. |
| `list_groups` | GET | `/auth/kerberos/groups` | generated | Manage users allowed to authenticate. |
| `login` | POST | `/auth/kerberos/login` | generated |  |
| `login2` | GET | `/auth/kerberos/login` | generated |  |
| `read_configuration` | GET | `/auth/kerberos/config` | generated | Configures the Kerberos keytab and service account. |
| `read_group` | GET | `/auth/kerberos/groups/{name}` | generated | Manage users allowed to authenticate. |
| `read_ldap_configuration` | GET | `/auth/kerberos/config/ldap` | generated | Configure the LDAP server to connect to, along with its options. |
| `write_group` | POST | `/auth/kerberos/groups/{name}` | generated | Manage users allowed to authenticate. |

</details>

<details>
<summary><code>ExBao.Auth.Kubernetes</code> — 7 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure_auth` | POST | `/auth/kubernetes/config` | generated | Configures the JWT Public Key and Kubernetes API information. |
| `delete_auth_role` | DELETE | `/auth/kubernetes/role/{name}` | generated | Register an role with the backend. |
| `list_auth_roles` | GET | `/auth/kubernetes/role` | generated | Lists all the roles registered with the backend. |
| `login` | POST | `/auth/kubernetes/login` | generated | Authenticates Kubernetes service accounts with OpenBao. |
| `read_auth_configuration` | GET | `/auth/kubernetes/config` | generated | Configures the JWT Public Key and Kubernetes API information. |
| `read_auth_role` | GET | `/auth/kubernetes/role/{name}` | generated | Register an role with the backend. |
| `write_auth_role` | POST | `/auth/kubernetes/role/{name}` | generated | Register an role with the backend. |

</details>

<details>
<summary><code>ExBao.Auth.LDAP</code> — 11 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure_auth` | POST | `/auth/ldap/config` | generated | Configure the LDAP server to connect to, along with its options. |
| `delete_group` | DELETE | `/auth/ldap/groups/{name}` | generated | Manage additional groups for users allowed to authenticate. |
| `delete_user` | DELETE | `/auth/ldap/users/{name}` | generated | Manage users allowed to authenticate. |
| `list_groups` | GET | `/auth/ldap/groups` | generated | Manage additional groups for users allowed to authenticate. |
| `list_users` | GET | `/auth/ldap/users` | generated | Manage users allowed to authenticate. |
| `login` | POST | `/auth/ldap/login/{username}` | generated | Log in with a username and password. |
| `read_auth_configuration` | GET | `/auth/ldap/config` | generated | Configure the LDAP server to connect to, along with its options. |
| `read_group` | GET | `/auth/ldap/groups/{name}` | generated | Manage additional groups for users allowed to authenticate. |
| `read_user` | GET | `/auth/ldap/users/{name}` | generated | Manage users allowed to authenticate. |
| `write_group` | POST | `/auth/ldap/groups/{name}` | generated | Manage additional groups for users allowed to authenticate. |
| `write_user` | POST | `/auth/ldap/users/{name}` | generated | Manage users allowed to authenticate. |

</details>

<details>
<summary><code>ExBao.Auth.Radius</code> — 8 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `configure` | POST | `/auth/radius/config` | generated | Configure the RADIUS server to connect to, along with its options. |
| `delete_user` | DELETE | `/auth/radius/users/{name}` | generated | Manage users allowed to authenticate. |
| `list_users` | GET | `/auth/radius/users` | generated | Manage users allowed to authenticate. |
| `login` | POST | `/auth/radius/login` | generated | Log in with a username and password. |
| `login_with_username` | POST | `/auth/radius/login/{urlusername}` | generated | Log in with a username and password. |
| `read_configuration` | GET | `/auth/radius/config` | generated | Configure the RADIUS server to connect to, along with its options. |
| `read_user` | GET | `/auth/radius/users/{name}` | generated | Manage users allowed to authenticate. |
| `write_user` | POST | `/auth/radius/users/{name}` | generated | Manage users allowed to authenticate. |

</details>

<details>
<summary><code>ExBao.Auth.Userpass</code> — 7 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `delete_user` | DELETE | `/auth/userpass/users/{username}` | generated | Manage users allowed to authenticate. |
| `list_users` | GET | `/auth/userpass/users` | generated | Manage users allowed to authenticate. |
| `login` | POST | `/auth/userpass/login/{username}` | generated | Log in with a username and password. |
| `read_user` | GET | `/auth/userpass/users/{username}` | generated | Manage users allowed to authenticate. |
| `reset_password` | POST | `/auth/userpass/users/{username}/password` | generated | Reset user's password. |
| `update_policies` | POST | `/auth/userpass/users/{username}/policies` | generated | Update the policies associated with the username. |
| `write_user` | POST | `/auth/userpass/users/{username}` | generated | Manage users allowed to authenticate. |

</details>

### System (by operation)

<details>
<summary><code>ExBao.Sys</code> — 207 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `auditing_calculate_hash` | POST | `/sys/audit-hash/{path}` | generated | The hash of the given string via the given audit backend |
| `auditing_disable_device` | DELETE | `/sys/audit/{path}` | generated | Disable the audit device at the given path. |
| `auditing_disable_request_header` | DELETE | `/sys/config/auditing/request-headers/{header}` | generated | Disable auditing of the given request header. |
| `auditing_enable_device` | POST | `/sys/audit/{path}` | generated | Enable a new audit device at the supplied path. |
| `auditing_enable_request_header` | POST | `/sys/config/auditing/request-headers/{header}` | generated | Enable auditing of a header. |
| `auditing_list_enabled_devices` | GET | `/sys/audit` | generated | List the enabled audit devices. |
| `auditing_list_request_headers` | GET | `/sys/config/auditing/request-headers` | generated | List the request headers that are configured to be audited. |
| `auditing_read_request_header_information` | GET | `/sys/config/auditing/request-headers/{header}` | generated | List the information for the given request header. |
| `auth_disable_method` | DELETE | `/sys/auth/{path}` | generated | Disable the auth method at the given auth path |
| `auth_enable_method` | POST | `/sys/auth/{path}` | generated | Enables a new auth method. |
| `auth_list_enabled_methods` | GET | `/sys/auth` | generated | List the currently enabled credential backends. |
| `auth_read_configuration` | GET | `/sys/auth/{path}` | generated | Read the configuration of the auth engine at the given path. |
| `auth_read_tuning_information` | GET | `/sys/auth/{path}/tune` | generated | Reads the given auth path's configuration. |
| `auth_tune_configuration_parameters` | POST | `/sys/auth/{path}/tune` | generated | Tune configuration parameters for a given auth path. |
| `collect_host_information` | GET | `/sys/host-info` | generated | Information about the host instance that this OpenBao server is running on. |
| `collect_in_flight_request_information` | GET | `/sys/in-flight-req` | generated | reports in-flight requests |
| `configure_encryption_key_config` | POST | `/sys/rotate/config` | generated | Configure the automatic key rotation. |
| `configure_rotate_keyring_config` | POST | `/sys/rotate/keyring/config` | generated | Configure the automatic key rotation. |
| `cors_configure` | POST | `/sys/config/cors` | generated | Configure the CORS settings. |
| `cors_delete_configuration` | DELETE | `/sys/config/cors` | generated | Remove any CORS settings. |
| `cors_read_configuration` | GET | `/sys/config/cors` | generated | Return the current CORS settings. |
| `decode_root_token` | POST | `/sys/decode-token` | generated | Decodes the encoded token with the otp. |
| `generate_hash` | POST | `/sys/tools/hash` | generated | Generate a hash sum for input data |
| `generate_hash_with_algorithm` | POST | `/sys/tools/hash/{urlalgorithm}` | generated | Generate a hash sum for input data |
| `generate_random` | POST | `/sys/tools/random` | generated | Generate random bytes |
| `generate_random_with_bytes` | POST | `/sys/tools/random/{urlbytes}` | generated | Generate random bytes |
| `generate_random_with_source` | POST | `/sys/tools/random/{source}` | generated | Generate random bytes |
| `generate_random_with_source_and_bytes` | POST | `/sys/tools/random/{source}/{urlbytes}` | generated | Generate random bytes |
| `generate_root_token_delete` | DELETE | `/sys/generate-root-token/attempt` | generated | Cancel root token generation. |
| `generate_root_token_get` | GET | `/sys/generate-root-token/attempt` | generated | Read the status of root token generation. |
| `generate_root_token_post` | POST | `/sys/generate-root-token/attempt` | generated | Initialize root token generation. |
| `ha_status` | GET | `/sys/ha-status` | generated | Check the HA status of an OpenBao cluster |
| `initialize_system` | POST | `/sys/init` | generated | Initialize a new OpenBao instance. |
| `internal_count_entities` | GET | `/sys/internal/counters/entities` | generated | Backwards compatibility is not guaranteed for this API |
| `internal_count_requests` | GET | `/sys/internal/counters/requests` | generated | Backwards compatibility is not guaranteed for this API |
| `internal_count_tokens` | GET | `/sys/internal/counters/tokens` | generated | Backwards compatibility is not guaranteed for this API |
| `internal_generate_open_api_document` | GET | `/sys/internal/specs/openapi` | generated | Generate an OpenAPI 3 document of all mounted paths. |
| `internal_generate_open_api_document_with_parameters` | POST | `/sys/internal/specs/openapi` | generated | Generate an OpenAPI 3 document of all mounted paths. |
| `internal_inspect_request` | GET | `/sys/internal/inspect/request` | generated | Expose all request information to the caller |
| `internal_inspect_router` | GET | `/sys/internal/inspect/router/{tag}` | generated | Expose the route entry and mount entry tables present in the router |
| `internal_ui_list_enabled_visible_mounts` | GET | `/sys/internal/ui/mounts` | generated | Lists all enabled and visible auth and secrets mounts. |
| `internal_ui_list_namespaces` | GET | `/sys/internal/ui/namespaces` | generated | Backwards compatibility is not guaranteed for this API |
| `internal_ui_read_mount_information` | GET | `/sys/internal/ui/mounts/{path}` | generated | Return information about the given mount. |
| `internal_ui_read_resultant_acl` | GET | `/sys/internal/ui/resultant-acl` | generated | Backwards compatibility is not guaranteed for this API |
| `leader_status` | GET | `/sys/leader` | generated | Returns the high availability status and current leader instance of OpenBao. |
| `leases_count` | GET | `/sys/leases/count` | generated | Count of leases associated with this OpenBao cluster |
| `leases_force_revoke_lease_with_prefix2` | POST | `/sys/leases/revoke-force/{prefix}` | generated | Revokes all secrets or tokens generated under a given prefix immediately |
| `leases_list` | GET | `/sys/leases` | generated | List leases associated with this OpenBao cluster |
| `leases_look_up` | GET | `/sys/leases/lookup/` | generated | View or list lease metadata. |
| `leases_look_up_with_prefix` | GET | `/sys/leases/lookup/{prefix}` | generated | View or list lease metadata. |
| `leases_read_lease` | POST | `/sys/leases/lookup` | generated | View or list lease metadata. |
| `leases_renew_lease` | POST | `/sys/leases/renew/{url_lease_id}` | generated | Renews a lease, requesting to extend the lease. |
| `leases_renew_lease2` | POST | `/sys/leases/renew` | generated | Renews a lease, requesting to extend the lease. |
| `leases_revoke_lease` | POST | `/sys/leases/revoke/{url_lease_id}` | generated | Revokes a lease immediately. |
| `leases_revoke_lease2` | POST | `/sys/leases/revoke` | generated | Revokes a lease immediately. |
| `leases_revoke_lease_with_prefix2` | POST | `/sys/leases/revoke-prefix/{prefix}` | generated | Revokes all secrets (via a lease ID prefix) or tokens (via the tokens' path property) gen… |
| `leases_tidy` | POST | `/sys/leases/tidy` | generated | This endpoint performs cleanup tasks that can be run if certain error conditions have occ… |
| `locked_users_list` | GET | `/sys/locked-users` | generated | Report the locked user count metrics, for this namespace and all child namespaces. |
| `locked_users_unlock` | POST | `/sys/locked-users/{mount_accessor}/unlock/{alias_identifier}` | generated | Unlocks the user with given mount_accessor and alias_identifier |
| `loggers_read_verbosity_level` | GET | `/sys/loggers` | generated | Read the log level for all existing loggers. |
| `loggers_read_verbosity_level_for` | GET | `/sys/loggers/{name}` | generated | Read the log level for a single logger. |
| `loggers_revert_verbosity_level` | DELETE | `/sys/loggers` | generated | Revert the all loggers to use log level provided in config. |
| `loggers_revert_verbosity_level_for` | DELETE | `/sys/loggers/{name}` | generated | Revert a single logger to use log level provided in config. |
| `loggers_update_verbosity_level` | POST | `/sys/loggers` | generated | Modify the log level for all existing loggers. |
| `loggers_update_verbosity_level_for` | POST | `/sys/loggers/{name}` | generated | Modify the log level of a single logger. |
| `metrics` | GET | `/sys/metrics` | generated | Export the metrics aggregated for telemetry purpose. |
| `mfa_validate` | POST | `/sys/mfa/validate` | generated | Validates the login for the given MFA methods. Upon successful validation, it returns an… |
| `monitor` | GET | `/sys/monitor` | generated |  |
| `mounts_disable_secrets_engine` | DELETE | `/sys/mounts/{path}` | generated | Disable the mount point specified at the given path. |
| `mounts_enable_secrets_engine` | POST | `/sys/mounts/{path}` | generated | Enable a new secrets engine at the given path. |
| `mounts_list_secrets_engines` | GET | `/sys/mounts` | generated | List the currently mounted backends. |
| `mounts_read_configuration` | GET | `/sys/mounts/{path}` | generated | Read the configuration of the secret engine at the given path. |
| `mounts_read_tuning_information` | GET | `/sys/mounts/{path}/tune` | generated | Tune backend configuration parameters for this mount. |
| `mounts_tune_configuration_parameters` | POST | `/sys/mounts/{path}/tune` | generated | Tune backend configuration parameters for this mount. |
| `namespaces_delete_namespaces_path` | DELETE | `/sys/namespaces/{path}` | generated | Delete a namespace. |
| `namespaces_delete_namespaces_path_delete_sealed` | DELETE | `/sys/namespaces/{path}/delete-sealed` | generated | Delete a sealed namespace by wiping its physical storage. |
| `namespaces_patch_namespaces_path` | PATCH | `/sys/namespaces/{path}` | generated | Update a namespace's custom metadata. |
| `namespaces_read_namespaces_path` | GET | `/sys/namespaces/{path}` | generated | Retrieve a namespace. |
| `namespaces_read_seal` | GET | `/sys/namespaces/{path}/seal-status` | generated | Check the seal status of an OpenBao namespace. |
| `namespaces_scan_namespaces` | GET | `/sys/namespaces` | generated | Scan (recursively list) namespaces. |
| `namespaces_seal` | POST | `/sys/namespaces/{path}/seal` | generated | Seal a namespace. |
| `namespaces_unseal` | POST | `/sys/namespaces/{path}/unseal` | generated | Unseal a namespace. |
| `namespaces_write_namespaces_api_lock_lock` | POST | `/sys/namespaces/api-lock/lock` | generated | Lock a namespace. |
| `namespaces_write_namespaces_api_lock_lock_path` | POST | `/sys/namespaces/api-lock/lock/{path}` | generated | Lock a namespace. |
| `namespaces_write_namespaces_api_lock_unlock` | POST | `/sys/namespaces/api-lock/unlock` | generated | Unlock a namespace. |
| `namespaces_write_namespaces_api_lock_unlock_path` | POST | `/sys/namespaces/api-lock/unlock/{path}` | generated | Unlock a namespace. |
| `namespaces_write_namespaces_path` | POST | `/sys/namespaces/{path}` | generated | Create or update a namespace. |
| `plugins_catalog_list_plugins` | GET | `/sys/plugins/catalog` | generated | Lists all the plugins known to OpenBao |
| `plugins_catalog_list_plugins_with_type` | GET | `/sys/plugins/catalog/{type}` | generated | List the plugins in the catalog. |
| `plugins_catalog_read_plugin_configuration` | GET | `/sys/plugins/catalog/{name}` | generated | Return the configuration data for the plugin with the given name. |
| `plugins_catalog_read_plugin_configuration_with_type` | GET | `/sys/plugins/catalog/{type}/{name}` | generated | Return the configuration data for the plugin with the given name. |
| `plugins_catalog_register_plugin` | POST | `/sys/plugins/catalog/{name}` | generated | Register a new plugin, or updates an existing one with the supplied name. |
| `plugins_catalog_register_plugin_with_type` | POST | `/sys/plugins/catalog/{type}/{name}` | generated | Register a new plugin, or updates an existing one with the supplied name. |
| `plugins_catalog_remove_plugin` | DELETE | `/sys/plugins/catalog/{name}` | generated | Remove the plugin with the given name. |
| `plugins_catalog_remove_plugin_with_type` | DELETE | `/sys/plugins/catalog/{type}/{name}` | generated | Remove the plugin with the given name. |
| `plugins_reload_backends` | POST | `/sys/plugins/reload/backend` | generated | Reload mounted plugin backends. |
| `policies_delete_acl_policy` | DELETE | `/sys/policies/acl/{name}` | generated | Delete the ACL policy with the given name. |
| `policies_delete_acl_policy2` | DELETE | `/sys/policy/{name}` | generated | Delete the policy with the given name. |
| `policies_delete_password_policy` | DELETE | `/sys/policies/password/{name}` | generated | Delete a password policy. |
| `policies_generate_password_from_password_policy` | GET | `/sys/policies/password/{name}/generate` | generated | Generate a password from an existing password policy. |
| `policies_list` | GET | `/sys/policy` | generated | List the configured access control policies. |
| `policies_list_acl_policies` | GET | `/sys/policies/acl` | generated | List the configured access control policies. |
| `policies_list_password_policies` | GET | `/sys/policies/password` | generated | List the existing password policies. |
| `policies_patch_acl_policy` | PATCH | `/sys/policies/acl/{name}` | generated | Patches an existing ACL policy. |
| `policies_read_acl_policy` | GET | `/sys/policies/acl/{name}` | generated | Retrieve information about the named ACL policy. |
| `policies_read_acl_policy2` | GET | `/sys/policy/{name}` | generated | Retrieve the policy body for the named policy. |
| `policies_read_password_policy` | GET | `/sys/policies/password/{name}` | generated | Retrieve an existing password policy. |
| `policies_write_acl_policy` | POST | `/sys/policies/acl/{name}` | generated | Add a new or update an existing ACL policy. |
| `policies_write_acl_policy2` | POST | `/sys/policy/{name}` | generated | Add a new or update an existing policy. |
| `policies_write_password_policy` | POST | `/sys/policies/password/{name}` | generated | Add a new or update an existing password policy. |
| `pprof_blocking` | GET | `/sys/pprof/block` | generated | Returns stack traces that led to blocking on synchronization primitives |
| `pprof_command_line` | GET | `/sys/pprof/cmdline` | generated | Returns the running program's command line. |
| `pprof_cpu_profile` | GET | `/sys/pprof/profile` | generated | Returns a pprof-formatted cpu profile payload. |
| `pprof_execution_trace` | GET | `/sys/pprof/trace` | generated | Returns the execution trace in binary form. |
| `pprof_goroutines` | GET | `/sys/pprof/goroutine` | generated | Returns stack traces of all current goroutines. |
| `pprof_index` | GET | `/sys/pprof` | generated | Returns an HTML page listing the available profiles. |
| `pprof_memory_allocations` | GET | `/sys/pprof/allocs` | generated | Returns a sampling of all past memory allocations. |
| `pprof_memory_allocations_live` | GET | `/sys/pprof/heap` | generated | Returns a sampling of memory allocations of live object. |
| `pprof_mutexes` | GET | `/sys/pprof/mutex` | generated | Returns stack traces of holders of contended mutexes |
| `pprof_symbols` | GET | `/sys/pprof/symbol` | generated | Returns the program counters listed in the request. |
| `pprof_thread_creations` | GET | `/sys/pprof/threadcreate` | generated | Returns stack traces that led to the creation of new OS threads |
| `query_token_accessor_capabilities` | POST | `/sys/capabilities-accessor` | generated | Fetches the capabilities of the token associated with the given token, on the given path. |
| `query_token_capabilities` | POST | `/sys/capabilities` | generated | Fetches the capabilities of the given token on the given path. |
| `query_token_self_capabilities` | POST | `/sys/capabilities-self` | generated | Fetches the capabilities of the given token on the given path. |
| `rate_limit_quotas_configure` | POST | `/sys/quotas/config` | generated | Create, update and read the quota configuration. |
| `rate_limit_quotas_delete` | DELETE | `/sys/quotas/rate-limit/{name}` | generated | Get, create or update rate limit resource quota for an optional namespace or mount. |
| `rate_limit_quotas_list` | GET | `/sys/quotas/rate-limit` | generated | Lists the names of all the rate limit quotas. |
| `rate_limit_quotas_read` | GET | `/sys/quotas/rate-limit/{name}` | generated | Get, create or update rate limit resource quota for an optional namespace or mount. |
| `rate_limit_quotas_read_configuration` | GET | `/sys/quotas/config` | generated | Create, update and read the quota configuration. |
| `rate_limit_quotas_write` | POST | `/sys/quotas/rate-limit/{name}` | generated | Get, create or update rate limit resource quota for an optional namespace or mount. |
| `raw_delete` | DELETE | `/sys/raw` | generated | Delete the key with given path. |
| `raw_delete_path` | DELETE | `/sys/raw/{path}` | generated | Delete the key with given path. |
| `raw_read` | GET | `/sys/raw` | generated | Read the value of the key at the given path. |
| `raw_read_path` | GET | `/sys/raw/{path}` | generated | Read the value of the key at the given path. |
| `raw_write` | POST | `/sys/raw` | generated | Update the value of the key at the given path. |
| `raw_write_path` | POST | `/sys/raw/{path}` | generated | Update the value of the key at the given path. |
| `read_encryption_key_config` | GET | `/sys/rotate/config` | generated | Get the automatic key rotation config. |
| `read_health_status` | GET | `/sys/health` | generated | Returns the health status of OpenBao. |
| `read_initialization_status` | GET | `/sys/init` | generated | Returns the initialization status of OpenBao. |
| `read_rotate_keyring_config` | GET | `/sys/rotate/keyring/config` | generated | Get the automatic key rotation config. |
| `read_sanitized_configuration_state` | GET | `/sys/config/state/sanitized` | generated | Return a sanitized version of the OpenBao server configuration. |
| `read_wrapping_properties` | POST | `/sys/wrapping/lookup` | generated | Look up wrapping properties for the given token. |
| `read_wrapping_properties2` | GET | `/sys/wrapping/lookup` | generated | Look up wrapping properties for the requester's token. |
| `rekey_attempt_cancel` | DELETE | `/sys/rekey/init` | generated | Cancels any in-progress rekey. |
| `rekey_attempt_initialize` | POST | `/sys/rekey/init` | generated | Initializes a new rekey attempt. |
| `rekey_attempt_read_progress` | GET | `/sys/rekey/init` | generated | Reads the configuration and progress of the current rekey attempt. |
| `rekey_attempt_update` | POST | `/sys/rekey/update` | generated | Enter a single unseal key share to progress the rekey of the OpenBao. |
| `rekey_delete_backup_key` | DELETE | `/sys/rekey/backup` | generated | Delete the backup copy of PGP-encrypted unseal keys. |
| `rekey_delete_backup_recovery_key` | DELETE | `/sys/rekey/recovery-key-backup` | generated | Allows fetching or deleting the backup of the rotated unseal keys. |
| `rekey_read_backup_key` | GET | `/sys/rekey/backup` | generated | Return the backup copy of PGP-encrypted unseal keys. |
| `rekey_read_backup_recovery_key` | GET | `/sys/rekey/recovery-key-backup` | generated | Allows fetching or deleting the backup of the rotated unseal keys. |
| `rekey_verification_cancel` | DELETE | `/sys/rekey/verify` | generated | Cancel any in-progress rekey verification operation. |
| `rekey_verification_read_progress` | GET | `/sys/rekey/verify` | generated | Read the configuration and progress of the current rekey verification attempt. |
| `rekey_verification_update` | POST | `/sys/rekey/verify` | generated | Enter a single new key share to progress the rekey verification operation. |
| `reload_subsystem` | POST | `/sys/config/reload/{subsystem}` | generated | Reload the given subsystem |
| `remount` | POST | `/sys/remount` | generated | Initiate a mount migration |
| `remount_status` | GET | `/sys/remount/status/{migration_id}` | generated | Check status of a mount migration |
| `rewrap` | POST | `/sys/wrapping/rewrap` | generated | Rotates a response-wrapped token. |
| `root_key_rotate` | POST | `/sys/rotate/root` | generated | Perform a root key rotation without requiring key shares to be provided. |
| `root_token_generation_cancel` | DELETE | `/sys/generate-root/attempt` | generated | Cancels any in-progress root generation attempt. |
| `root_token_generation_cancel_2` | DELETE | `/sys/generate-root` | generated | Cancels any in-progress root generation attempt. |
| `root_token_generation_initialize` | POST | `/sys/generate-root/attempt` | generated | Initializes a new root generation attempt. |
| `root_token_generation_initialize_2` | POST | `/sys/generate-root` | generated | Initializes a new root generation attempt. |
| `root_token_generation_read_progress` | GET | `/sys/generate-root/attempt` | generated | Read the configuration and progress of the current root generation attempt. |
| `root_token_generation_read_progress2` | GET | `/sys/generate-root` | generated | Read the configuration and progress of the current root generation attempt. |
| `root_token_generation_update` | POST | `/sys/generate-root/update` | generated | Enter a single unseal key share to progress the root generation attempt. |
| `rotate_attempt_cancel` | DELETE | `/sys/rotate/root/init` | generated | Cancels any in-progress rotate root operation. |
| `rotate_attempt_cancel_rotate_recovery_init` | DELETE | `/sys/rotate/recovery/init` | generated | Cancels any in-progress rotate root operation. |
| `rotate_attempt_initialize` | POST | `/sys/rotate/root/init` | generated | Initializes a new root rotate attempt. |
| `rotate_attempt_initialize_rotate_recovery_init` | POST | `/sys/rotate/recovery/init` | generated | Initializes a new root rotate attempt. |
| `rotate_attempt_read_progress` | GET | `/sys/rotate/root/init` | generated | Reads the configuration and progress of the current root rotate attempt. |
| `rotate_attempt_read_rotate_recovery_init` | GET | `/sys/rotate/recovery/init` | generated | Reads the configuration and progress of the current root rotate attempt. |
| `rotate_attempt_update` | POST | `/sys/rotate/root/update` | generated | Enter a single unseal key share to progress the rotation of the root key of OpenBao. |
| `rotate_attempt_update_rotate_recovery_update` | POST | `/sys/rotate/recovery/update` | generated | Enter a single unseal key share to progress the rotation of the root key of OpenBao. |
| `rotate_delete_backup_key` | DELETE | `/sys/rotate/root/backup` | generated | Delete the backup copy of PGP-encrypted unseal keys. |
| `rotate_delete_rotate_recovery_backup` | DELETE | `/sys/rotate/recovery/backup` | generated | Delete the backup copy of PGP-encrypted unseal keys. |
| `rotate_encryption_key` | POST | `/sys/rotate` | generated | Rotate the encryption key. |
| `rotate_read_backup_key` | GET | `/sys/rotate/root/backup` | generated | Return the backup copy of PGP-encrypted unseal keys. |
| `rotate_read_rotate_recovery_backup` | GET | `/sys/rotate/recovery/backup` | generated | Return the backup copy of PGP-encrypted unseal keys. |
| `rotate_rotate_keyring` | POST | `/sys/rotate/keyring` | generated | Rotate the encryption key. |
| `rotate_verification_cancel` | DELETE | `/sys/rotate/root/verify` | generated | Cancel any in-progress rotate verification operation. |
| `rotate_verification_cancel_rotate_recovery_verify` | DELETE | `/sys/rotate/recovery/verify` | generated | Cancel any in-progress rotate verification operation. |
| `rotate_verification_read_progress` | GET | `/sys/rotate/root/verify` | generated | Read the configuration and progress of the current rotate verification attempt. |
| `rotate_verification_read_rotate_recovery_verify` | GET | `/sys/rotate/recovery/verify` | generated | Read the configuration and progress of the current rotate verification attempt. |
| `rotate_verification_update` | POST | `/sys/rotate/root/verify` | generated | Enter a single new key share to progress the rotation verification operation. |
| `rotate_verification_update_rotate_recovery_verify` | POST | `/sys/rotate/recovery/verify` | generated | Enter a single new key share to progress the rotation verification operation. |
| `seal` | POST | `/sys/seal` | generated | Seal the OpenBao instance. |
| `seal_status` | GET | `/sys/seal-status` | generated | Check the seal status of an OpenBao instance. |
| `status_encryption_key` | GET | `/sys/key-status` | generated | Provides information about the backend encryption key. |
| `step_down_leader` | POST | `/sys/step-down` | generated | Cause the node to give up active status. |
| `system_list_policies_detailed_acl` | GET | `/sys/policies/detailed/acl` | generated | List ACL policies with detailed information. |
| `system_list_policies_detailed_acl_name` | GET | `/sys/policies/detailed/acl/{name}` | generated | List ACL policies with detailed information. |
| `ui_headers_configure` | POST | `/sys/config/ui/headers/{header}` | generated | Configure the values to be returned for the UI header. |
| `ui_headers_delete_configuration` | DELETE | `/sys/config/ui/headers/{header}` | generated | Remove a UI header. |
| `ui_headers_list` | GET | `/sys/config/ui/headers` | generated | Return a list of configured UI headers. |
| `ui_headers_read_configuration` | GET | `/sys/config/ui/headers/{header}` | generated | Return the given UI header's configuration |
| `unseal` | POST | `/sys/unseal` | generated | Unseal the OpenBao instance. |
| `unwrap` | POST | `/sys/wrapping/unwrap` | generated | Unwraps a response-wrapped token. |
| `update_generation_attempt_root_token` | POST | `/sys/generate-root-token/update` | generated | Provide an unseal key share for root token generation. |
| `version_history` | GET | `/sys/version-history` | generated | Returns map of historical version change entries |
| `workflows_delete_workflows_manage_path` | DELETE | `/sys/workflows/manage/{path}` | generated | Delete a workflow. |
| `workflows_execute_write_workflows_execute_path` | POST | `/sys/workflows/execute/{path}` | generated | Execute the given workflow. |
| `workflows_list_workflows_manage` | GET | `/sys/workflows/manage` | generated | List workflows. |
| `workflows_read_workflows_manage_path` | GET | `/sys/workflows/manage/{path}` | generated | Retrieve a workflow. |
| `workflows_trace_write_workflows_trace_path` | POST | `/sys/workflows/trace/{path}` | generated | Execute the given workflow. |
| `workflows_write_workflows_manage_path` | POST | `/sys/workflows/manage/{path}` | generated | Create or update a workflow. |
| `wrap` | POST | `/sys/wrapping/wrap` | generated | Response-wraps an arbitrary JSON object. |

</details>

<details>
<summary><code>ExBao.Identity</code> — 105 operations</summary>

| Function | Method | Path | Status | Summary |
|----------|--------|------|--------|---------|
| `alias_create` | POST | `/identity/alias` | generated | Create a new alias. |
| `alias_delete_by_id` | DELETE | `/identity/alias/id/{id}` | generated | Update, read or delete an alias ID. |
| `alias_list_by_id` | GET | `/identity/alias/id` | generated | List all the alias IDs. |
| `alias_read_by_id` | GET | `/identity/alias/id/{id}` | generated | Update, read or delete an alias ID. |
| `alias_update_by_id` | POST | `/identity/alias/id/{id}` | generated | Update, read or delete an alias ID. |
| `entity_batch_delete` | POST | `/identity/entity/batch-delete` | generated | Delete all of the entities provided |
| `entity_create` | POST | `/identity/entity` | generated | Create a new entity |
| `entity_create_alias` | POST | `/identity/entity-alias` | generated | Create a new alias. |
| `entity_delete_alias_by_id` | DELETE | `/identity/entity-alias/id/{id}` | generated | Update, read or delete an alias ID. |
| `entity_delete_by_id` | DELETE | `/identity/entity/id/{id}` | generated | Update, read or delete an entity using entity ID |
| `entity_delete_by_name` | DELETE | `/identity/entity/name/{name}` | generated | Update, read or delete an entity using entity name |
| `entity_list_aliases_by_id` | GET | `/identity/entity-alias/id` | generated | List all the alias IDs. |
| `entity_list_by_id` | GET | `/identity/entity/id` | generated | List all the entity IDs |
| `entity_list_by_name` | GET | `/identity/entity/name` | generated | List all the entity names |
| `entity_look_up` | POST | `/identity/lookup/entity` | generated | Query entities based on various properties. |
| `entity_merge` | POST | `/identity/entity/merge` | generated | Merge two or more entities together |
| `entity_read_alias_by_id` | GET | `/identity/entity-alias/id/{id}` | generated | Update, read or delete an alias ID. |
| `entity_read_by_id` | GET | `/identity/entity/id/{id}` | generated | Update, read or delete an entity using entity ID |
| `entity_read_by_name` | GET | `/identity/entity/name/{name}` | generated | Update, read or delete an entity using entity name |
| `entity_update_alias_by_id` | POST | `/identity/entity-alias/id/{id}` | generated | Update, read or delete an alias ID. |
| `entity_update_by_id` | POST | `/identity/entity/id/{id}` | generated | Update, read or delete an entity using entity ID |
| `entity_update_by_name` | POST | `/identity/entity/name/{name}` | generated | Update, read or delete an entity using entity name |
| `group_create` | POST | `/identity/group` | generated | Create a new group. |
| `group_create_alias` | POST | `/identity/group-alias` | generated | Creates a new group alias, or updates an existing one. |
| `group_delete_alias_by_id` | DELETE | `/identity/group-alias/id/{id}` | generated |  |
| `group_delete_by_id` | DELETE | `/identity/group/id/{id}` | generated | Update or delete an existing group using its ID. |
| `group_delete_by_name` | DELETE | `/identity/group/name/{name}` | generated |  |
| `group_list_aliases_by_id` | GET | `/identity/group-alias/id` | generated | List all the group alias IDs. |
| `group_list_by_id` | GET | `/identity/group/id` | generated | List all the group IDs. |
| `group_list_by_name` | GET | `/identity/group/name` | generated |  |
| `group_look_up` | POST | `/identity/lookup/group` | generated | Query groups based on various properties. |
| `group_read_alias_by_id` | GET | `/identity/group-alias/id/{id}` | generated |  |
| `group_read_by_id` | GET | `/identity/group/id/{id}` | generated | Update or delete an existing group using its ID. |
| `group_read_by_name` | GET | `/identity/group/name/{name}` | generated |  |
| `group_update_alias_by_id` | POST | `/identity/group-alias/id/{id}` | generated |  |
| `group_update_by_id` | POST | `/identity/group/id/{id}` | generated | Update or delete an existing group using its ID. |
| `group_update_by_name` | POST | `/identity/group/name/{name}` | generated |  |
| `mfa_admin_destroy_totp_secret` | POST | `/identity/mfa/method/totp/admin-destroy` | generated | Destroys a TOTP secret for the given MFA method ID on the given entity |
| `mfa_admin_generate_totp_secret` | POST | `/identity/mfa/method/totp/admin-generate` | generated | Update or create TOTP secret for the given method ID on the given entity. |
| `mfa_configure_duo_method` | POST | `/identity/mfa/method/duo/{method_id}` | generated | Update or create a configuration for the given MFA method |
| `mfa_configure_okta_method` | POST | `/identity/mfa/method/okta/{method_id}` | generated | Update or create a configuration for the given MFA method |
| `mfa_configure_ping_id_method` | POST | `/identity/mfa/method/pingid/{method_id}` | generated | Update or create a configuration for the given MFA method |
| `mfa_configure_totp_method` | POST | `/identity/mfa/method/totp/{method_id}` | generated | Update or create a configuration for the given MFA method |
| `mfa_delete_duo_method` | DELETE | `/identity/mfa/method/duo/{method_id}` | generated | Delete a configuration for the given MFA method |
| `mfa_delete_login_enforcement` | DELETE | `/identity/mfa/login-enforcement/{name}` | generated | Delete a login enforcement |
| `mfa_delete_okta_method` | DELETE | `/identity/mfa/method/okta/{method_id}` | generated | Delete a configuration for the given MFA method |
| `mfa_delete_ping_id_method` | DELETE | `/identity/mfa/method/pingid/{method_id}` | generated | Delete a configuration for the given MFA method |
| `mfa_delete_totp_method` | DELETE | `/identity/mfa/method/totp/{method_id}` | generated | Delete a configuration for the given MFA method |
| `mfa_generate_totp_secret` | POST | `/identity/mfa/method/totp/generate` | generated | Update or create TOTP secret for the given method ID on the given entity. |
| `mfa_list_duo_methods` | GET | `/identity/mfa/method/duo` | generated | List MFA method configurations for the given MFA method |
| `mfa_list_login_enforcements` | GET | `/identity/mfa/login-enforcement` | generated | List login enforcements |
| `mfa_list_methods` | GET | `/identity/mfa/method` | generated | List MFA method configurations for all MFA methods |
| `mfa_list_okta_methods` | GET | `/identity/mfa/method/okta` | generated | List MFA method configurations for the given MFA method |
| `mfa_list_ping_id_methods` | GET | `/identity/mfa/method/pingid` | generated | List MFA method configurations for the given MFA method |
| `mfa_list_totp_methods` | GET | `/identity/mfa/method/totp` | generated | List MFA method configurations for the given MFA method |
| `mfa_read_duo_method_configuration` | GET | `/identity/mfa/method/duo/{method_id}` | generated | Read the current configuration for the given MFA method |
| `mfa_read_login_enforcement` | GET | `/identity/mfa/login-enforcement/{name}` | generated | Read the current login enforcement |
| `mfa_read_method_configuration` | GET | `/identity/mfa/method/{method_id}` | generated | Read the current configuration for the given ID regardless of the MFA method type |
| `mfa_read_okta_method_configuration` | GET | `/identity/mfa/method/okta/{method_id}` | generated | Read the current configuration for the given MFA method |
| `mfa_read_ping_id_method_configuration` | GET | `/identity/mfa/method/pingid/{method_id}` | generated | Read the current configuration for the given MFA method |
| `mfa_read_totp_method_configuration` | GET | `/identity/mfa/method/totp/{method_id}` | generated | Read the current configuration for the given MFA method |
| `mfa_write_login_enforcement` | POST | `/identity/mfa/login-enforcement/{name}` | generated | Create or update a login enforcement |
| `oidc_configure` | POST | `/identity/oidc/config` | generated | OIDC configuration |
| `oidc_delete_assignment` | DELETE | `/identity/oidc/assignment/{name}` | generated | CRUD operations for OIDC assignments. |
| `oidc_delete_client` | DELETE | `/identity/oidc/client/{name}` | generated | CRUD operations for OIDC clients. |
| `oidc_delete_key` | DELETE | `/identity/oidc/key/{name}` | generated | CRUD operations for OIDC keys. |
| `oidc_delete_provider` | DELETE | `/identity/oidc/provider/{name}` | generated | CRUD operations for OIDC providers. |
| `oidc_delete_role` | DELETE | `/identity/oidc/role/{name}` | generated | CRUD operations on OIDC Roles |
| `oidc_delete_scope` | DELETE | `/identity/oidc/scope/{name}` | generated | CRUD operations for OIDC scopes. |
| `oidc_generate_token` | GET | `/identity/oidc/token/{name}` | generated | Generate an OIDC token |
| `oidc_introspect` | POST | `/identity/oidc/introspect` | generated | Verify the authenticity of an OIDC token |
| `oidc_list_assignments` | GET | `/identity/oidc/assignment` | generated | List OIDC assignments |
| `oidc_list_clients` | GET | `/identity/oidc/client` | generated | List OIDC clients |
| `oidc_list_keys` | GET | `/identity/oidc/key` | generated | List OIDC keys |
| `oidc_list_providers` | GET | `/identity/oidc/provider` | generated | List OIDC providers |
| `oidc_list_roles` | GET | `/identity/oidc/role` | generated | List configured OIDC roles |
| `oidc_list_scopes` | GET | `/identity/oidc/scope` | generated | List OIDC scopes |
| `oidc_provider_authorize` | GET | `/identity/oidc/provider/{name}/authorize` | generated | Provides the OIDC Authorization Endpoint. |
| `oidc_provider_authorize_with_parameters` | POST | `/identity/oidc/provider/{name}/authorize` | generated | Provides the OIDC Authorization Endpoint. |
| `oidc_provider_token` | POST | `/identity/oidc/provider/{name}/token` | generated | Provides the OIDC Token Endpoint. |
| `oidc_provider_user_info` | GET | `/identity/oidc/provider/{name}/userinfo` | generated | Provides the OIDC UserInfo Endpoint. |
| `oidc_provider_user_info2` | POST | `/identity/oidc/provider/{name}/userinfo` | generated | Provides the OIDC UserInfo Endpoint. |
| `oidc_read_assignment` | GET | `/identity/oidc/assignment/{name}` | generated | CRUD operations for OIDC assignments. |
| `oidc_read_client` | GET | `/identity/oidc/client/{name}` | generated | CRUD operations for OIDC clients. |
| `oidc_read_configuration` | GET | `/identity/oidc/config` | generated | OIDC configuration |
| `oidc_read_key` | GET | `/identity/oidc/key/{name}` | generated | CRUD operations for OIDC keys. |
| `oidc_read_open_id_configuration` | GET | `/identity/oidc/.well-known/openid-configuration` | generated | Query OIDC configurations |
| `oidc_read_provider` | GET | `/identity/oidc/provider/{name}` | generated | CRUD operations for OIDC providers. |
| `oidc_read_provider_open_id_configuration` | GET | `/identity/oidc/provider/{name}/.well-known/openid-configuration` | generated | Query OIDC configurations |
| `oidc_read_provider_public_keys` | GET | `/identity/oidc/provider/{name}/.well-known/keys` | generated | Retrieve public keys |
| `oidc_read_public_keys` | GET | `/identity/oidc/.well-known/keys` | generated | Retrieve public keys |
| `oidc_read_role` | GET | `/identity/oidc/role/{name}` | generated | CRUD operations on OIDC Roles |
| `oidc_read_scope` | GET | `/identity/oidc/scope/{name}` | generated | CRUD operations for OIDC scopes. |
| `oidc_rotate_key` | POST | `/identity/oidc/key/{name}/rotate` | generated | Rotate a named OIDC key. |
| `oidc_write_assignment` | POST | `/identity/oidc/assignment/{name}` | generated | CRUD operations for OIDC assignments. |
| `oidc_write_client` | POST | `/identity/oidc/client/{name}` | generated | CRUD operations for OIDC clients. |
| `oidc_write_key` | POST | `/identity/oidc/key/{name}` | generated | CRUD operations for OIDC keys. |
| `oidc_write_provider` | POST | `/identity/oidc/provider/{name}` | generated | CRUD operations for OIDC providers. |
| `oidc_write_role` | POST | `/identity/oidc/role/{name}` | generated | CRUD operations on OIDC Roles |
| `oidc_write_scope` | POST | `/identity/oidc/scope/{name}` | generated | CRUD operations for OIDC scopes. |
| `persona_create` | POST | `/identity/persona` | generated | Create a new alias. |
| `persona_delete_by_id` | DELETE | `/identity/persona/id/{id}` | generated | Update, read or delete an alias ID. |
| `persona_list_by_id` | GET | `/identity/persona/id` | generated | List all the alias IDs. |
| `persona_read_by_id` | GET | `/identity/persona/id/{id}` | generated | Update, read or delete an alias ID. |
| `persona_update_by_id` | POST | `/identity/persona/id/{id}` | generated | Update, read or delete an alias ID. |

</details>
