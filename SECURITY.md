# Security Policy

## Reporting a Vulnerability

We take a very active stance in eliminating security problems. We
strongly encourage you to report such problems to our private mailing
list first ([security@privasys.org](mailto:security@privasys.org)),
before disclosing them in a public forum.

## Threat model

This app is a thin wrapper around the Brave Web Search API whose sole
security purpose is to keep the `BRAVE_API_KEY` inside the enclave's
sealed per-app storage. Concretely:

- The `.cwasm` binary is reproducibly built from this repo's commit
  by [reproducible-app-builder](https://github.com/Privasys/reproducible-app-builder)
  and its SHA-256 is committed into the app's RA-TLS certificate.
- `BRAVE_API_KEY` is delivered to the enclave inside the
  authenticated `wasm_load.env` payload, sealed at rest by the
  enclave's per-app AES-256 key, and surfaced to the guest only via
  `wasi:cli/environment.get-environment()`.
- TLS to `api.search.brave.com` terminates inside the enclave; the
  host kernel and hypervisor see only ciphertext.
- The sorted list of env-var **keys** (not values) is folded into
  the per-app `configuration_hash` (X.509 OID
  `1.3.6.1.4.1.65230.3.5`) so attestation reflects which secrets are
  configured without leaking the secrets themselves.

## Out of scope

- Brave's own service availability and result quality.
- Misconfiguration of the surrounding fleet (e.g. exposing this tool
  to anonymous callers without rate limiting upstream).
