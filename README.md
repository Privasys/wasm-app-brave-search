# wasm-app-brave-search

Brave Web Search MCP tool for the Privasys enclave runtime.

This is a [WASM Component](https://component-model.bytecodealliance.org/)
that runs inside an attestable enclave (SGX via `enclave-os-mini`). Its
sole job is to wrap the
[Brave Search Web API](https://api-dashboard.search.brave.com/app/documentation/web-search/get-started)
so the subscription token (`X-Subscription-Token`) is held inside the
enclave and never crosses an untrusted boundary.

It exposes two functions to the chat assistant via MCP:

| Function | Description |
| --- | --- |
| `search(query, count)` | Returns up to `count` parsed `{title, url, description}` hits. |
| `search-raw(query, count)` | Returns the raw Brave JSON body. |

`count` is clamped to `1..=20` (the upper bound the Brave Web Search
endpoint enforces); pass `0` to use the default of `10`.

## Why a separate tool?

The fleet's existing browse tool (`lightpanda`) is a headless browser
that fetches a single page. It cannot answer questions like *"What's
the latest on X?"* because the model first needs to discover relevant
URLs. This app is the missing search step — and unlike calling Brave
directly from the chat backend, the API key lives inside the enclave's
sealed per-app storage, so neither the host kernel nor the chat
operator can see it.

## Configuration — required env var

The Brave subscription token is injected via the per-app `wasm_env`
map at deploy time. It is sealed at rest by the enclave's per-app
AES-256 key and surfaced to the guest through
`wasi:cli/environment.get-environment()`. It never leaves the
enclave.

| Env var | Purpose |
| --- | --- |
| `BRAVE_API_KEY` | Brave Search subscription token, sent as `X-Subscription-Token`. |

Set it via the developer portal (App → Settings → environment
variables). The portal pushes the value **directly to the enclave**
over RA-TLS / sealed session-relay; it never traverses a
non-attestable service. Inside the enclave the value is sealed at
rest with the per-app AES-256 key.

Then redeploy the app so the new env reaches the enclave inside the
next `wasm_load` envelope.

The sorted list of env-var **keys** is folded into the per-app
`configuration_hash` (X.509 OID `1.3.6.1.4.1.65230.3.5`) for
attestation; **values** are deliberately excluded so secret rotation
does not invalidate the app's RA-TLS certificate, and so secrets
never leak through the public attestation extension.

## Build

The `.cwasm` MUST be produced via the
[reproducible-app-builder](https://github.com/Privasys/reproducible-app-builder)
GitHub Actions workflow — not locally — because the wasmtime engine
config used for AOT compilation must exactly match the in-enclave
runtime, and the build pipeline injects WIT doc comments + `@auth`
annotations into a `package-docs` custom section that the management
service forwards to the enclave on `wasm_load`.

Local sanity-check (cargo-component):

```bash
cargo component build --release --target wasm32-wasip1
```

## Deploy

1. Create the app row in the management service with `app_type=wasm`,
   pointing at this repo.
2. Trigger `build-cwasm.yml` against this repo's commit (the developer
   portal does this for you on "Build new version").
3. Set `BRAVE_API_KEY` (above).
4. Deploy the version to an SGX enclave (the developer portal's
   "Deploy" tab handles this).
5. Register a corresponding `ai_tools` row so the chat fleet exposes
   it as an MCP tool (`transport=privasys_http`,
   `enabled_default=true`).

## Security notes

- TLS to `api.search.brave.com` terminates inside the enclave — the
  API key is never visible to the host kernel or hypervisor.
- The response is parsed with a hand-rolled minimal JSON walker (no
  `serde_json`) to keep the cwasm small. The parser is forgiving:
  unknown fields are ignored, missing fields substitute empty strings,
  and zero results return an empty `hits` list rather than an error.
- This app does not use the auth interface — it is intentionally
  callable by anonymous chat sessions, since the upstream gateway
  already authenticates the chat user.
- Reproducibility: the cwasm artefact's SHA-256 is committed into the
  app's RA-TLS certificate; clients can rebuild from this repo's
  commit and verify the digest matches end-to-end.

## License

GNU Affero General Public License v3.0. See [`LICENSE`](LICENSE).
