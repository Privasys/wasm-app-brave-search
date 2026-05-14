# Contributing

Thank you for your interest in `wasm-app-brave-search`.

## Filing issues

Use GitHub Issues on this repository. For security issues, see
[SECURITY.md](SECURITY.md) — please do not open public issues for
suspected vulnerabilities.

## Pull requests

1. Fork the repo and create a topic branch from `main`.
2. Keep changes small and focused; separate logically distinct work
   into separate PRs.
3. Run `cargo component build --release --target wasm32-wasip1`
   locally to confirm the WIT bindings still generate cleanly. The
   final attestable `.cwasm` is produced by the
   [reproducible-app-builder](https://github.com/Privasys/reproducible-app-builder)
   CI workflow, not locally.
4. If you change the WIT world (`wit/world.wit`), the per-app
   `configuration_hash` will change too. Mention this in your PR
   description so deployment review notices.

## Coding conventions

- No `serde_json` / heavyweight deps — keep the cwasm small. The
  hand-rolled JSON walker in `src/lib.rs` is intentional.
- All HTTP must go through `privasys:enclave-os/https.fetch` so TLS
  terminates inside the enclave.
- Read secrets from `wasi:cli/environment` only; never bake them into
  the binary.

## License

By submitting a contribution you agree it will be released under the
[GNU Affero General Public License v3.0](LICENSE).
