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

## Licence and Contributor Licence Agreement

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Before we can merge your first pull request, you need to accept the
[Privasys Contributor Licence Agreement](https://github.com/Privasys/cla). You
keep the copyright in your work; the agreement lets Privasys also license it
under other terms, and Privasys commits to keeping it available under an
open-source licence. A check on your pull request explains how to accept: one
comment, once, for every Privasys repository. If you contribute as part of your
work for an employer, your employer may need to sign the entity agreement
instead.
