![Rust](https://github.com/a-a-hofmann/evote-crypto/workflows/Rust/badge.svg)

# evote-crypto-rs
Simple rust crypto library for my thesis. Only includes text-book version of crypto algorithms.

The goal is to implement the crypto primitives in such a way that is wasm compatible in order to be used as a dependency for the Substrate e-voting pallet.

## Benchmark
To run the benchmark. Pull the repository and run:

```bash
cargo bench --features bench
```