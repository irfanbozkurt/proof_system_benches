This is a fork of Plonky2 with _nonnative_ arithmetics included, for benching reasons.

Nonnative arithmetics and u32 utils don't compile with latest version of Rust or Plonky2, and this repository solves API and version incompatibilities.

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example pre_block
```
