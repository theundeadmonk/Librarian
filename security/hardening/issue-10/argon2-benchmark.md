# Argon2id Version 1 Development Benchmark

**Date:** 2026-07-23
**Status:** Development-machine evidence; slowest-supported-baseline run still required

## Profile

- Argon2id version `0x13`
- memory: `65,536` KiB
- iterations: `3`
- parallelism: `4`
- output: `32` bytes
- build: Rust `1.97.1`, `--release`, `x86_64-pc-windows-msvc`

## Machine

- Windows 11 Pro `10.0.26200` (build `26200`)
- 13th Gen Intel Core i9-13900KF
- 24 physical cores, 32 logical processors
- 32,265 MiB visible memory

## Result

Twenty consecutive master-password unlocks of the same deterministic empty
vault produced:

- median: `76 ms`
- p95: `97 ms`

The run used the ignored
`benchmark_version_one_argon2_unlock_profile` test in `librarian-vault-core`.
It measures the complete core unlock path, including the KDF, wrapper
authentication, manifest authentication, and strict decoding.

## Reproduction

```powershell
cargo test -p librarian-vault-core `
  --release `
  --locked `
  --target x86_64-pc-windows-msvc `
  benchmark_version_one_argon2_unlock_profile `
  -- `
  --ignored `
  --nocapture
```

## Acceptance boundary

This machine is substantially faster than a reasonable minimum Windows 11
baseline. The result proves that the exact profile is wired and measurable; it
does not establish the final product latency budget. Repeat the same harness on
the slowest supported Windows 11 hardware after that baseline and budget are
defined. Do not weaken the profile as a fallback. `FormatReadiness` remains
`ScaffoldOnly`.
