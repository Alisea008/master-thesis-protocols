# Transieve

Transieve is an evaluation framework for measuring the real cost of transciphering (hybrid homomorphic encryption). It separates a transciphering pipeline into three swappable layers: an application workload, a symmetric cipher with its homomorphic decryption circuit, and an FHE backend. Whole pipelines can then be compared end to end under one workload, one security level, and one set of metrics, and a new cipher, backend, or workload can be added without touching the rest.

The framework ships with three backends (TFHE-Boolean, TFHE-shortint, and leveled BFV), five ciphers (Kreyvium, Grain-128a, AES-128, Rasta-525-5, and Pasta-3), and two workloads: threshold private set intersection over Bloom filters, the primary benchmark, and a secure voting tally that demonstrates the swappable workload layer. A small CLI drives dataset generation, single experiments, scaling sweeps, and verification.

## Requirements

- A recent Rust toolchain with Cargo (stable Rust, edition 2021)
- A 64-bit host (the TFHE stack targets x86_64)
- The Rust dependencies declared in [Cargo.toml](Cargo.toml)

### Main dependencies

The core project depends on:

- `clap` for command-line parsing
- `serde` / `serde_json` for config and output data
- `bincode` and `anyhow` for serialization and error handling
- `rand`, `siphasher`, and `itertools` for sampling and data generation
- `tfhe` for the FHE backend implementations

Optional support for the BFV backend is behind the `bfv` feature:

```bash
cargo build --release --features bfv
```

After building, run the compiled binary directly:

```bash
./target/release/transieve <command> [options]
```

On Windows PowerShell, use:

```powershell
.\target\release\transieve.exe <command> [options]
```

## Source layout

```text
src/
|-- app/          application adapters
|-- backend/      Boolean, shortint, and optional BFV FHE backends
|-- cipher/       transciphering cipher implementations
|-- protocol/     Bloom filters, circuits, datasets, extraction, verification
|-- runtime/      config, pipeline, scaling, timing
|-- lib.rs
`-- main.rs
```

## Setup

1. Clone the repository and enter it.
2. Build the project:

   ```bash
   cargo build --release
   ```

3. Generate the party-set data described by the runtime config:

   ```bash
   ./target/release/transieve generate
   ```

   This reads [party_sets/party_sets_meta.json](party_sets/party_sets_meta.json)
and writes the cached dataset directories under [party_sets](party_sets).

4. Optionally verify the generated data:

   ```bash
   ./target/release/transieve verify
   ```

## Available commands

Use the compiled CLI:

```bash
./target/release/transieve <command> [options]
```

The supported commands are:

- `generate` — create the cached party-set directories implied by the config
- `sample` — run one end-to-end sample experiment
- `scaling` — run one or more scaling sweeps and emit CSV output
- `verify` — sanity-check the cached party-set directories

Run the built-in help for the full argument list:

```bash
./target/release/transieve --help
./target/release/transieve sample --help
./target/release/transieve scaling --help
```

## Small smoke tests and local runs

These examples are intended for quick local validation with small parameters.

### Plaintext-only smoke test

```bash
./target/release/transieve sample \
  --plaintext-only \
  --parties 3 \
  --threshold 2 \
  --common 5 \
  --size 100
```

This skips the FHE path and is useful for checking the surrounding pipeline.

### Small full sample run

```bash
./target/release/transieve sample \
  --parties 4 \
  --threshold 2 \
  --common 4 \
  --size 200 \
  --sample-bits 1000
```

The `--sample-bits` flag overrides the per-run FHE sample cap for a lighter
local run.

### Small scaling sweep

```bash
./target/release/transieve scaling \
  --sweep parties \
  --n-values 4,6,8 \
  --sample-bits 1000 \
  --tag smoke
```

This writes CSV results into the configured output directory (default:
`benchmark_outputs_circuit`).

### Optional transciphering smoke test

```bash
./target/release/transieve sample \
  --parties 3 \
  --threshold 2 \
  --common 5 \
  --size 100 \
  --transcipher kreyvium
```

The `--transcipher` flag runs the named cipher as a transciphering stage.
Supported Boolean names include `kreyvium`, `grain128a`, `rasta`, and `aes128`.
Shortint variants such as `rasta-shortint` and `aes-shortint` are also available.

## Parameters you can set

### Sample command

The `sample` subcommand accepts:

- `--app` — choose the application mode (`tpsi` or `voting`)
- `--parties` — override the number of parties `N`
- `--threshold` — override the threshold `T`
- `--common` — override the number of common IPs `C`
- `--size` — override the party-set size `S`
- `--plaintext-only` — skip FHE and transcipher work
- `--baseline` — choose the direct baseline backend (`boolean`, `shortint`, or `bfv`)
- `--transcipher` — enable a transciphering stage with a named cipher
- `--microbench` — run the Boolean single-party cipher microbenchmark
- `--sample-bits` — reduce the per-run FHE sample-bit cap for lighter runs

### Scaling command

The `scaling` subcommand accepts:

- `--app` — choose the application mode (`tpsi` or `voting`)
- `--sweep` — choose `all`, `parties`, `threshold`, `set_size`, or `common_ips`
- `--baseline` — choose the bare baseline backend
- `--transcipher` — run each sweep point with a named transciphering cipher
- `--plaintext-only` — skip FHE/transcipher work and emit the cheaper protocol metrics
- `--n-values` — override the parties sweep values as a comma-separated list
- `--sample-bits` — reduce the per-point FHE sample-bit cap
- `--tag` — add a filename suffix to distinguish repeated runs

## Configuration

Runtime behavior is driven by [party_sets/party_sets_meta.json](party_sets/party_sets_meta.json).
That file defines:

- `sample_config` — the default parameters used by `sample`
- `scaling_config` — the default sweep ranges and output location

The default output directory for sweep CSVs is `benchmark_outputs_circuit` unless the
config changes it.

## Implementation Docs

- [Cipher implementations](docs/implementation/ciphers.md)
- [TFHE backend notes](docs/implementation/tfhe-backends.md)
- [BFV backend notes](docs/implementation/bfv-backend.md)
- [Pasta on BFV](docs/implementation/pasta-bfv.md)
