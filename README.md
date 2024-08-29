# circuits 

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://succinctlabs.github.io/sp1/getting-started/install.html)
- [Docker](https://docs.docker.com/get-docker/)

### Directory Overview

| Directory | Purpose | Contents |
|-----------|---------|----------|
| `lib/`    | Internal Library | Encapsulates all circuit business logic |
| `program/`| Executable Wrapper | Combines SP1 with our circuit library to create the program executable |
| `script/` | Build Utilities | Contains scripts for building vkeys, proofs and evm artifacts |
| `utils/`  | Client Library | Client-facing library for creating proofs and interacting with the circuit |
| `tests/`  | Testing Suite | Unit and Integration tests |

### Run Unit Tests
```sh
./download_test_blocks.s
cargo test -p tests
```

### Run Specific Test
```sh
cargo test -p tests --test <test_name>
# <tx_hash | sha256_merkle | bitcoin | lp_hash | payment | giga>
```

### Generate Test Plonk Proof
```sh
cargo run --release --bin plonk_test
```

### Retrieve the Verification Key

To retrieve your `programVKey` for your on-chain contract, run the following command:

```sh
cargo run --release --bin vkey
```

