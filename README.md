# circuits

## Quickstart Dependencies
<details>
<summary>Linux Dependencies</summary>

```
sudo apt install libgmp3-dev build-essential
```
</details>

**Install**<br>
- [Pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#automatic-installer)<br>
- [Noir](https://noir-lang.org/docs/getting_started/installation/#installing-noirup)<br>

**Then run**<br>
```
noirup --version 0.30.0
cd circuits/lp_hash_verification && $HOME/.nargo/bin/nargo info # trigger install of barratenberg
pyenv install 3.11
pyenv virtualenv 3.11 rift 
python -m pip install -r requirements.txt
```


### Tests
To test any of the scattered unit tests, `cd` into the directory of the subcircuit you want to test and run:
```
nargo test --show-output
```

E2E tests can be run from the root directory:
```
python tests/block_circuit_test.py
python tests/payment_circuit_test.py
python tests/lp_circuit_test.py
python tests/sha256_circuit_test.py
python tests/giga_circuit_test.py
```


### Create Subcircuit Verification Keys
The `Giga` circuit needs verification key hashes to validate the subcircuits it recurses, these can be generated with the following commands.

#### Standard Recursive Circuits 
Generates the verification key hashes for the rift specific recursive circuits (lp hash, block, payment), slow to run.
```
python scripts/generate_subcircuit_verification_keys.py
```

#### Recursive SHA256 Circuit
`n` specifies which chunk (1000 circuits) from 0-6 inclusive to generate verification keys for.
1. Generate verification keys and hashes<br>
    ```python scripts/generate_recursive_sha_vkeys.py <chunk_number>```

2. Create hash list<br>
    ```python scripts/create_recursive_sha256_hashlist.py 1> ./circuits/giga/src/sha256_circuit_hashes.nr```


