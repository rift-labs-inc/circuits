# circuits

## Quickstart Dependencies
<details>
<summary>Linux Dependencies</summary>

```
sudo apt install libgmp3-dev build-essential
```
</details>

[pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#automatic-installer)<br>
[noir](https://noir-lang.org/docs/getting_started/installation/#installing-noirup)<br>

```
noirup --version 0.30.0
cd circuits/lp_hash_verification && $HOME/.nargo/bin/nargo info # trigger install of barratenberg
pyenv install 3.11
pyenv virtualenv 3.11 rift 
python -m pip install -r requirements.txt
```

### Create Subcircuit Verification Keys

#### Standard Recursive Circuits 
Generates the verification key hashes for the standard recursive circuits (lp hash, block, payment), slow to run.
```
python scripts/generate_recursive_circuit_verification_key_hashes.py 1> ./circuits/giga/src/recursive_circuit_hashes.nr
```

#### Recursive SHA256 Circuit
`n` specifies which chunk (1000 circuits) from 0-6 inclusive to generate verification keys for.
1. Generate verification keys and hashes<br>
    ```python scripts/generate_recursive_sha_vkeys.py <chunk_number>```

2. Create hash list<br>
    ```python scripts/create_recursive_sha256_hashlist.py 1> ./circuits/giga/src/sha256_circuit_hashes.nr```


