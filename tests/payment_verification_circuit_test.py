import os
import sys
import asyncio
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.fetch_block_data import fetch_block_data
from utils.rift_lib import (
    create_block_verification_prover_toml_witness,
    Block,
    compute_block_hash,
    LiquidityProvider,
    create_lp_hash_verification_prover_toml,
    BB
)
from utils.noir_lib import (
    initialize_noir_project_folder,
    compile_project,
    create_witness,
    normalize_hex_str,
    pad_list,
    hex_string_to_byte_array,
    split_hex_into_31_byte_chunks,
    create_proof,
    build_raw_verification_key,
    extract_vk_as_fields,
    verify_proof
)


from bitcoin import SelectParams
from bitcoin.core import b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CTxInWitness, CTxWitness, CScriptWitness, CMutableTransaction, Hash160, CTransaction
from bitcoin.core.script import CScript, OP_0, SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress

def create_simple_fake_payment() -> tuple[CMutableTransaction, str, str]:
    SelectParams("mainnet")

    # Create the (in)famous correct brainwallet secret key.
    h = hashlib.sha256(b'correct horse battery staple').digest()
    seckey = CBitcoinSecret.from_secret_bytes(h)

    # Create an address from that private key.
    public_key = seckey.pub
    scriptPubKey = CScript([OP_0, Hash160(public_key)])
    address = P2WPKHBitcoinAddress.from_scriptPubKey(scriptPubKey)

    # Choose the first UTXO, let's spend it!
           
    txid = "1010000000000000000000000000000000000000000000000000000000dead01"
    vout = 0
    amount = 1000000000 # 10 BTC in satoshis

    # Calculate an amount for the upcoming new UTXO. Set a high fee to bypass
    # bitcoind minfee setting.
    amount_less_fee = int(amount - (0.01 * COIN))

    # Create a destination to send the coins.
    destination_address = "bc1qssdcp5kvwh6nghzg9tuk99xsflwkdv4hgvq58q"
    destination_address = P2WPKHBitcoinAddress(destination_address)
    target_scriptPubKey = destination_address.to_scriptPubKey()

    # Create the unsigned transaction.
    txin = CTxIn(COutPoint(lx(txid), vout))
    txout = CTxOut(amount_less_fee, target_scriptPubKey)
    tx = CMutableTransaction([txin], [txout])

    # Specify which transaction input is going to be signed for.
    txin_index = 0

    # When signing a P2WPKH transaction, use an "implicit" script that isn't
    # specified in the scriptPubKey or the witness.
    redeem_script = address.to_redeemScript()

    # Calculate the signature hash for the transaction. This is then signed by the
    # private key that controls the UTXO being spent here at this txin_index.
    sighash = SignatureHash(redeem_script, tx, txin_index, SIGHASH_ALL, amount=amount, sigversion=SIGVERSION_WITNESS_V0)
    signature = seckey.sign(sighash) + bytes([SIGHASH_ALL])

    # Construct a witness for this transaction input. The public key is given in
    # the witness so that the appropriate redeem_script can be calculated by
    # anyone. The original scriptPubKey had only the Hash160 hash of the public
    # key, not the public key itself, and the redeem script can be entirely
    # re-constructed  if given just the public key. So the public key is added to
    # the witness. This is P2WPKH in bip141.
    witness = [signature, public_key]

    # Aggregate all of the witnesses together, and then assign them to the
    # transaction object.
    ctxinwitnesses = [CTxInWitness(CScriptWitness(witness))]
    tx.wit = CTxWitness(ctxinwitnesses)

    # Done! Print the transaction to standard output. Show the transaction
    # serialization in hex (instead of bytes), and render the txid.

    circuit_txn_data = CTransaction(tx.vin, tx.vout, tx.nLockTime, tx.nVersion).serialize()
    txn_hash = tx.GetTxid().hex()
    return tx, circuit_txn_data.hex(), txn_hash

"""
fn main(
	txn_data_encoded: pub [Field; constants::MAX_ENCODED_CHUNKS],
	liquidity_providers_encoded: pub [[Field; 4]; constants::MAX_LIQUIDITY_PROVIDERS],
	order_nonce_encoded: pub [Field; 2],
	expected_payout: pub u64,
	txn_data: [u8; constants::MAX_TXN_BYTES]
) {
"""

async def test_single_theo_payment():
    print("Testing Single Theo Payment...")
    # [0] compile project folder
    COMPILATION_DIR = "circuits/payment_verification"
    print("Compiling payment verification circuit...")
    #await compile_project(COMPILATION_DIR)
    txn, circuit_txn_data, txn_hash = create_simple_fake_payment()
    print("txn", txn)
    print("txn_hash", txn_hash)
    print("circuit_txn_data", circuit_txn_data)
    





def main():
    asyncio.run(test_single_theo_payment())

if __name__ == "__main__":
    main()
