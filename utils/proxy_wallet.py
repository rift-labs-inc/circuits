import hashlib
from typing import cast
import json
import asyncio
import os
import sys

from pydantic import BaseModel

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bitcoin import SelectParams
from bitcoin.core import CMutableTxIn, b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CTxInWitness, CTxWitness, CScriptWitness, CMutableTransaction, Hash160, CTransaction
from bitcoin.core.script import CScript, OP_0, CScriptOp, SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from dotenv import load_dotenv

from utils.rift_lib import LiquidityProvider, normalize_hex_str
from utils.btc_data import broadcast_transaction, fetch_transaction_data_in_block, fetch_utxo_status, get_rpc 

class BitcoinWallet(BaseModel, arbitrary_types_allowed=True):
    secret_key: CBitcoinSecret
    public_key: str
    unlock_script: str
    address: str


def get_wallet(mainnet: bool = True) -> BitcoinWallet:
    load_dotenv()
    SelectParams("mainnet" if mainnet else "testnet")
    private_key = os.environ["TESTNET_BITCOIN_PRIVATE_KEY"] if not mainnet else os.environ["MAINNET_BITCOIN_PRIVATE_KEY"]

    # Create the (in)famous correct brainwallet secret key.
    seckey = CBitcoinSecret.from_secret_bytes(bytes.fromhex(normalize_hex_str(private_key)))

    # Create an address from that private key.
    public_key = seckey.pub
    scriptPubKey = CScript([OP_0, Hash160(public_key)])
    address = P2WPKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
    return BitcoinWallet(
        secret_key=seckey,
        public_key=public_key.hex(),
        unlock_script=scriptPubKey.hex(),
        address=str(address)
    )

def get_secondary_wallets(num: int, mainnet: bool = True) -> list[BitcoinWallet]:
    secret_base = os.environ['MAINNET_BITCOIN_SECONDARY_PRIVATE_KEY_BASE'] if mainnet else os.environ['TESTNET_BITCOIN_SECONDARY_PRIVATE_KEY_BASE']
    SelectParams("mainnet" if mainnet else "testnet")
    wallets = []
    for i in range(num):
        secret_key = CBitcoinSecret.from_secret_bytes(hashlib.sha256((secret_base + str(i)).encode()).digest())
        public_key = secret_key.pub
        scriptPubKey = CScript([OP_0, Hash160(public_key)])
        address = P2WPKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        wallets.append(BitcoinWallet(
            secret_key=secret_key,
            public_key=public_key.hex(),
            unlock_script=scriptPubKey.hex(),
            address=str(address)
        ))
    return wallets


# doesn't modify btc state (safe)
# in_txid_hex is little endian (what you see on block explorers)
async def build_rift_payment_transaction(
    order_nonce_hex: str,
    liquidity_providers: list[LiquidityProvider],
    in_tx_block_hash_hex: str,
    in_txid_hex: str,
    in_txvout: int,
    wallet: BitcoinWallet,
    rpc_url: str,
    fee_sats: int = 50_000,
    mainnet: bool = True
):
    SelectParams("mainnet" if mainnet else "testnet")

    transaction = await fetch_transaction_data_in_block(
        block_hash=normalize_hex_str(in_tx_block_hash_hex),
        txid=normalize_hex_str(in_txid_hex),
        rpc_url=rpc_url,
        verbose=True
    )

    """
    fetch_utxo = await fetch_utxo_status(
        txid=normalize_hex_str(in_txid_hex),
        vout=in_txvout,
        rpc_url=rpc_url
    )
    print("UTXO Status:", fetch_utxo)
    """


    total_lp_sum = sum(lp.amount for lp in liquidity_providers)
    vin_sats = int(float(transaction["vout"][in_txvout]["value"]) * COIN)
    print("Vin sats", vin_sats)
    assert total_lp_sum <= vin_sats 

    lp_outputs = [
        CTxOut(
            lp.amount,
            CScript(bytes.fromhex(normalize_hex_str(lp.locking_script_hex)))
        )
        for i, lp in enumerate(liquidity_providers)
    ]
    assert (vin_sats - total_lp_sum - fee_sats) >= 0
    change_output = CTxOut(
        vin_sats - total_lp_sum - fee_sats,
        CScript(bytes.fromhex(wallet.unlock_script))
    )

    OP_RETURN = bytes.fromhex("6a")
    OP_PUSHBYTES_32 = bytes.fromhex("20")
    inscription = CTxOut(0, CScript(OP_RETURN + OP_PUSHBYTES_32 + bytes.fromhex(normalize_hex_str(order_nonce_hex))))

    # Create the unsigned transaction.
    txin = CTxIn(COutPoint(bytes.fromhex(normalize_hex_str(in_txid_hex))[::-1], in_txvout), nSequence=0xfffffffd)

    tx = CMutableTransaction([txin], [*lp_outputs, inscription, change_output])

    # Specify which transaction input is going to be signed for.
    txin_index = 0

    # When signing a P2WPKH transaction, use an "implicit" script that isn't
    # specified in the scriptPubKey or the witness.
    address = P2WPKHBitcoinAddress.from_scriptPubKey(CScript([OP_0, Hash160(bytes.fromhex(normalize_hex_str(wallet.public_key)))])) #type:ignore
    redeem_script = address.to_redeemScript()

    # Calculate the signature hash for the transaction. This is then signed by the
    # private key that controls the UTXO being spent here at this txin_index.
    sighash = SignatureHash(redeem_script, tx, txin_index, SIGHASH_ALL, amount=vin_sats, sigversion=SIGVERSION_WITNESS_V0)
    signature = cast(bytes, wallet.secret_key.sign(sighash)) + bytes([SIGHASH_ALL])

    # Construct a witness for this transaction input. The public key is given in
    # the witness so that the appropriate redeem_script can be calculated by
    # anyone. The original scriptPubKey had only the Hash160 hash of the public
    # key, not the public key itself, and the redeem script can be entirely
    # re-constructed  if given just the public key. So the public key is added to
    # the witness. This is P2WPKH in bip141.
    witness = [signature, bytes.fromhex(normalize_hex_str(wallet.public_key))]

    # Aggregate all of the witnesses together, and then assign them to the
    # transaction object.
    ctxinwitnesses = [CTxInWitness(CScriptWitness(witness))]
    tx.wit = CTxWitness(ctxinwitnesses)

    # Done! Print the transaction to standard output. Show the transaction
    # serialization in hex (instead of bytes), and render the txid.

    # debug

    # this doesn't include any segwit data on purpose
    circuit_txn_data = CTransaction(tx.vin, tx.vout, tx.nLockTime, tx.nVersion).serialize()
    txn_hash = tx.GetTxid().hex()
    return {
        "txid_data": circuit_txn_data.hex(),
        "txid": txn_hash,
        "tx": tx.serialize().hex()
    }

if __name__ == "__main__":
    mainnet = True
    wallet = get_wallet(mainnet=mainnet)
    lp_wallets = [LiquidityProvider(amount=420, btc_exchange_rate=1, locking_script_hex=wallet.unlock_script) for wallet in get_secondary_wallets(3, mainnet=True)] 
    print("LP WALLETS", lp_wallets)
    unbroadcast_txn = asyncio.run(build_rift_payment_transaction(
        order_nonce_hex=hashlib.sha256(b"rift").hexdigest(),
        liquidity_providers=lp_wallets,
        in_tx_block_hash_hex="000000000000000000034668ec702a564a51deff2b01bcd3ea17a5934792b3c1",
        in_txid_hex="90e1921d161bf93d51da10422c74fab914fa14acdfa7ff6e5d1cfd0ef587c63e",
        in_txvout=3,
        wallet=wallet,
        rpc_url=get_rpc(mainnet=mainnet),
        mainnet=mainnet,
        fee_sats=1600
    ))
    print("Txn Data:", json.dumps(unbroadcast_txn, indent=2))
    # broadcast
    print(asyncio.run(broadcast_transaction(unbroadcast_txn["tx"], get_rpc(mainnet=mainnet))))
