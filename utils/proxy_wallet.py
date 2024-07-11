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


def get_testnet_wallet() -> BitcoinWallet:
    load_dotenv()
    private_key = os.environ["TESTNET_BITCOIN_PRIVATE_KEY"]
    SelectParams("testnet")

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

def get_secondary_testnet_wallets(num: int) -> list[BitcoinWallet]:
    secret_base = os.environ['TESTNET_BITCOIN_SECONDARY_PRIVATE_KEY_BASE']
    SelectParams("testnet")
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

    tx = CMutableTransaction([txin], [*lp_outputs, change_output]) #inscription, 

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
    wallet = get_testnet_wallet()
    lp_wallets = [LiquidityProvider(amount=1_000_000, btc_exchange_rate=1, locking_script_hex=wallet.unlock_script) for wallet in get_secondary_testnet_wallets(10)] 
    unbroadcast_txn = asyncio.run(build_rift_payment_transaction(
        order_nonce_hex=hashlib.sha256(b"rift").hexdigest(),
        liquidity_providers=lp_wallets,
        in_tx_block_hash_hex="0000000000006f2fa21b8d8dccd3a21af9cd81bfed2db1382fa98636154147d7",
        in_txid_hex="6718c0391fc4cc0d2170bc99bdcfc6e57deafe08acc1f2ba6387371b85982a02",
        in_txvout=11,
        wallet=wallet,
        rpc_url=get_rpc(mainnet=False),
        mainnet=False,
        fee_sats=900_000
    ))
    print("Txn Data:", json.dumps(unbroadcast_txn, indent=2))
    # broadcast
    print(asyncio.run(broadcast_transaction(unbroadcast_txn["tx"], get_rpc(mainnet=False))))
    """
    Txn Data: {
      "txid_data": "0100000001022a98851b378763baf2c1ac08feea7de5c6cfbd99bc70210dccc41f39c018670b00000000fdffffff0b40420f00000000001600145a56436f3106b12a7e25df0b2facbc334ea6de5f40420f00000000001600140e9e91b8531fceb498204d17ef8d088ee0fa8d7a40420f00000000001600140c2eed55791ba08075baa9203dc89a12da2e0b3d40420f000000000016001441d5b79bf267c92aa387b99f4aa71cd88cb72a4440420f0000000000160014911a98c4e8ffc4f9f306402ac180ccbf4eba9d9440420f0000000000160014193f1ba0362901bd02fe7f750af4b71c4c07dbd840420f00000000001600140aa437977cb2d9992342ffa445dd08c216e6dee240420f0000000000160014f9f3a59d86bfc7849d1bcff2ecea69c4820fa04740420f0000000000160014c3198a9fddf935a49ff80bae5229d5dba079cae340420f0000000000160014802903cc08b1df3f445c11c7f19c2cd92f907e81c04c60640100000016001455d2d56a5a9314b63acb7c3b2567ff795179166400000000",
      "txid": "387a650ebf14875b1f3f59ba6b32ca20e3387e3643419aef7169f0ce17e9502b",
      "tx": "01000000000101022a98851b378763baf2c1ac08feea7de5c6cfbd99bc70210dccc41f39c018670b00000000fdffffff0b40420f00000000001600145a56436f3106b12a7e25df0b2facbc334ea6de5f40420f00000000001600140e9e91b8531fceb498204d17ef8d088ee0fa8d7a40420f00000000001600140c2eed55791ba08075baa9203dc89a12da2e0b3d40420f000000000016001441d5b79bf267c92aa387b99f4aa71cd88cb72a4440420f0000000000160014911a98c4e8ffc4f9f306402ac180ccbf4eba9d9440420f0000000000160014193f1ba0362901bd02fe7f750af4b71c4c07dbd840420f00000000001600140aa437977cb2d9992342ffa445dd08c216e6dee240420f0000000000160014f9f3a59d86bfc7849d1bcff2ecea69c4820fa04740420f0000000000160014c3198a9fddf935a49ff80bae5229d5dba079cae340420f0000000000160014802903cc08b1df3f445c11c7f19c2cd92f907e81c04c60640100000016001455d2d56a5a9314b63acb7c3b2567ff795179166402473044022030d4354c3b6547b7890bfb19ca5ba7bf5e0ed6daed3a27a23e2ee9e4302720e6022034c7ae686ae2e5fb9ee3cf5af503958426e390fea4045768c6aaa9fe89693cb2012102b14f0a5b2b39520d75bee0c6b655a0776e0db9b435163973d17788aa7d773f3100000000"
    }
    {'result': '2b50e917cef06971ef9a4143367e38e320ca326bba593f1f5b8714bf0e657a38', 'error': None, 'id': 'curltext'}
    block hash: 000000000000001dd60372c3aaf4a8a20bdcc726b49707e552505f0b238b428e
    """

