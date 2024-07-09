import hashlib
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bitcoin import SelectParams
from bitcoin.core import b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CTxInWitness, CTxWitness, CScriptWitness, CMutableTransaction, Hash160, CTransaction
from bitcoin.core.script import CScript, OP_0, CScriptOp, SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from dotenv import load_dotenv

from utils.rift_lib import normalize_hex_str

def get_testnet_wallet() -> tuple[str, str, str]:
    load_dotenv()
    private_key = os.environ["TESTNET_BITCOIN_PRIVATE_KEY"]
    SelectParams("testnet")

    # Create the (in)famous correct brainwallet secret key.
    seckey = CBitcoinSecret.from_secret_bytes(bytes.fromhex(normalize_hex_str(private_key)))

    # Create an address from that private key.
    public_key = seckey.pub
    scriptPubKey = CScript([OP_0, Hash160(public_key)])
    address = P2WPKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
    return seckey.hex(), public_key.hex(), str(address) 

if __name__ == "__main__":
    secret_key, public_key, address = get_testnet_wallet()
    print(f"Secret key: {secret_key}")
    print(f"Public key: {public_key}")
    print(f"Address: {address}")
