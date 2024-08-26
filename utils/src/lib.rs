mod errors;
use errors::{BitcoinRpcError};
use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use rift_lib::sha256_merkle::{MerkleProofStep};


pub async fn generate_merkle_proof(txns: Vec<[u8; 32]>, natural_txid: [u8; 32]) -> Result<[u8; 32], BitcoinRpcError> {
    todo!()
}

