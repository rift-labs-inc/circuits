#[cfg(test)]
mod tests {
    use rift_lib::sha256_merkle::{hash_pairs, MerkleProofStep, assert_merkle_proof_equality};
    use hex_literal::hex;
    use bitcoincore_rpc_async::bitcoin::Block;
    
    #[test]
    fn test_hash_pairs() {
        //let block: Block = deserialize(&Vec::<u8>::from_hex(block_hex).unwrap()).unwrap();
    }

}

