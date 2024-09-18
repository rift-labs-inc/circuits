#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin::Block;

    use crypto_bigint::{Encoding, U256};
    use hex_literal::hex;
    use rift_core::btc_light_client::{
        assert_blockchain, assert_pow, bits_to_target, verify_block, AsLittleEndianBytes,
        Block as RiftOptimizedBlock,
    };
    use rift_lib::{get_retarget_height_from_block_height, load_hex_bytes, AsRiftOptimizedBlock};

    #[test]
    fn test_rift_block_converter() {
        let block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let canon_serialized_header = serialize(&block.header);
        let rift_block = block.as_rift_optimized_block().serialize();
        assert_eq!(
            canon_serialized_header, rift_block,
            "Rift block serialization failed"
        );
    }

    #[test]
    fn test_block_hash() {
        let block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let rift_block = &block.as_rift_optimized_block();

        let canon_block_hash = block.header.block_hash().as_byte_array().to_little_endian();
        let rift_block_hash = rift_block.compute_block_hash();

        assert_eq!(
            canon_block_hash, rift_block_hash,
            "Block hash computation failed"
        );
    }

    #[test]
    fn test_bits_to_target() {
        let block: Block = deserialize(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let rift_block = &block.as_rift_optimized_block();
        println!("Bits: {:?}", rift_block.bits);

        let canon_target = block.header.target();

        let proposed_target = bits_to_target(rift_block.bits);

        println!("Canon target:    {:?}", canon_target.to_be_bytes());

        println!(
            "Proposed target: {:?}",
            Vec::<u8>::from_hex(&proposed_target.to_string()).unwrap()
        );

        assert_eq!(
            canon_target.to_be_bytes(),
            Vec::<u8>::from_hex(&proposed_target.to_string())
                .unwrap()
                .as_slice(),
            "Bits to target conversion failed"
        );
    }

    #[test]
    fn test_assert_pow() {
        let block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let rift_block = &block.as_rift_optimized_block();

        assert_pow(
            &rift_block.compute_block_hash(),
            &rift_block,
            bits_to_target(rift_block.bits),
        );
    }

    #[test]
    #[should_panic(expected = "PoW invalid hash < target")]
    fn test_assert_pow_fails_on_hash_less_than_target() {
        let block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let mut rift_block = block.as_rift_optimized_block();
        //  a nonce that will ~100% likely result in a hash less than the target
        rift_block.nonce = [0; 4];

        assert_pow(
            &rift_block.compute_block_hash(),
            &rift_block,
            bits_to_target(rift_block.bits),
        );
    }

    #[test]
    fn test_verify_block_transition() {
        let first_block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let second_block = deserialize::<Block>(&load_hex_bytes("data/block_858565.hex")).unwrap();

        let first_rift_block = first_block.as_rift_optimized_block();
        let second_rift_block = &second_block.as_rift_optimized_block();

        let first_block_hash = first_rift_block.compute_block_hash();
        let second_block_hash = second_rift_block.compute_block_hash();

        let retarget_height = get_retarget_height_from_block_height(first_rift_block.height);
        let retarget_block = deserialize::<Block>(&load_hex_bytes(&format!(
            "data/block_{}.hex",
            retarget_height
        )))
        .unwrap();
        let rift_retarget_block = &retarget_block.as_rift_optimized_block();

        println!("First Block Hash: {:?}", first_block_hash.as_hex());

        verify_block(
            second_block_hash,
            first_block_hash,
            &second_rift_block,
            &rift_retarget_block,
            first_rift_block.height,
        )
    }

    #[test]
    #[should_panic(expected = "Proposed prev_block hash does not match real prev_block hash")]
    fn test_verify_block_transition_fails_no_link() {
        let first_block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let second_block = deserialize::<Block>(&load_hex_bytes("data/block_858565.hex")).unwrap();

        let mut first_rift_block = first_block.as_rift_optimized_block();
        first_rift_block.prev_blockhash = [0; 32];
        let second_rift_block = &second_block.as_rift_optimized_block();

        let first_block_hash = first_rift_block.compute_block_hash();
        let second_block_hash = second_rift_block.compute_block_hash();

        let retarget_height = get_retarget_height_from_block_height(first_rift_block.height);
        let retarget_block = deserialize::<Block>(&load_hex_bytes(&format!(
            "data/block_{}.hex",
            retarget_height
        )))
        .unwrap();
        let rift_retarget_block = &retarget_block.as_rift_optimized_block();

        verify_block(
            second_block_hash,
            first_block_hash,
            &second_rift_block,
            &rift_retarget_block,
            first_rift_block.height,
        )
    }

    #[test]
    fn test_blockchain_verifies() {
        let initial_block = 858564;
        let block_delta = 3;
        // chainwork of block 858564
        let intial_block_chainwork = U256::from_be_bytes(hex!(
            "00000000000000000000000000000000000000008b0ed4006167d9147181e166"
        ));
        // chainwork of block 858567

        let final_block_chainwork = U256::from_be_bytes(hex!(
            "00000000000000000000000000000000000000008b0fc108548a1a9c90289890"
        ));
        let blocks = (0..block_delta)
            .map(|i| {
                deserialize::<Block>(&load_hex_bytes(&format!(
                    "data/block_{}.hex",
                    initial_block + i
                )))
                .unwrap()
                .as_rift_optimized_block()
            })
            .collect::<Vec<RiftOptimizedBlock>>();

        let retarget_block = &deserialize::<Block>(&load_hex_bytes(&format!(
            "data/block_{}.hex",
            get_retarget_height_from_block_height(initial_block)
        )))
        .unwrap()
        .as_rift_optimized_block();

        let commited_block_hashes = blocks
            .iter()
            .map(|block| block.compute_block_hash())
            .collect::<Vec<[u8; 32]>>();

        println!(
            "Block heights {:?}",
            blocks
                .iter()
                .map(|block| block.height)
                .collect::<Vec<u64>>()
        );

        println!("Retarget block bits: {:?}", retarget_block.bits);
        println!("Initial block bits: {:?}", blocks[0].bits);

        assert_blockchain(
            commited_block_hashes,
            initial_block,
            intial_block_chainwork,
            retarget_block.compute_block_hash(),
            get_retarget_height_from_block_height(initial_block),
            final_block_chainwork,
            blocks,
            *retarget_block,
        );
    }

    #[test]
    fn test_blockchain_verifies_during_retarget() {
        let initial_block = 856799;
        let block_delta = 2;
        let intial_block_chainwork = U256::from_be_bytes(hex!(
            "000000000000000000000000000000000000000088ee16bb485893eb55b2efe0"
        ));

        let blocks = (0..block_delta)
            .map(|i| {
                deserialize::<Block>(&load_hex_bytes(&format!(
                    "data/block_{}.hex",
                    initial_block + i
                )))
                .unwrap()
                .as_rift_optimized_block()
            })
            .collect::<Vec<RiftOptimizedBlock>>();

        println!("Blocks: {:?}", blocks.len());
        println!("retarget height {}", get_retarget_height_from_block_height(initial_block));

        let retarget_block = &deserialize::<Block>(&load_hex_bytes(&format!(
            "data/block_{}.hex",
            get_retarget_height_from_block_height(initial_block)
        )))
        .unwrap()
        .as_rift_optimized_block();

        let commited_block_hashes = blocks
            .iter()
            .map(|block| block.compute_block_hash())
            .collect::<Vec<[u8; 32]>>();

        println!(
            "Block heights {:?}",
            blocks
                .iter()
                .map(|block| block.height)
                .collect::<Vec<u64>>()
        );

        let final_block_chainwork = blocks
            .iter()
            .fold(intial_block_chainwork, |chainwork_acc, block| {
                block.compute_chainwork(chainwork_acc)
            });

        assert_blockchain(
            commited_block_hashes,
            initial_block,
            intial_block_chainwork,
            retarget_block.compute_block_hash(),
            retarget_block.height,
            final_block_chainwork,
            blocks,
            *retarget_block,
        );
    }
}
