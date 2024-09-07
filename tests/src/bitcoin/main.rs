#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin::Block;

    use rift_core::btc_light_client::{
        assert_blockchain, assert_pow, bits_to_target, verify_block, Block as RiftOptimizedBlock,
    };
    use rift_lib::{
        get_retarget_height_from_block_height, load_hex_bytes, to_little_endian,
        to_rift_optimized_block,
    };

    #[test]
    fn test_rift_block_converter() {
        let block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let canon_serialized_header = serialize(&block.header);
        let rift_block = to_rift_optimized_block(858564, &block).serialize();
        assert_eq!(
            canon_serialized_header, rift_block,
            "Rift block serialization failed"
        );
    }

    #[test]
    fn test_block_hash() {
        let block = deserialize::<Block>(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let rift_block = to_rift_optimized_block(858564, &block);

        let canon_block_hash = to_little_endian(*block.header.block_hash().as_byte_array());
        let rift_block_hash = rift_block.compute_block_hash();

        assert_eq!(
            canon_block_hash, rift_block_hash,
            "Block hash computation failed"
        );
    }

    #[test]
    fn test_bits_to_target() {
        let block: Block = deserialize(&load_hex_bytes("data/block_858564.hex")).unwrap();
        let rift_block = to_rift_optimized_block(858564, &block);
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
        let rift_block = to_rift_optimized_block(858564, &block);

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
        let mut rift_block = to_rift_optimized_block(858564, &block);
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

        let first_rift_block = to_rift_optimized_block(858564, &first_block);
        let second_rift_block = to_rift_optimized_block(858565, &second_block);

        let first_block_hash = first_rift_block.compute_block_hash();
        let second_block_hash = second_rift_block.compute_block_hash();

        let retarget_height = get_retarget_height_from_block_height(first_rift_block.height);
        let retarget_block = deserialize::<Block>(&load_hex_bytes(&format!(
            "data/block_{}.hex",
            retarget_height
        )))
        .unwrap();
        let rift_retarget_block = to_rift_optimized_block(retarget_height, &retarget_block);

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

        let mut first_rift_block = to_rift_optimized_block(858564, &first_block);
        first_rift_block.prev_blockhash = [0; 32];
        let second_rift_block = to_rift_optimized_block(858565, &second_block);

        let first_block_hash = first_rift_block.compute_block_hash();
        let second_block_hash = second_rift_block.compute_block_hash();

        let retarget_height = get_retarget_height_from_block_height(first_rift_block.height);
        let retarget_block = deserialize::<Block>(&load_hex_bytes(&format!(
            "data/block_{}.hex",
            retarget_height
        )))
        .unwrap();
        let rift_retarget_block = to_rift_optimized_block(retarget_height, &retarget_block);

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
        let blocks = (0..block_delta)
            .map(|i| {
                to_rift_optimized_block(
                    initial_block + i,
                    &deserialize::<Block>(&load_hex_bytes(&format!(
                        "data/block_{}.hex",
                        initial_block + i
                    )))
                    .unwrap(),
                )
            })
            .collect::<Vec<RiftOptimizedBlock>>();

        let retarget_block = to_rift_optimized_block(
            get_retarget_height_from_block_height(initial_block),
            &deserialize::<Block>(&load_hex_bytes(&format!(
                "data/block_{}.hex",
                get_retarget_height_from_block_height(initial_block)
            )))
            .unwrap(),
        );

        let commited_block_hashes = blocks
            .iter()
            .map(|block| block.compute_block_hash())
            .collect::<Vec<[u8; 32]>>();

        assert_blockchain(
            commited_block_hashes,
            initial_block,
            retarget_block.compute_block_hash(),
            get_retarget_height_from_block_height(initial_block),
            blocks,
            retarget_block,
        );
    }
}
