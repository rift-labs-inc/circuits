#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin::Block;

    use hex_literal::hex;
    use rift_lib::constants::MAX_LIQUIDITY_PROVIDERS;
    use rift_lib::payment::compint_to_u64;
    use utils::{generate_merkle_proof_and_root, load_hex_bytes, to_little_endian};

    use sha2::{Digest, Sha256};

    #[test]
    fn test_compint() {
        assert!(0x01 == compint_to_u64([0x01 as u8]));

        assert!(0xFC == compint_to_u64([0xFC as u8]));

        assert!(0xF1 == compint_to_u64([0xF1 as u8]));

        assert!(0xCDAB == compint_to_u64([0xFD, 0xAB, 0xCD]));

        assert!(0x01EFCDAB == compint_to_u64([0xFE, 0xAB, 0xCD, 0xEF, 0x01, 0x00]));

        assert!(
            0x01EFCDAB01EFCDAB
                == compint_to_u64([0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0xAB, 0xCD, 0xEF, 0x01]),
        );

        assert!(99999 == compint_to_u64([0xFE, 0x9f, 0x86, 0x01, 0x00]));
    }
}
