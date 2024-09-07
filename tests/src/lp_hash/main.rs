#[cfg(test)]
mod tests {
    use rift_core::lp::{assert_lp_hash, build_hashable_chunk};

    use hex_literal::hex;

    use sha2::{Digest, Sha256};

    #[test]
    fn test_chunk_builder() {
        let lp_data: [[u8; 32]; 3] = [
            hex!("000000000000000000000000000000000000000000000000000009184e72a000"),
            hex!("0000000000000000000000000000000000000000000000000000000000000045"),
            hex!("0014841b80d2cc75f5345c482af96294d04fdd66b2b700000000000000000000"),
        ];
        let intermediate_vault_hash = [0u8; 32];
        let expected_vault_hash: [u8; 32] =
            hex!("050dd95440fe766ea732543cdf44af1f715b59c7d53c42928f52bb2e91a7af37");

        let hashable_chunk = build_hashable_chunk(lp_data, intermediate_vault_hash);
        let vault_hash: [u8; 32] = Sha256::digest(hashable_chunk).into();
        assert_eq!(vault_hash, expected_vault_hash, "Invalid vault hash");
    }

    #[test]
    fn test_assert_lp_hash() {
        let lp_data: [[u8; 32]; 3] = [
            hex!("000000000000000000000000000000000000000000000000000009184e72a000"),
            hex!("0000000000000000000000000000000000000000000000000000000000000045"),
            hex!("0014841b80d2cc75f5345c482af96294d04fdd66b2b700000000000000000000"),
        ];
        let expected_vault_hash: [u8; 32] =
            hex!("050dd95440fe766ea732543cdf44af1f715b59c7d53c42928f52bb2e91a7af37");
        assert_lp_hash(expected_vault_hash, &[lp_data].to_vec(), 1);
    }
}
