use sha2::{Digest, Sha256};
use hex_literal::hex;

pub fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn get_natural_txid(tx: &[u8]) -> [u8; 32] {
    let intermediate_hash= sha256_hash(tx);
    sha256_hash(&intermediate_hash)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_smoke_test() {
        let bytes = b"hello world";
        let hash = sha256_hash(bytes);
        assert!(hash == hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    }

    #[test]
    fn test_hash_real_tx() {
        let tx = hex!("0100000001bc54f8d308bf85970edb9eb4f8d0bf2983f0e1fa757d726ad07a936d1a08de200e0000008b483045022100ce7348ae09b85a34f9bc2f40a7f7360b73d9cab631177c4b64a6762b846db1d7022044a0f6d7ba1d8a3ece8dfa944c1641c592fe03bb9c85a8e1b2587662a4c0de0b0141048dc2db8d85f77078d6a508b2e7dad48f5ad9215a5514b9e569d48febbdba1f74edbd6888cbffad42615d5fc07617369eff80f910d476114f7eae78bd85366359ffffffff0200a86100000000001976a91459400c3493b3425576b2e16ad769998a5b4dbb5488ac98ea3600000000001976a91472535c7212117b1d049906548d06fa6a95c250aa88ac00000000");

        let hash = get_natural_txid(&tx);
        println!("hash: {:?}", hash);
        assert!(hash == hex!("eb2b4edd084fa05ccc85db28c4d1d1d8fae8d9e5d18a8bfd528a7a74ae27a895"));
    }

}
