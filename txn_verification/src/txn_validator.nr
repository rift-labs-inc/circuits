use dep::std;
use dep::rift_lib::constants;
use dep::rift_lib::byte_lib;
global VERIFICATION_KEY: [Field] = [];
global VERIFICATION_KEY_HASH: Field = 0x0;

pub fn assert_txn_contains_lp_utxos() {
	std::verify_proof(
	    VERIFICATION_KEY.as_slice(),
        recursive_txn_decoder_proof.as_slice(),
        encoded_txn_data.as_slice(),
		VERIFICATION_KEY_HASH	
	);
}
