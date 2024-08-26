#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::private::{FixedBytes, U256};
use alloy_sol_types::SolType;
use rift_lib::{
    validate_rift_transaction, CircuitInput, SolidityPublicValues,
};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let circuit_input = sp1_zkvm::io::read::<CircuitInput>();

    let circuit_public_input = validate_rift_transaction(circuit_input);

    // Encode the public values of the program.
    let bytes = SolidityPublicValues::abi_encode(&SolidityPublicValues {
        natural_txid: FixedBytes::from(circuit_public_input.natural_txid),
        merkle_root: FixedBytes::from(circuit_public_input.merkle_root),
        lp_reservation_hash: FixedBytes::from(circuit_public_input.lp_reservation_hash),
        order_nonce: FixedBytes::from(circuit_public_input.order_nonce),
        expected_payout: U256::from_be_slice(&circuit_public_input.expected_payout),
        lp_count: circuit_public_input.lp_count,
        retarget_block_hash: FixedBytes::from(circuit_public_input.retarget_block_hash),
        safe_block_height: circuit_public_input.safe_block_height,
        safe_block_height_delta: circuit_public_input.safe_block_height_delta,
        confirmation_block_height_delta: circuit_public_input.confirmation_block_height_delta,
        retarget_block_height: circuit_public_input.retarget_block_height,
        block_hashes: circuit_public_input
            .block_hashes
            .iter()
            .map(|x| FixedBytes::from(*x))
            .collect::<Vec<_>>(),
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
