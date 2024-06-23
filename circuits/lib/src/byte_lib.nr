struct CompConstant<N> {
}

trait New<N> {
	fn new() -> CompConstant<N>;
}

impl<N> New<N> for CompConstant<N> {
	fn new() -> CompConstant<N> {
		CompConstant{}
	}
}

// `_theoretical_max` needs to be const-generic-esque b/c for loops must be known at compile time
fn grab_bytes_conditional<T, N, C, Env>(
    data: [T; N],
    offset: u64,
    little_endian: bool,
    _theoretical_max: CompConstant<C>,
    runtime_max: fn[Env](u64) -> bool
) -> [T; C]
		where T: Default {
    let mut out: [T; C] = [T::default(); C];
    for i in 0..C {
        if runtime_max(i) {
            if little_endian {
                out[i] = data[(offset + C)-1-i];
            } else {
                out[i] = data[offset + i];
            }
        }
    }
    out
}

pub fn grab_bytes_be<T, N, C>(max: CompConstant<C>, data: [T; N], offset: u64) -> [T; C] where T: Default {
    grab_bytes_conditional(data, offset, false, max, |_| true)
}

pub fn grab_bytes_le<T, N, C>(max: CompConstant<C>, data: [T; N], offset: u64) -> [T; C] where T: Default {
    grab_bytes_conditional(data, offset, true, max, |_| true)
}

pub fn grab_bytes_be_conditional<T, N, C, Env>(
    max: CompConstant<C>,
    data: [T; N],
    offset: u64,
    runtime_max: fn[Env](u64) -> bool
) -> [T; C] where T: Default {
    grab_bytes_conditional(data, offset, false, max, runtime_max)
}

pub fn grab_bytes_le_conditional<T, N, C, Env>(
    max: CompConstant<C>,
    data: [T; N],
    offset: u64,
    runtime_max: fn[Env](u64) -> bool
) -> [T; C] where T: Default {
    grab_bytes_conditional(data, offset, true, max, runtime_max)
}

pub fn u8_bytes_to_field<N>(array: [u8; N]) -> Field {
    assert(N <= 31);
    let mut result: Field = 0;
    for i in 0..N {
        result = (result * 256) + (array[i] as Field);
    }
    result
}

pub fn extract_bytes_from_u64<N>(byte_count: CompConstant<N>, number: u64) -> [u8; N] {
    assert(N <= 8);

    let mut bytes: [u8; N] = [0; N];
    for i in 0..N {
        // Calculate the shift amount for big-endian byte order
        let shift_amount = 8 * (8 - N + i);
        // Shift the number right by calculated bits and mask with 0xFF to get the ith byte in big-endian order
        let byte = ((number >> shift_amount as u8) & 0xFF) as u8;
        bytes[i] = byte;
    }

    bytes
}

pub fn decode_field_encoded_hash(encoded_expected_hash: [Field; 2]) -> [u8; 32] {
    let mut proposed_txn_hash: [u8; 32] = [0; 32];
    let leg1 = encoded_expected_hash[0].to_be_bytes(31);
    let leg2 = encoded_expected_hash[1].to_be_bytes(1);
    for i in 0..31 {
        proposed_txn_hash[i] = leg1[i];
    }
    proposed_txn_hash[31] = leg2[0];
    proposed_txn_hash
}
