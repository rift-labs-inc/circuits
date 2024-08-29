use bitcoin::opcodes::all::{OP_RETURN};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::script::Builder;
use bitcoin::{
    transaction, Address, Amount, CompressedPublicKey, Network, OutPoint, PrivateKey, Script, ScriptBuf, Sequence, TxOut, Txid
};
use bitcoin::{
    Transaction, TxIn, Witness, EcdsaSighashType, PublicKey,
    hashes::{Hash, HashEngine},
    secp256k1::{self, Secp256k1, SecretKey},
    consensus::Encodable
};
use bitcoin::sighash::SighashCache;

use crypto_bigint::{U256, NonZero};
use rift_lib::lp::LiquidityReservation;
use std::str::FromStr;

use crate::to_little_endian;

// Assuming you have a crate named `rift_lib` with these types


pub struct P2WPKHBitcoinWallet {
    secret_key: SecretKey,
    public_key: String,
    unlock_script: [u8; 25],
    address: Address,
}

impl P2WPKHBitcoinWallet {
    pub fn new(secret_key: SecretKey, public_key: String, unlock_script: [u8; 25], address: Address) -> Self {
        Self { secret_key, public_key, unlock_script, address }
    }

    pub fn from_secret_key(secret_key: [u8; 32], network: Network) -> Self {
        let secret_key = SecretKey::from_slice(&secret_key).unwrap();
        let secp = Secp256k1::new();
        let pk = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&secp, &pk);
        let unlock_script = public_key.p2wpkh_script_code().unwrap().to_bytes();
        let address = Address::p2wpkh(&CompressedPublicKey::from_private_key(&secp, &pk).unwrap(), network);
        Self::new(secret_key, public_key.to_string(), unlock_script.try_into().unwrap(), address)
    }

    pub fn get_p2wpkh_script(&self) -> ScriptBuf {
        let public_key = PublicKey::from_str(&self.public_key).expect("Invalid public key");
        ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().expect("Invalid public key for P2WPKH"))
    }
}

fn wei_to_satoshi(wei_amount: U256, wei_sats_exchange_rate: u64) -> u64 {
    let rate = NonZero::new(U256::from_u64(wei_sats_exchange_rate))
        .expect("Exchange rate cannot be zero");
    
    let result = wei_amount
        .checked_div(&rate)
        .expect("Division overflow");
    
    if result > U256::from_u64(u64::MAX) {
        panic!("Result exceeds u64 capacity");
    }
    
    result.as_limbs()[0].into()
}

pub fn serialize_no_segwit(tx: &Transaction) -> Vec<u8> {
    let mut buffer = Vec::new();
    tx.version.consensus_encode(&mut buffer).expect("Encoding version failed");
    tx.input.consensus_encode(&mut buffer).expect("Encoding inputs failed");
    tx.output.consensus_encode(&mut buffer).expect("Encoding outputs failed");
    tx.lock_time.consensus_encode(&mut buffer).expect("Encoding lock_time failed");
    buffer
}

pub fn build_rift_payment_transaction(
    order_nonce: [u8; 32],
    liquidity_providers: &[LiquidityReservation],
    in_txid: [u8; 32],
    transaction: &Transaction,
    in_txvout: u32,
    wallet: &P2WPKHBitcoinWallet,
    fee_sats: u64,
) -> Transaction {
    // Fetch transaction data (you'll need to implement this function)

    let total_lp_sum_btc: u64 = liquidity_providers.iter()
        .map(|lp| wei_to_satoshi(lp.amount_reserved, lp.btc_exchange_rate))
        .sum();

    let vin_sats = transaction.output[in_txvout as usize].value.to_sat();

    println!("Total LP Sum BTC: {}", total_lp_sum_btc);
    println!("Vin sats: {}", vin_sats);
    

    let mut tx_outs = Vec::new();

    // Add liquidity provider outputs
    for lp in liquidity_providers {
        let amount = wei_to_satoshi(lp.amount_reserved, lp.btc_exchange_rate);
        let script = Script::from_bytes(&lp.script_pub_key);
        tx_outs.push(TxOut { value: Amount::from_sat(amount), script_pubkey: script.into() });
    }

    // Add OP_RETURN output
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&order_nonce)
        .into_script();    tx_outs.push(TxOut { value: Amount::ZERO, script_pubkey: op_return_script });

    // Add change output
    let change_amount = vin_sats - total_lp_sum_btc - fee_sats;
    tx_outs.push(TxOut {
        value: Amount::from_sat(change_amount),
        script_pubkey: wallet.get_p2wpkh_script(),
    });


    // Create input
    let outpoint = OutPoint::new(Txid::from_slice(to_little_endian::<32>(in_txid).as_slice()).unwrap(), in_txvout);
    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: Script::new().into(),
        sequence: Sequence(0xFFFFFFFD),
        witness: Witness::new(),
    };

    // Create unsigned transaction
    let mut tx = Transaction {
        version: transaction::Version(1),
        lock_time: LockTime::from_consensus(0),
        input: vec![tx_in],
        output: tx_outs,
    };


    sign_transaction(&mut tx, &wallet, vin_sats)
}

fn sign_transaction(tx: &mut Transaction, wallet: &P2WPKHBitcoinWallet, input_amount: u64) -> Transaction {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_str(&wallet.public_key).unwrap();

    // We're assuming there's only one input to sign
    let input_index = 0;

    // Create a SighashCache for efficient signature hash computation
    let mut sighash_cache = SighashCache::new(tx.clone());

    // Compute the sighash
    let sighash = sighash_cache.p2wpkh_signature_hash(
        input_index,
        &wallet.get_p2wpkh_script(),
        Amount::from_sat(input_amount),
        EcdsaSighashType::All,
    ).unwrap();

    // Sign the sighash
    let signature = secp.sign_ecdsa(&secp256k1::Message::from_digest_slice(&sighash[..]).unwrap(), &wallet.secret_key);

    // Serialize the signature and add the sighash type
    let mut signature_bytes = signature.serialize_der().to_vec();
    signature_bytes.push(EcdsaSighashType::All as u8);

    // Create the witness
    let witness = Witness::from_slice(&[
        signature_bytes.as_slice(),
        &public_key.to_bytes(),
    ]);

    // Set the witness for the input
    tx.input[input_index].witness = witness;

    tx.clone()
}

