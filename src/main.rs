use bitcoin::consensus::encode::{
    deserialize_hex,
    FromHexError,
    serialize_hex,
};

use bitcoin::sighash::{
    Prevouts,
    SighashCache,
};

use bitcoin::taproot::{
    ControlBlock,
    LeafVersion,
    Signature,
    TapNodeHash,
    TaprootMerkleBranch,
};

use bitcoin::{
    Address,
    Amount,
    FeeRate,
    hashes::Hash,
    key::TapTweak,
    Network,
    opcodes::all::OP_CHECKSIG,
    OutPoint,
    ScriptBuf,
    Script,
    Sequence,
    TapSighashType,
    Transaction,
    transaction::Version,
    TxIn,
    TxOut,
    Witness,
};

use bitcoin::secp256k1::{
    Message,
    Secp256k1,
    SecretKey,
    Signing,
    Verification,
    XOnlyPublicKey,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};

struct AddressInfo {
    secret_key: SecretKey,
    merkle_path: Vec<TapNodeHash>,
}

impl AddressInfo {
    fn new<R: std::io::Read>(secret_key: SecretKey, read: &mut R) -> Result<Self, std::io::Error> {
        Ok(
            Self {
                secret_key,
                merkle_path: Self::read_into_merkle_path(read)?,
            }
        )
    }

    fn read_into_merkle_path<R: std::io::Read>(read: &mut R) -> Result<Vec<TapNodeHash>, std::io::Error> {
        let mut buf = [0u8; 32];
        let mut path = Vec::new();

        loop {
            let read_count = read.read(buf.as_mut())?;

            let pad = (32 - read_count) as u8;
            if read_count < 32 {
                for i in read_count..32 {
                    buf[i] = pad;
                }
            }

            path.push(TapNodeHash::from_byte_array(buf));

            if read_count < 32 {
                break;
            }
        }

        Ok(path)
    }

    // Kinda waffled on whether to leave these static, who cares for this shitty PoC
    fn calculate_merkle_root(script: &Script, merkle_path: &[TapNodeHash]) -> TapNodeHash {
        let mut node_hash = TapNodeHash::from_script(script.as_ref(), LeafVersion::TapScript);

        for path_node in merkle_path {
            node_hash = TapNodeHash::from_node_hashes(*path_node, node_hash);
        }

        node_hash
    }

    // Kinda waffled on whether to leave these static, who cares for this shitty PoC
    fn build_control_block<C: Verification>(secp: &Secp256k1<C>, internal_key: &XOnlyPublicKey, script: &Script, merkle_path: &[TapNodeHash]) -> ControlBlock {
        use bitcoin::key::TapTweak;

        let merkle_root = Self::calculate_merkle_root(script, merkle_path);

        let output_key = internal_key.tap_tweak(secp, Some(merkle_root));

        ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: output_key.1,
            internal_key: *internal_key,
            merkle_branch: TaprootMerkleBranch::try_from(merkle_path.to_vec()).unwrap(),
        }
    }

    fn control_block<C: Verification + Signing>(&self, secp: &Secp256k1<C>) -> ControlBlock {
        let script = self.script(secp);

        Self::build_control_block(secp, &self.internal_key(secp), &script, &self.merkle_path)
    }

    fn merkle_root<C: Signing>(&self, secp: &Secp256k1<C>) -> TapNodeHash {
        Self::calculate_merkle_root(&self.script(&secp), &self.merkle_path)
    }

    fn internal_key<C: Signing>(&self, secp: &Secp256k1<C>) -> XOnlyPublicKey {
        self.secret_key.x_only_public_key(secp).0
    }

    fn script<C: Signing>(&self, secp: &Secp256k1<C>) -> ScriptBuf {
        let pubkey = self.secret_key.x_only_public_key(secp).0;

        ScriptBuf::builder()
            .push_x_only_key(&pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn address<C: Signing + Verification>(&self, secp: &Secp256k1<C>, network: Network) -> Address {
        let pubkey = self.secret_key.x_only_public_key(secp).0;

        let merkle_root = Self::calculate_merkle_root(&self.script(secp), &self.merkle_path);

        Address::p2tr(secp, pubkey, Some(merkle_root), network)
    }
}

#[derive(Clone, Args)]
struct CreateAddress {
    path: std::path::PathBuf,

    secret_key: Option<SecretKey>,
}

// I guess clap value_parser didn't like that deserialize_hex is generic?
fn parse_tx(s: &str) -> Result<Transaction, FromHexError> {
    deserialize_hex(s)
}

fn parse_signet_address(s: &str) -> Result<Address, bitcoin::address::ParseError> {
    use std::str::FromStr;

    Address::from_str(s)
        .and_then(|a| a.require_network(Network::Signet))
}

#[derive(Clone, Args)]
struct Spend {
    path: std::path::PathBuf,

    secret_key: SecretKey,

    #[arg(value_parser = parse_tx)]
    transaction: Transaction,

    outpoint_index: usize,

    #[arg(value_parser = parse_signet_address)]
    address: Address,
}

#[derive(Clone, Args)]
struct Oops {
    path: std::path::PathBuf,

    secret_key: SecretKey,

    #[arg(value_parser = parse_tx)]
    transaction: Transaction,

    outpoint_index: usize,

    #[arg(value_parser = parse_signet_address)]
    address: Address,
}

#[derive(Clone, Subcommand)]
enum Command {
    CreateAddress(CreateAddress),
    Spend(Spend),
    Oops(Oops),
}

#[derive(Parser)]
#[command(name = "stupid-tap-trick")]
struct CommandLine {
    #[command(subcommand)]
    command: Command,
}

fn main() {
    let secp = Secp256k1::new();

    let command_line = CommandLine::parse();

    match command_line.command {
        Command::CreateAddress(ref args) => {
            let secret = if let Some(secret_key) = args.secret_key {
                secret_key
            } else {
                SecretKey::new(&mut rand::thread_rng())
            };

            let mut reader = std::fs::File::open(&args.path).unwrap();

            let address_info = AddressInfo::new(secret.clone(), &mut reader).unwrap();

            eprintln!("secret_key: {}", secret.display_secret());

            let address = address_info.address(&secp, Network::Signet);
            eprintln!("address: {address}");
        }
        Command::Spend(ref args) => {
            let mut reader = std::fs::File::open(&args.path).unwrap();

            let address_info = AddressInfo::new(args.secret_key, &mut reader).unwrap();

            let control_block = address_info.control_block(&secp);

            let mut witness = Witness::new();
            witness.push(vec![0u8; 64]);
            witness.push(address_info.script(&secp));
            witness.push(control_block.serialize());

            let mut spend_tx = Transaction {
                version: Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: args.transaction.compute_txid(),
                            vout: args.outpoint_index as u32,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness,
                    }
                ],
                output: vec![
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: args.address.script_pubkey(),
                    }
                ],
            };
            let prevout = &args.transaction.output[args.outpoint_index];

            let fee_rate = FeeRate::from_sat_per_vb(FeeRate::BROADCAST_MIN.to_sat_per_vb_ceil() + 1).unwrap();

            let fee = fee_rate.fee_wu(spend_tx.weight()).unwrap();

            spend_tx.output[0].value = prevout.value - fee;

            spend_tx.input[0].witness = Witness::new();

            let mut sighash_cache = SighashCache::new(&spend_tx);

            let leaf_hash = bitcoin::TapLeafHash::from_script(&address_info.script(&secp), LeafVersion::TapScript);

            let prevouts_vec = vec![prevout.clone()];
            let prevouts = Prevouts::All(&prevouts_vec);

            let sighash = sighash_cache.taproot_signature_hash(0, &prevouts, None, Some((leaf_hash, 0xFFFFFFFF)), TapSighashType::All).unwrap();

            let message = Message::from(sighash);
            let signature = secp.sign_schnorr_with_rng(&message, &args.secret_key.keypair(&secp), &mut rand::thread_rng());

            spend_tx.input[0].witness = {
                let mut witness = Witness::new();
                let signature = Signature {
                    signature,
                    sighash_type: TapSighashType::All,
                };

                witness.push(signature.serialize());
                witness.push(address_info.script(&secp));
                witness.push(control_block.serialize());
                witness
            };

            println!("{}", serialize_hex(&spend_tx));
        }
        Command::Oops(ref args) => {
            eprintln!("I never actually tested this");
            let mut reader = std::fs::File::open(&args.path).unwrap();

            let address_info = AddressInfo::new(args.secret_key, &mut reader).unwrap();

            let mut witness = Witness::new();
            witness.push(vec![0u8; 64]);

            let mut spend_tx = Transaction {
                version: Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: args.transaction.compute_txid(),
                            vout: args.outpoint_index as u32,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness,
                    }
                ],
                output: vec![
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: args.address.script_pubkey(),
                    }
                ],
            };
            let prevout = &args.transaction.output[args.outpoint_index];

            let fee_rate = FeeRate::from_sat_per_vb(FeeRate::BROADCAST_MIN.to_sat_per_vb_ceil() + 1).unwrap();

            let fee = fee_rate.fee_wu(spend_tx.weight()).unwrap();

            spend_tx.output[0].value = prevout.value - fee;

            let mut sighash_cache = SighashCache::new(&spend_tx);

            let prevouts_vec = vec![prevout.clone()];
            let prevouts = Prevouts::All(&prevouts_vec);

            let keypair = args.secret_key.keypair(&secp);
            let keypair = keypair.tap_tweak(&secp, Some(address_info.merkle_root(&secp))).to_inner();

            let sighash = sighash_cache.taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::All).unwrap();

            let message = Message::from(sighash);
            let signature = secp.sign_schnorr_with_rng(&message, &keypair, &mut rand::thread_rng());

            spend_tx.input[0].witness = {
                let mut witness = Witness::new();
                let signature = Signature {
                    signature,
                    sighash_type: TapSighashType::All,
                };

                witness.push(signature.serialize());
                witness
            };

            println!("{}", serialize_hex(&spend_tx));
        }
    }
}
