//! Default minimum balance constants for different blockchain networks
//! These values are used to ensure relayers maintain sufficient funds for operation.
pub const DEFAULT_EVM_MIN_BALANCE: u128 = 1; // 0.001 ETH in wei
pub const DEFAULT_STELLAR_MIN_BALANCE: u64 = 1_000_000; // 1 XLM
pub const DEFAULT_SOLANA_MIN_BALANCE: u64 = 10_000_000; // 0.01 Lamport
pub const MAX_SOLANA_TX_DATA_SIZE: u16 = 1232;
pub const EVM_SMALLEST_UNIT_NAME: &str = "wei";
pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
#[allow(dead_code)]
pub const STELLAR_SMALLEST_UNIT_NAME: &str = "stroop";
pub const SOLANA_SMALLEST_UNIT_NAME: &str = "lamport";

pub const DEFAULT_RPC_WEIGHT: u8 = 100;
