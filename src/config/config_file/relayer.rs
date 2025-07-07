//! Configuration file definitions for relayer services.
//!
//! Provides configuration structures and validation for relayer settings:
//! - Network configuration (EVM, Solana, Stellar)
//! - Gas/fee policies
//! - Transaction validation rules
//! - Network endpoints
use super::{ConfigFileError, ConfigFileNetworkType, NetworksFileConfig};
use crate::models::RpcConfig;
use apalis_cron::Schedule;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ConfigFileRelayerNetworkPolicy {
    Evm(ConfigFileRelayerEvmPolicy),
    Solana(ConfigFileRelayerSolanaPolicy),
    Stellar(ConfigFileRelayerStellarPolicy),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigFileRelayerEvmPolicy {
    pub gas_price_cap: Option<u128>,
    pub whitelist_receivers: Option<Vec<String>>,
    pub eip1559_pricing: Option<bool>,
    pub private_transactions: Option<bool>,
    pub min_balance: Option<u128>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllowedTokenSwapConfig {
    /// Conversion slippage percentage for token. Optional.
    pub slippage_percentage: Option<f32>,
    /// Minimum amount of tokens to swap. Optional.
    pub min_amount: Option<u64>,
    /// Maximum amount of tokens to swap. Optional.
    pub max_amount: Option<u64>,
    /// Minimum amount of tokens to retain after swap. Optional.
    pub retain_min_amount: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllowedToken {
    pub mint: String,
    /// Maximum supported token fee (in lamports) for a transaction. Optional.
    pub max_allowed_fee: Option<u64>,
    /// Swap configuration for the token. Optional.
    pub swap_config: Option<AllowedTokenSwapConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigFileRelayerSolanaFeePaymentStrategy {
    User,
    Relayer,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFileRelayerSolanaSwapStrategy {
    JupiterSwap,
    JupiterUltra,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JupiterSwapOptions {
    /// Maximum priority fee (in lamports) for a transaction. Optional.
    pub priority_fee_max_lamports: Option<u64>,
    /// Priority. Optional.
    pub priority_level: Option<String>,

    pub dynamic_compute_unit_limit: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigFileRelayerSolanaSwapPolicy {
    /// DEX strategy to use for token swaps.
    pub strategy: Option<ConfigFileRelayerSolanaSwapStrategy>,

    /// Cron schedule for executing token swap logic to keep relayer funded. Optional.
    pub cron_schedule: Option<String>,

    /// Min sol balance to execute token swap logic to keep relayer funded. Optional.
    pub min_balance_threshold: Option<u64>,

    /// Swap options for JupiterSwap strategy. Optional.
    pub jupiter_swap_options: Option<JupiterSwapOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigFileRelayerSolanaPolicy {
    /// Determines if the relayer pays the transaction fee or the user. Optional.
    pub fee_payment_strategy: Option<ConfigFileRelayerSolanaFeePaymentStrategy>,

    /// Fee margin percentage for the relayer. Optional.
    pub fee_margin_percentage: Option<f32>,

    /// Minimum balance required for the relayer (in lamports). Optional.
    pub min_balance: Option<u64>,

    /// List of allowed tokens by their identifiers. Only these tokens are supported if provided.
    pub allowed_tokens: Option<Vec<AllowedToken>>,

    /// List of allowed programs by their identifiers. Only these programs are supported if
    /// provided.
    pub allowed_programs: Option<Vec<String>>,

    /// List of allowed accounts by their public keys. The relayer will only operate with these
    /// accounts if provided.
    pub allowed_accounts: Option<Vec<String>>,

    /// List of disallowed accounts by their public keys. These accounts will be explicitly
    /// blocked.
    pub disallowed_accounts: Option<Vec<String>>,

    /// Maximum transaction size. Optional.
    pub max_tx_data_size: Option<u16>,

    /// Maximum supported signatures. Optional.
    pub max_signatures: Option<u8>,

    /// Maximum allowed fee (in lamports) for a transaction. Optional.
    pub max_allowed_fee_lamports: Option<u64>,

    /// Swap dex config to use for token swaps. Optional.
    pub swap_config: Option<ConfigFileRelayerSolanaSwapPolicy>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigFileRelayerStellarPolicy {
    pub max_fee: Option<u32>,
    pub timeout_seconds: Option<u64>,
    pub min_balance: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct RelayerFileConfig {
    pub id: String,
    pub name: String,
    pub network: String,
    pub paused: bool,
    #[serde(flatten)]
    pub network_type: ConfigFileNetworkType,
    #[serde(default)]
    pub policies: Option<ConfigFileRelayerNetworkPolicy>,
    pub signer_id: String,
    #[serde(default)]
    pub notification_id: Option<String>,
    #[serde(default)]
    pub custom_rpc_urls: Option<Vec<RpcConfig>>,
}
use serde::{de, Deserializer};
use serde_json::Value;

impl<'de> Deserialize<'de> for RelayerFileConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as a generic JSON object
        let mut value: Value = Value::deserialize(deserializer)?;

        // Extract and validate required fields
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("id"))?
            .to_string();

        let name = value
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("name"))?
            .to_string();

        let network = value
            .get("network")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("network"))?
            .to_string();

        let paused = value
            .get("paused")
            .and_then(Value::as_bool)
            .ok_or_else(|| de::Error::missing_field("paused"))?;

        // Deserialize `network_type` using `ConfigFileNetworkType`
        let network_type: ConfigFileNetworkType = serde_json::from_value(
            value
                .get("network_type")
                .cloned()
                .ok_or_else(|| de::Error::missing_field("network_type"))?,
        )
        .map_err(de::Error::custom)?;

        let signer_id = value
            .get("signer_id")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("signer_id"))?
            .to_string();

        let notification_id = value
            .get("notification_id")
            .and_then(Value::as_str)
            .map(|s| s.to_string());

        // Handle `policies`, using `network_type` to determine how to deserialize
        let policies = if let Some(policy_value) = value.get_mut("policies") {
            match network_type {
                ConfigFileNetworkType::Evm => {
                    serde_json::from_value::<ConfigFileRelayerEvmPolicy>(policy_value.clone())
                        .map(ConfigFileRelayerNetworkPolicy::Evm)
                        .map(Some)
                        .map_err(de::Error::custom)
                }
                ConfigFileNetworkType::Solana => {
                    serde_json::from_value::<ConfigFileRelayerSolanaPolicy>(policy_value.clone())
                        .map(ConfigFileRelayerNetworkPolicy::Solana)
                        .map(Some)
                        .map_err(de::Error::custom)
                }
                ConfigFileNetworkType::Stellar => {
                    serde_json::from_value::<ConfigFileRelayerStellarPolicy>(policy_value.clone())
                        .map(ConfigFileRelayerNetworkPolicy::Stellar)
                        .map(Some)
                        .map_err(de::Error::custom)
                }
            }
        } else {
            Ok(None) // `policies` is optional
        }?;

        let custom_rpc_urls = value
            .get("custom_rpc_urls")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        // Handle both string format (legacy) and object format (new)
                        if let Some(url_str) = v.as_str() {
                            // Convert string to RpcConfig with default weight
                            Some(RpcConfig::new(url_str.to_string()))
                        } else {
                            // Try to parse as a RpcConfig object
                            serde_json::from_value::<RpcConfig>(v.clone()).ok()
                        }
                    })
                    .collect()
            });

        Ok(RelayerFileConfig {
            id,
            name,
            network,
            paused,
            network_type,
            policies,
            signer_id,
            notification_id,
            custom_rpc_urls,
        })
    }
}

impl RelayerFileConfig {
    const MAX_ID_LENGTH: usize = 36;

    fn validate_solana_pub_keys(&self, keys: &Option<Vec<String>>) -> Result<(), ConfigFileError> {
        if let Some(keys) = keys {
            let solana_pub_key_regex =
                Regex::new(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$").map_err(|e| {
                    ConfigFileError::InternalError(format!("Regex compilation error: {}", e))
                })?;
            for key in keys {
                if !solana_pub_key_regex.is_match(key) {
                    return Err(ConfigFileError::InvalidPolicy(
                        "Value must contain only letters, numbers, dashes and underscores".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_solana_fee_margin_percentage(
        &self,
        fee_margin_percentage: Option<f32>,
    ) -> Result<(), ConfigFileError> {
        if let Some(value) = fee_margin_percentage {
            if value < 0f32 {
                return Err(ConfigFileError::InvalidPolicy(
                    "Negative values are not accepted".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_solana_swap_config(
        &self,
        policy: &ConfigFileRelayerSolanaPolicy,
        network: &str,
    ) -> Result<(), ConfigFileError> {
        let swap_config = match &policy.swap_config {
            Some(config) => config,
            None => return Ok(()),
        };

        if let Some(fee_payment_strategy) = &policy.fee_payment_strategy {
            match fee_payment_strategy {
                ConfigFileRelayerSolanaFeePaymentStrategy::User => {}
                ConfigFileRelayerSolanaFeePaymentStrategy::Relayer => {
                    return Err(ConfigFileError::InvalidPolicy(
                        "Swap config only supported for user fee payment strategy".into(),
                    ));
                }
            }
        }

        if let Some(strategy) = &swap_config.strategy {
            match strategy {
                ConfigFileRelayerSolanaSwapStrategy::JupiterSwap => {
                    if network != "mainnet-beta" {
                        return Err(ConfigFileError::InvalidPolicy(
                            "JupiterSwap strategy is only supported on mainnet-beta".into(),
                        ));
                    }
                }
                ConfigFileRelayerSolanaSwapStrategy::JupiterUltra => {
                    if network != "mainnet-beta" {
                        return Err(ConfigFileError::InvalidPolicy(
                            "JupiterUltra strategy is only supported on mainnet-beta".into(),
                        ));
                    }
                }
            }
        }

        if let Some(cron_schedule) = &swap_config.cron_schedule {
            if cron_schedule.is_empty() {
                return Err(ConfigFileError::InvalidPolicy(
                    "Empty cron schedule is not accepted".into(),
                ));
            }
        }

        if let Some(schedule) = &swap_config.cron_schedule {
            Schedule::from_str(schedule).map_err(|_| {
                ConfigFileError::InvalidPolicy("Invalid cron schedule format".into())
            })?;
        }

        if let Some(strategy) = &swap_config.jupiter_swap_options {
            // strategy must be jupiter_swap
            if swap_config.strategy != Some(ConfigFileRelayerSolanaSwapStrategy::JupiterSwap) {
                return Err(ConfigFileError::InvalidPolicy(
                    "JupiterSwap options are only valid for JupiterSwap strategy".into(),
                ));
            }
            if let Some(max_lamports) = strategy.priority_fee_max_lamports {
                if max_lamports == 0 {
                    return Err(ConfigFileError::InvalidPolicy(
                        "Max lamports must be greater than 0".into(),
                    ));
                }
            }
            if let Some(priority_level) = &strategy.priority_level {
                if priority_level.is_empty() {
                    return Err(ConfigFileError::InvalidPolicy(
                        "Priority level cannot be empty".into(),
                    ));
                }
                let valid_levels = ["medium", "high", "veryHigh"];
                if !valid_levels.contains(&priority_level.as_str()) {
                    return Err(ConfigFileError::InvalidPolicy(
                        "Priority level must be one of: medium, high, veryHigh".into(),
                    ));
                }
            }

            if strategy.priority_level.is_some() && strategy.priority_fee_max_lamports.is_none() {
                return Err(ConfigFileError::InvalidPolicy(
                    "Priority Fee Max lamports must be set if priority level is set".into(),
                ));
            }
            if strategy.priority_fee_max_lamports.is_some() && strategy.priority_level.is_none() {
                return Err(ConfigFileError::InvalidPolicy(
                    "Priority level must be set if priority fee max lamports is set".into(),
                ));
            }
        }

        Ok(())
    }

    fn validate_policies(&self) -> Result<(), ConfigFileError> {
        match self.network_type {
            ConfigFileNetworkType::Solana => {
                if let Some(ConfigFileRelayerNetworkPolicy::Solana(policy)) = &self.policies {
                    self.validate_solana_pub_keys(&policy.allowed_accounts)?;
                    self.validate_solana_pub_keys(&policy.disallowed_accounts)?;
                    let allowed_token_keys = policy.allowed_tokens.as_ref().map(|tokens| {
                        tokens
                            .iter()
                            .map(|token| token.mint.clone())
                            .collect::<Vec<String>>()
                    });
                    self.validate_solana_pub_keys(&allowed_token_keys)?;
                    self.validate_solana_pub_keys(&policy.allowed_programs)?;
                    self.validate_solana_fee_margin_percentage(policy.fee_margin_percentage)?;
                    self.validate_solana_swap_config(policy, &self.network)?;
                    // check if both allowed_accounts and disallowed_accounts are present
                    if policy.allowed_accounts.is_some() && policy.disallowed_accounts.is_some() {
                        return Err(ConfigFileError::InvalidPolicy(
                            "allowed_accounts and disallowed_accounts cannot be both present"
                                .into(),
                        ));
                    }
                }
            }
            ConfigFileNetworkType::Evm => {}
            ConfigFileNetworkType::Stellar => {}
        }
        Ok(())
    }

    fn validate_custom_rpc_urls(&self) -> Result<(), ConfigFileError> {
        if let Some(configs) = &self.custom_rpc_urls {
            for config in configs {
                reqwest::Url::parse(&config.url).map_err(|_| {
                    ConfigFileError::InvalidFormat(format!("Invalid RPC URL: {}", config.url))
                })?;

                if config.weight > 100 {
                    return Err(ConfigFileError::InvalidFormat(
                        "RPC URL weight must be in range 0-100".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    // TODO add validation that multiple relayers on same network cannot use same signer
    pub fn validate(&self) -> Result<(), ConfigFileError> {
        if self.id.is_empty() {
            return Err(ConfigFileError::MissingField("relayer id".into()));
        }
        let id_regex = Regex::new(r"^[a-zA-Z0-9-_]+$").map_err(|e| {
            ConfigFileError::InternalError(format!("Regex compilation error: {}", e))
        })?;
        if !id_regex.is_match(&self.id) {
            return Err(ConfigFileError::InvalidIdFormat(
                "ID must contain only letters, numbers, dashes and underscores".into(),
            ));
        }

        if self.id.len() > Self::MAX_ID_LENGTH {
            return Err(ConfigFileError::InvalidIdLength(format!(
                "ID length must not exceed {} characters",
                Self::MAX_ID_LENGTH
            )));
        }
        if self.name.is_empty() {
            return Err(ConfigFileError::MissingField("relayer name".into()));
        }
        if self.network.is_empty() {
            return Err(ConfigFileError::MissingField("network".into()));
        }

        self.validate_policies()?;
        self.validate_custom_rpc_urls()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RelayersFileConfig {
    pub relayers: Vec<RelayerFileConfig>,
}

impl RelayersFileConfig {
    pub fn new(relayers: Vec<RelayerFileConfig>) -> Self {
        Self { relayers }
    }

    pub fn validate(&self, networks: &NetworksFileConfig) -> Result<(), ConfigFileError> {
        if self.relayers.is_empty() {
            return Err(ConfigFileError::MissingField("relayers".into()));
        }

        let mut ids = HashSet::new();
        for relayer in &self.relayers {
            if relayer.network.is_empty() {
                return Err(ConfigFileError::InvalidFormat(
                    "relayer.network cannot be empty".into(),
                ));
            }

            if networks
                .get_network(relayer.network_type, &relayer.network)
                .is_none()
            {
                return Err(ConfigFileError::InvalidReference(format!(
                    "Relayer '{}' references non-existent network '{}' for type '{:?}'",
                    relayer.id, relayer.network, relayer.network_type
                )));
            }
            relayer.validate()?;
            if !ids.insert(relayer.id.clone()) {
                return Err(ConfigFileError::DuplicateId(relayer.id.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{EvmNetworkConfig, NetworkConfigCommon, NetworkFileConfig};
    use crate::constants::DEFAULT_RPC_WEIGHT;

    use super::*;
    use serde_json::json;

    #[test]
    fn test_solana_policy_duplicate_entries() {
        let config = json!({
            "id": "solana-relayer",
            "name": "Solana Mainnet Relayer",
            "network": "mainnet",
            "network_type": "solana",
            "signer_id": "solana-signer",
            "paused": false,
            "policies": {
                "allowed_accounts": ["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"],
                "disallowed_accounts": ["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"],
            }
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();

        let err = relayer.validate_policies().unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid policy: allowed_accounts and disallowed_accounts cannot be both present"
        );
    }

    #[test]
    fn test_solana_policy_format() {
        let config = json!({
            "id": "solana-relayer",
            "name": "Solana Mainnet Relayer",
            "network": "mainnet",
            "network_type": "solana",
            "signer_id": "solana-signer",
            "paused": false,
            "policies": {
                "min_balance": 100,
                "allowed_tokens": [ {"mint": "token1"}, {"mint": "token2"}],
            }
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();

        let err = relayer.validate_policies().unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid policy: Value must contain only letters, numbers, dashes and underscores"
        );
    }

    #[test]
    fn test_valid_evm_relayer() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false,
            "policies": {
                "gas_price_cap": 100,
                "whitelist_receivers": ["0x1234"],
                "eip1559_pricing": true
            }
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());
        assert_eq!(relayer.id, "test-relayer");
        assert_eq!(relayer.network_type, ConfigFileNetworkType::Evm);
    }

    #[test]
    fn test_valid_solana_relayer() {
        let config = json!({
            "id": "solana-relayer",
            "name": "Solana Mainnet Relayer",
            "network": "mainnet-beta",
            "network_type": "solana",
            "signer_id": "solana-signer",
            "paused": false,
            "policies": {
                "min_balance": 100,
                "disallowed_accounts": ["HCKHoE2jyk1qfAwpHQghvYH3cEfT8euCygBzF9AV6bhY"],
            }
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());
        assert_eq!(relayer.id, "solana-relayer");
        assert_eq!(relayer.network_type, ConfigFileNetworkType::Solana);
    }

    #[test]
    fn test_valid_stellar_relayer() {
        let config = json!({
            "id": "stellar-relayer",
            "name": "Stellar Public Relayer",
            "network": "mainnet",
            "network_type": "stellar",
            "signer_id": "stellar_signer",
            "paused": false,
            "policies": {
                "max_fee": 100,
                "timeout_seconds": 10,
                "min_balance": 100
            }
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());
        assert_eq!(relayer.id, "stellar-relayer");
        assert_eq!(relayer.network_type, ConfigFileNetworkType::Stellar);
    }

    #[test]
    fn test_invalid_network_type() {
        let config = json!({
            "id": "test-relayer",
            "network_type": "invalid",
            "signer_id": "test-signer"
        });

        let result = serde_json::from_value::<RelayerFileConfig>(config);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "missing field `name`")]
    fn test_missing_required_fields() {
        let config = json!({
            "id": "test-relayer"
        });

        let _relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
    }

    #[test]
    fn test_valid_custom_rpc_urls() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false,
            "custom_rpc_urls": [
                { "url": "https://api.example.com/rpc", "weight": 2 },
                { "url": "https://rpc.example.com" }
            ]
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());

        let rpc_urls = relayer.custom_rpc_urls.unwrap();
        assert_eq!(rpc_urls.len(), 2);
        assert_eq!(rpc_urls[0].url, "https://api.example.com/rpc");
        assert_eq!(rpc_urls[0].weight, 2_u8);
        assert_eq!(rpc_urls[1].url, "https://rpc.example.com");
        assert_eq!(rpc_urls[1].weight, DEFAULT_RPC_WEIGHT);
        assert_eq!(rpc_urls[1].get_weight(), DEFAULT_RPC_WEIGHT);
    }

    #[test]
    fn test_valid_custom_rpc_urls_string_format() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false,
            "custom_rpc_urls": [
                "https://api.example.com/rpc",
                "https://rpc.example.com"
            ]
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());

        let rpc_urls = relayer.custom_rpc_urls.unwrap();
        assert_eq!(rpc_urls.len(), 2);
        assert_eq!(rpc_urls[0].url, "https://api.example.com/rpc");
        assert_eq!(rpc_urls[0].weight, DEFAULT_RPC_WEIGHT);
        assert_eq!(rpc_urls[0].get_weight(), DEFAULT_RPC_WEIGHT);
        assert_eq!(rpc_urls[1].url, "https://rpc.example.com");
        assert_eq!(rpc_urls[1].weight, DEFAULT_RPC_WEIGHT);
        assert_eq!(rpc_urls[1].get_weight(), DEFAULT_RPC_WEIGHT);
    }

    #[test]
    fn test_invalid_custom_rpc_urls() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false,
            "custom_rpc_urls": [
                { "url": "not-a-url", "weight": 1 },
                { "url": "https://api.example.com/rpc", "weight": 2 }
            ]
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        let result = relayer.validate();
        assert!(result.is_err());
        if let Err(ConfigFileError::InvalidFormat(msg)) = result {
            assert!(msg.contains("Invalid RPC URL"));
        } else {
            panic!("Expected ConfigFileError::InvalidFormat");
        }
    }

    #[test]
    fn test_invalid_custom_rpc_urls_weight() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false,
            "custom_rpc_urls": [
                { "url": "https://api.example.com/rpc", "weight": 200 }
            ]
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        let result = relayer.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_custom_rpc_urls() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false,
            "custom_rpc_urls": []
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());
    }

    #[test]
    fn test_no_custom_rpc_urls() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet",
            "network_type": "evm",
            "signer_id": "test-signer",
            "paused": false
        });

        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        assert!(relayer.validate().is_ok());
    }

    /// Helper to build a minimal RelayerFileConfig JSON for Solana with given swap_config
    fn make_relayer_config_with_solana_swap_config(
        swap_config: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "mainnet-beta",
            "network_type": "solana",
            "signer_id": "test-signer",
            "paused": false,
            "policies": {
                "fee_payment_strategy": "user",
                "swap_config": swap_config
            }
        })
    }

    #[test]
    fn invalid_jupiter_swap_options_without_strategy() {
        let swap_cfg = json!({
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 1,
            "jupiter_swap_options": {
                "priority_level": "high",
                "priority_fee_max_lamports": 1000,
                "dynamic_compute_unit_limit": true
            }
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: JupiterSwap options are only valid for JupiterSwap strategy"
        );
    }

    #[test]
    fn invalid_priority_fee_zero() {
        let swap_cfg = json!({
            "strategy": "jupiter-swap",
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 1,
            "jupiter_swap_options": {
                "priority_level": "medium",
                "priority_fee_max_lamports": 0,
                "dynamic_compute_unit_limit": false
            }
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: Max lamports must be greater than 0"
        );
    }

    #[test]
    fn invalid_empty_priority_level() {
        let swap_cfg = json!({
            "strategy": "jupiter-swap",
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 1,
            "jupiter_swap_options": {
                "priority_level": "",
                "priority_fee_max_lamports": 100,
                "dynamic_compute_unit_limit": false
            }
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: Priority level cannot be empty"
        );
    }

    #[test]
    fn invalid_priority_level_value() {
        let swap_cfg = json!({
            "strategy": "jupiter-swap",
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 1,
            "jupiter_swap_options": {
                "priority_level": "urgent",
                "priority_fee_max_lamports": 100,
                "dynamic_compute_unit_limit": true
            }
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: Priority level must be one of: medium, high, veryHigh"
        );
    }

    #[test]
    fn valid_jupiter_swap_config() {
        let swap_cfg = json!({
            "strategy": "jupiter-swap",
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 10,
            "jupiter_swap_options": {
                "priority_level": "medium",
                "priority_fee_max_lamports": 2000,
                "dynamic_compute_unit_limit": true
            }
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        assert!(relayer.validate().is_ok());
    }

    #[test]
    fn valid_jupiter_ultra_config() {
        let swap_cfg = json!({
            "strategy": "jupiter-ultra",
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 10,
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        assert!(relayer.validate().is_ok());
    }

    #[test]
    fn invalid_jupiter_swap_options_value_for_ultra() {
        let swap_cfg = json!({
            "strategy": "jupiter-ultra",
            "cron_schedule": "0 * * * * *",
            "min_balance_threshold": 10,
            "jupiter_swap_options": {
                "priority_level": "medium",
                "priority_fee_max_lamports": 2000,
                "dynamic_compute_unit_limit": true
            }
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: JupiterSwap options are only valid for JupiterSwap strategy"
        );
    }

    #[test]
    fn invalid_swap_config_empty_cron() {
        let swap_cfg = json!({
            "strategy": "jupiter-ultra",
            "cron_schedule": "",
            "min_balance_threshold": 10,
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: Empty cron schedule is not accepted"
        );
    }

    #[test]
    fn invalid_swap_config_invalid_cron() {
        let swap_cfg = json!({
            "strategy": "jupiter-ultra",
            "cron_schedule": "* 1 *",
            "min_balance_threshold": 10,
        });
        let cfg = make_relayer_config_with_solana_swap_config(swap_cfg);
        let relayer: RelayerFileConfig = serde_json::from_value(cfg).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: Invalid cron schedule format"
        );
    }

    #[test]
    fn invalid_swap_config_invalid_network_jupiter_swap() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "devnet",
            "network_type": "solana",
            "signer_id": "test-signer",
            "paused": false,
            "policies": {
                "fee_payment_strategy": "user",
                "swap_config": {
                    "strategy": "jupiter-swap",
                    "cron_schedule": "* 1 *",
                    "min_balance_threshold": 10,
                }
            }
        });
        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: JupiterSwap strategy is only supported on mainnet-beta"
        );
    }

    #[test]
    fn invalid_swap_config_invalid_network_jupiter_ultra() {
        let config = json!({
            "id": "test-relayer",
            "name": "Test Relayer",
            "network": "devnet",
            "network_type": "solana",
            "signer_id": "test-signer",
            "paused": false,
            "policies": {
                "fee_payment_strategy": "user",
                "swap_config": {
                    "strategy": "jupiter-ultra",
                    "cron_schedule": "* 1 *",
                    "min_balance_threshold": 10,
                }
            }
        });
        let relayer: RelayerFileConfig = serde_json::from_value(config).unwrap();
        let err = relayer.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid policy: JupiterUltra strategy is only supported on mainnet-beta"
        );
    }

    #[test]
    fn test_relayer_with_non_existent_network_fails_validation() {
        let relayers = vec![RelayerFileConfig {
            id: "test-relayer".to_string(),
            name: "Test Relayer".to_string(),
            network: "non-existent-network".to_string(),
            paused: false,
            network_type: ConfigFileNetworkType::Evm,
            policies: None,
            signer_id: "test-signer".to_string(),
            notification_id: None,
            custom_rpc_urls: None,
        }];

        let networks = NetworksFileConfig::new(vec![NetworkFileConfig::Evm(EvmNetworkConfig {
            common: NetworkConfigCommon {
                network: "existing-network".to_string(),
                from: None,
                rpc_urls: Some(vec!["https://rpc.test.example.com".to_string()]),
                explorer_urls: Some(vec!["https://explorer.test.example.com".to_string()]),
                average_blocktime_ms: Some(12000),
                is_testnet: Some(true),
                tags: Some(vec!["test".to_string()]),
            },
            chain_id: Some(31337),
            required_confirmations: Some(1),
            features: None,
            symbol: Some("ETH".to_string()),
        })])
        .expect("Failed to create NetworksFileConfig for test");

        let relayers_config = RelayersFileConfig::new(relayers);
        let result = relayers_config.validate(&networks);

        assert!(result.is_err());
        if let Err(ConfigFileError::InvalidReference(msg)) = result {
            assert!(msg.contains("non-existent network 'non-existent-network'"));
            assert!(msg.contains("Relayer 'test-relayer'"));
        } else {
            panic!("Expected InvalidReference error, got: {:?}", result);
        }
    }
}
