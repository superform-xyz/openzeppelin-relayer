#[cfg(test)]
pub mod mockutils {
    use std::sync::Arc;

    use alloy::primitives::U256;
    use secrets::SecretVec;

    use crate::{
        config::{EvmNetworkConfig, NetworkConfigCommon},
        jobs::MockJobProducerTrait,
        models::{
            AppState, EvmTransactionRequest, LocalSignerConfig, NetworkRepoModel, NetworkType,
            PluginModel, RelayerEvmPolicy, RelayerNetworkPolicy, RelayerRepoModel, SignerConfig,
            SignerRepoModel,
        },
        repositories::{
            InMemoryNetworkRepository, InMemoryNotificationRepository, InMemoryPluginRepository,
            InMemoryRelayerRepository, InMemorySignerRepository, InMemoryTransactionCounter,
            InMemoryTransactionRepository, PluginRepositoryTrait, RelayerRepositoryStorage,
            Repository,
        },
    };

    pub fn create_mock_relayer(id: String, paused: bool) -> RelayerRepoModel {
        RelayerRepoModel {
            id: id.clone(),
            name: format!("Relayer {}", id.clone()),
            network: "test".to_string(),
            paused,
            network_type: NetworkType::Evm,
            policies: RelayerNetworkPolicy::Evm(RelayerEvmPolicy {
                gas_price_cap: None,
                whitelist_receivers: None,
                eip1559_pricing: Some(false),
                private_transactions: false,
                min_balance: 0,
            }),
            signer_id: "test".to_string(),
            address: "0x".to_string(),
            notification_id: None,
            system_disabled: false,
            custom_rpc_urls: None,
        }
    }

    pub fn create_mock_signer() -> SignerRepoModel {
        let seed = vec![1u8; 32];
        let raw_key = SecretVec::new(32, |v| v.copy_from_slice(&seed));
        SignerRepoModel {
            id: "test".to_string(),
            config: SignerConfig::Test(LocalSignerConfig { raw_key }),
        }
    }

    pub fn create_mock_network() -> NetworkRepoModel {
        NetworkRepoModel {
            id: "test".to_string(),
            name: "test".to_string(),
            network_type: NetworkType::Evm,
            config: crate::models::NetworkConfigData::Evm(EvmNetworkConfig {
                common: NetworkConfigCommon {
                    network: "test".to_string(),
                    from: None,
                    rpc_urls: Some(vec!["http://localhost:8545".to_string()]),
                    explorer_urls: None,
                    average_blocktime_ms: Some(1000),
                    is_testnet: Some(true),
                    tags: None,
                },
                required_confirmations: Some(1),
                features: None,
                symbol: Some("testETH".to_string()),
                chain_id: Some(1),
            }),
        }
    }

    pub async fn create_mock_app_state(
        relayers: Option<Vec<RelayerRepoModel>>,
        signers: Option<Vec<SignerRepoModel>>,
        networks: Option<Vec<NetworkRepoModel>>,
        plugins: Option<Vec<PluginModel>>,
    ) -> AppState<MockJobProducerTrait> {
        let relayer_repository = Arc::new(RelayerRepositoryStorage::in_memory(
            InMemoryRelayerRepository::default(),
        ));
        if let Some(relayers) = relayers {
            for relayer in relayers {
                relayer_repository.create(relayer).await.unwrap();
            }
        }

        let signer_repository = Arc::new(InMemorySignerRepository::default());
        if let Some(signers) = signers {
            for signer in signers {
                signer_repository.create(signer).await.unwrap();
            }
        }

        let network_repository = Arc::new(InMemoryNetworkRepository::default());
        if let Some(networks) = networks {
            for network in networks {
                network_repository.create(network).await.unwrap();
            }
        }

        let plugin_repository = Arc::new(InMemoryPluginRepository::default());
        if let Some(plugins) = plugins {
            for plugin in plugins {
                plugin_repository.add(plugin).await.unwrap();
            }
        }

        let mut mock_job_producer = MockJobProducerTrait::new();

        mock_job_producer
            .expect_produce_transaction_request_job()
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mock_job_producer
            .expect_produce_submit_transaction_job()
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mock_job_producer
            .expect_produce_check_transaction_status_job()
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mock_job_producer
            .expect_produce_send_notification_job()
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mock_job_producer
            .expect_produce_solana_token_swap_request_job()
            .returning(|_, _| Box::pin(async { Ok(()) }));

        AppState {
            relayer_repository,
            transaction_repository: Arc::new(InMemoryTransactionRepository::default()),
            signer_repository,
            notification_repository: Arc::new(InMemoryNotificationRepository::default()),
            network_repository,
            transaction_counter_store: Arc::new(InMemoryTransactionCounter::default()),
            job_producer: Arc::new(mock_job_producer),
            plugin_repository,
        }
    }

    pub fn create_mock_evm_transaction_request() -> EvmTransactionRequest {
        EvmTransactionRequest {
            to: Some("0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string()),
            value: U256::from(0),
            data: Some("0x".to_string()),
            gas_limit: 21000,
            gas_price: Some(0),
            speed: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            valid_until: None,
        }
    }
}
