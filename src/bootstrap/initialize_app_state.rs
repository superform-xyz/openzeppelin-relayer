//! Application state initialization
//!
//! This module contains functions for initializing the application state,
//! including setting up repositories, job queues, and other necessary components.
use crate::{
    jobs::{self, Queue},
    models::{AppState, DefaultAppState},
    repositories::{
        InMemoryNetworkRepository, InMemoryNotificationRepository, InMemoryPluginRepository,
        InMemoryRelayerRepository, InMemorySignerRepository, InMemoryTransactionCounter,
        InMemoryTransactionRepository, RelayerRepositoryStorage,
    },
};
use actix_web::web;
use color_eyre::Result;
use std::sync::Arc;

/// Initializes application state
///
/// # Returns
///
/// * `Result<web::Data<AppState>>` - Initialized application state
///
/// # Errors
///
/// Returns error if:
/// - Repository initialization fails
/// - Configuration loading fails
pub async fn initialize_app_state() -> Result<web::ThinData<DefaultAppState>> {
    let relayer_repository = Arc::new(RelayerRepositoryStorage::in_memory(
        InMemoryRelayerRepository::new(),
    ));
    let transaction_repository = Arc::new(InMemoryTransactionRepository::new());
    let signer_repository = Arc::new(InMemorySignerRepository::new());
    let notification_repository = Arc::new(InMemoryNotificationRepository::new());
    let network_repository = Arc::new(InMemoryNetworkRepository::new());
    let transaction_counter_store = Arc::new(InMemoryTransactionCounter::new());
    let queue = Queue::setup().await?;
    let job_producer = Arc::new(jobs::JobProducer::new(queue.clone()));
    let plugin_repository = Arc::new(InMemoryPluginRepository::new());

    let app_state = web::ThinData(AppState {
        relayer_repository,
        transaction_repository,
        signer_repository,
        notification_repository,
        network_repository,
        transaction_counter_store,
        job_producer,
        plugin_repository,
    });

    Ok(app_state)
}
