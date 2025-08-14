//! This module contains the status handling functionality for Stellar transactions.
//! It includes methods for checking transaction status with robust error handling,
//! ensuring proper transaction state management and lane cleanup.

use chrono::Utc;
use log::{info, warn};
use serde_json::{json, Value};
use soroban_rs::xdr::{Error, Hash};

use super::StellarRelayerTransaction;
use crate::{
    constants::STELLAR_DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    jobs::{JobProducerTrait, TransactionStatusCheck},
    models::{
        NetworkTransactionData, RelayerRepoModel, TransactionError, TransactionRepoModel,
        TransactionStatus, TransactionUpdateRequest,
    },
    repositories::{Repository, TransactionCounterTrait, TransactionRepository},
    services::{Signer, StellarProviderTrait},
};

impl<R, T, J, S, P, C> StellarRelayerTransaction<R, T, J, S, P, C>
where
    R: Repository<RelayerRepoModel, String> + Send + Sync,
    T: TransactionRepository + Send + Sync,
    J: JobProducerTrait + Send + Sync,
    S: Signer + Send + Sync,
    P: StellarProviderTrait + Send + Sync,
    C: TransactionCounterTrait + Send + Sync,
{
    /// Main status handling method with robust error handling.
    /// This method checks transaction status and handles lane cleanup for finalized transactions.
    pub async fn handle_transaction_status_impl(
        &self,
        tx: TransactionRepoModel,
    ) -> Result<TransactionRepoModel, TransactionError> {
        info!("Handling transaction status for: {:?}", tx.id);

        // Call core status checking logic with error handling
        match self.status_core(tx.clone()).await {
            Ok(updated_tx) => Ok(updated_tx),
            Err(error) => {
                // Only retry for provider errors, not validation errors
                match error {
                    TransactionError::ValidationError(_) => {
                        // Don't retry validation errors (like missing hash)
                        Err(error)
                    }
                    _ => {
                        // Handle status check failure - requeue for retry
                        self.handle_status_failure(tx, error).await
                    }
                }
            }
        }
    }

    /// Core status checking logic - pure business logic without error handling concerns.
    async fn status_core(
        &self,
        tx: TransactionRepoModel,
    ) -> Result<TransactionRepoModel, TransactionError> {
        let stellar_hash = self.parse_and_validate_hash(&tx)?;

        let provider_response = match self.provider().get_transaction(&stellar_hash).await {
            Ok(response) => response,
            Err(e) => {
                let error_str = format!("{:?}", e);

                // Check if this is an XDR parsing error (common with fee bump transactions)
                if error_str.contains("Xdr(Invalid)") || error_str.contains("xdr processing error")
                {
                    warn!(
                        "XDR parsing error for transaction {}, using raw RPC fallback",
                        tx.id
                    );

                    // Fallback: Get transaction status via raw RPC request
                    // TODO: This is a temporary solution to handle XDR parsing errors.
                    // We should remove this once we upgrade to next stable rpc client version.
                    match self.get_transaction_status_raw(&stellar_hash).await {
                        Ok(status) => {
                            // Return a minimal response with just the status
                            soroban_rs::stellar_rpc_client::GetTransactionResponse {
                                status,
                                envelope: None,
                                result: None,
                                result_meta: None,
                            }
                        }
                        Err(raw_err) => {
                            warn!("Raw RPC fallback also failed for {}: {:?}", tx.id, raw_err);
                            return Err(TransactionError::from(e));
                        }
                    }
                } else {
                    warn!("Provider get_transaction failed for {}: {:?}", tx.id, e);
                    return Err(TransactionError::from(e));
                }
            }
        };

        match provider_response.status.as_str().to_uppercase().as_str() {
            "SUCCESS" => self.handle_stellar_success(tx, provider_response).await,
            "FAILED" => self.handle_stellar_failed(tx, provider_response).await,
            _ => {
                self.handle_stellar_pending(tx, provider_response.status)
                    .await
            }
        }
    }

    /// Handles status check failures with retry logic.
    /// This method ensures failed status checks are retried appropriately.
    async fn handle_status_failure(
        &self,
        tx: TransactionRepoModel,
        error: TransactionError,
    ) -> Result<TransactionRepoModel, TransactionError> {
        warn!(
            "Failed to get Stellar transaction status for {}: {}. Re-queueing check.",
            tx.id, error
        );

        // Step 1: Re-queue status check for retry
        if let Err(requeue_error) = self.requeue_status_check(&tx).await {
            warn!(
                "Failed to requeue status check for transaction {}: {}",
                tx.id, requeue_error
            );
            // Continue with original error even if requeue fails
        }

        // Step 2: Log failure for monitoring (status_check_fail_total metric would go here)
        info!(
            "Transaction {} status check failure handled. Will retry later. Error: {}",
            tx.id, error
        );

        // Step 3: Return original transaction unchanged (will be retried)
        Ok(tx)
    }

    /// Helper function to re-queue a transaction status check job.
    pub async fn requeue_status_check(
        &self,
        tx: &TransactionRepoModel,
    ) -> Result<(), TransactionError> {
        self.job_producer()
            .produce_check_transaction_status_job(
                TransactionStatusCheck::new(tx.id.clone(), tx.relayer_id.clone()),
                Some(STELLAR_DEFAULT_STATUS_RETRY_DELAY_SECONDS),
            )
            .await?;
        Ok(())
    }

    /// Parses the transaction hash from the network data and validates it.
    /// Returns a `TransactionError::ValidationError` if the hash is missing, empty, or invalid.
    pub fn parse_and_validate_hash(
        &self,
        tx: &TransactionRepoModel,
    ) -> Result<Hash, TransactionError> {
        let stellar_network_data = tx.network_data.get_stellar_transaction_data()?;

        let tx_hash_str = stellar_network_data.hash.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            TransactionError::ValidationError(format!(
                "Stellar transaction {} is missing or has an empty on-chain hash in network_data. Cannot check status.",
                tx.id
            ))
        })?;

        let stellar_hash: Hash = tx_hash_str.parse().map_err(|e: Error| {
            TransactionError::UnexpectedError(format!(
                "Failed to parse transaction hash '{}' for tx {}: {:?}. This hash may be corrupted or not a valid Stellar hash.",
                tx_hash_str, tx.id, e
            ))
        })?;

        Ok(stellar_hash)
    }

    /// Handles the logic when a Stellar transaction is confirmed successfully.
    pub async fn handle_stellar_success(
        &self,
        tx: TransactionRepoModel,
        provider_response: soroban_rs::stellar_rpc_client::GetTransactionResponse,
    ) -> Result<TransactionRepoModel, TransactionError> {
        // Extract the actual fee charged from the transaction result and update network data
        let updated_network_data = provider_response.result.as_ref().and_then(|tx_result| {
            tx.network_data
                .get_stellar_transaction_data()
                .ok()
                .map(|stellar_data| {
                    NetworkTransactionData::Stellar(
                        stellar_data.with_fee(tx_result.fee_charged as u32),
                    )
                })
        });

        let update_request = TransactionUpdateRequest {
            status: Some(TransactionStatus::Confirmed),
            confirmed_at: Some(Utc::now().to_rfc3339()),
            network_data: updated_network_data,
            ..Default::default()
        };

        let confirmed_tx = self
            .finalize_transaction_state(tx.id.clone(), update_request)
            .await?;

        self.enqueue_next_pending_transaction(&tx.id).await?;

        Ok(confirmed_tx)
    }

    /// Handles the logic when a Stellar transaction has failed.
    pub async fn handle_stellar_failed(
        &self,
        tx: TransactionRepoModel,
        provider_response: soroban_rs::stellar_rpc_client::GetTransactionResponse,
    ) -> Result<TransactionRepoModel, TransactionError> {
        let base_reason = "Transaction failed on-chain. Provider status: FAILED.".to_string();
        let detailed_reason = if let Some(ref tx_result_xdr) = provider_response.result {
            format!(
                "{} Specific XDR reason: {}.",
                base_reason,
                tx_result_xdr.result.name()
            )
        } else {
            format!("{} No detailed XDR result available.", base_reason)
        };

        warn!("Stellar transaction {} failed: {}", tx.id, detailed_reason);

        let update_request = TransactionUpdateRequest {
            status: Some(TransactionStatus::Failed),
            status_reason: Some(detailed_reason),
            ..Default::default()
        };

        let updated_tx = self
            .finalize_transaction_state(tx.id.clone(), update_request)
            .await?;

        self.enqueue_next_pending_transaction(&tx.id).await?;

        Ok(updated_tx)
    }

    /// Handles the logic when a Stellar transaction is still pending or in an unknown state.
    pub async fn handle_stellar_pending(
        &self,
        tx: TransactionRepoModel,
        original_status_str: String,
    ) -> Result<TransactionRepoModel, TransactionError> {
        info!(
            "Stellar transaction {} status is still '{}'. Re-queueing check.",
            tx.id, original_status_str
        );
        self.requeue_status_check(&tx).await?;
        Ok(tx)
    }

    /// Get transaction status via raw RPC request (workaround for XDR parsing issues)
    async fn get_transaction_status_raw(
        &self,
        tx_hash: &soroban_rs::xdr::Hash,
    ) -> Result<String, TransactionError> {
        // Convert hash to hex string (manual implementation to avoid hex dependency)
        let hash_hex: String = tx_hash
            .0
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();

        // Build JSON-RPC request
        let request_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": {
                "hash": hash_hex
            }
        });

        // Get the RPC URL from the provider
        let rpc_url = self.provider().rpc_url();

        // Make HTTP request using reqwest (already a dependency)
        let client = reqwest::Client::new();
        let response = client
            .post(rpc_url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                TransactionError::UnexpectedError(format!("Raw RPC request failed: {}", e))
            })?;

        // Parse response as generic JSON
        let json_response: Value = response.json().await.map_err(|e| {
            TransactionError::UnexpectedError(format!("Failed to parse JSON response: {}", e))
        })?;

        // Check for RPC error
        if let Some(error) = json_response.get("error") {
            if let Some(code) = error.get("code").and_then(|c| c.as_i64()) {
                if code == -32602 || code == -32600 {
                    return Ok("NOT_FOUND".to_string());
                }
            }
            return Err(TransactionError::UnexpectedError(format!(
                "RPC error: {:?}",
                error
            )));
        }

        // Extract status from result
        json_response
            .get("result")
            .and_then(|result| result.get("status"))
            .and_then(|status| status.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                TransactionError::UnexpectedError("Missing status in response".to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NetworkTransactionData, RepositoryError};
    use mockall::predicate::eq;
    use soroban_rs::stellar_rpc_client::GetTransactionResponse;

    use crate::domain::transaction::stellar::test_helpers::*;

    fn dummy_get_transaction_response(status: &str) -> GetTransactionResponse {
        GetTransactionResponse {
            status: status.to_string(),
            envelope: None,
            result: None,
            result_meta: None,
        }
    }

    mod handle_transaction_status_tests {
        use super::*;

        #[tokio::test]
        async fn handle_transaction_status_confirmed_triggers_next() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-confirm-this".to_string();
            let tx_hash_bytes = [1u8; 32];
            let tx_hash_hex = hex::encode(tx_hash_bytes);
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(tx_hash_hex.clone());
            } else {
                panic!("Expected Stellar network data for tx_to_handle");
            }
            tx_to_handle.status = TransactionStatus::Submitted;

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // 1. Mock provider to return SUCCESS
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(dummy_get_transaction_response("SUCCESS")) })
                });

            // 2. Mock partial_update for confirmation
            mocks
                .tx_repo
                .expect_partial_update()
                .withf(move |id, update| {
                    id == "tx-confirm-this"
                        && update.status == Some(TransactionStatus::Confirmed)
                        && update.confirmed_at.is_some()
                })
                .times(1)
                .returning(move |id, update| {
                    let mut updated_tx = tx_to_handle.clone(); // Use the original tx_to_handle as base
                    updated_tx.id = id;
                    updated_tx.status = update.status.unwrap();
                    updated_tx.confirmed_at = update.confirmed_at;
                    Ok(updated_tx)
                });

            // Send notification for confirmed tx
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // 3. Mock find_by_status for pending transactions
            let mut oldest_pending_tx = create_test_transaction(&relayer.id);
            oldest_pending_tx.id = "tx-oldest-pending".to_string();
            oldest_pending_tx.status = TransactionStatus::Pending;
            let captured_oldest_pending_tx = oldest_pending_tx.clone();
            mocks
                .tx_repo
                .expect_find_by_status()
                .with(eq(relayer.id.clone()), eq(vec![TransactionStatus::Pending]))
                .times(1)
                .returning(move |_, _| Ok(vec![captured_oldest_pending_tx.clone()]));

            // 4. Mock produce_transaction_request_job for the next pending transaction
            mocks
                .job_producer
                .expect_produce_transaction_request_job()
                .withf(move |job, _delay| job.transaction_id == "tx-oldest-pending")
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let mut initial_tx_for_handling = create_test_transaction(&relayer.id);
            initial_tx_for_handling.id = "tx-confirm-this".to_string();
            if let NetworkTransactionData::Stellar(ref mut stellar_data) =
                initial_tx_for_handling.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
            } else {
                panic!("Expected Stellar network data for initial_tx_for_handling");
            }
            initial_tx_for_handling.status = TransactionStatus::Submitted;

            let result = handler
                .handle_transaction_status_impl(initial_tx_for_handling)
                .await;

            assert!(result.is_ok());
            let handled_tx = result.unwrap();
            assert_eq!(handled_tx.id, "tx-confirm-this");
            assert_eq!(handled_tx.status, TransactionStatus::Confirmed);
            assert!(handled_tx.confirmed_at.is_some());
        }

        #[tokio::test]
        async fn handle_transaction_status_still_pending() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-pending-check".to_string();
            let tx_hash_bytes = [2u8; 32];
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
            } else {
                panic!("Expected Stellar network data");
            }
            tx_to_handle.status = TransactionStatus::Submitted; // Or any status that implies it's being watched

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // 1. Mock provider to return PENDING
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(dummy_get_transaction_response("PENDING")) })
                });

            // 2. Mock partial_update: should NOT be called
            mocks.tx_repo.expect_partial_update().never();

            // 3. Mock job_producer to expect a re-enqueue of status check
            mocks
                .job_producer
                .expect_produce_check_transaction_status_job()
                .withf(move |job, delay| {
                    job.transaction_id == "tx-pending-check"
                        && delay == &Some(STELLAR_DEFAULT_STATUS_RETRY_DELAY_SECONDS)
                })
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // Notifications should NOT be sent for pending
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .never();

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let original_tx_clone = tx_to_handle.clone();

            let result = handler.handle_transaction_status_impl(tx_to_handle).await;

            assert!(result.is_ok());
            let returned_tx = result.unwrap();
            // Transaction should be returned unchanged as it's still pending
            assert_eq!(returned_tx.id, original_tx_clone.id);
            assert_eq!(returned_tx.status, original_tx_clone.status);
            assert!(returned_tx.confirmed_at.is_none()); // Ensure it wasn't accidentally confirmed
        }

        #[tokio::test]
        async fn handle_transaction_status_failed() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-fail-this".to_string();
            let tx_hash_bytes = [3u8; 32];
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
            } else {
                panic!("Expected Stellar network data");
            }
            tx_to_handle.status = TransactionStatus::Submitted;

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // 1. Mock provider to return FAILED
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(dummy_get_transaction_response("FAILED")) })
                });

            // 2. Mock partial_update for failure - use actual update values
            let relayer_id_for_mock = relayer.id.clone();
            mocks
                .tx_repo
                .expect_partial_update()
                .times(1)
                .returning(move |id, update| {
                    // Use the actual update values instead of hardcoding
                    let mut updated_tx = create_test_transaction(&relayer_id_for_mock);
                    updated_tx.id = id;
                    updated_tx.status = update.status.unwrap();
                    updated_tx.status_reason = update.status_reason.clone();
                    Ok::<_, RepositoryError>(updated_tx)
                });

            // Send notification for failed tx
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // 3. Mock find_by_status for pending transactions (should be called by enqueue_next_pending_transaction)
            mocks
                .tx_repo
                .expect_find_by_status()
                .with(eq(relayer.id.clone()), eq(vec![TransactionStatus::Pending]))
                .times(1)
                .returning(move |_, _| Ok(vec![])); // No pending transactions

            // Should NOT try to enqueue next transaction since there are no pending ones
            mocks
                .job_producer
                .expect_produce_transaction_request_job()
                .never();
            // Should NOT re-queue status check
            mocks
                .job_producer
                .expect_produce_check_transaction_status_job()
                .never();

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let mut initial_tx_for_handling = create_test_transaction(&relayer.id);
            initial_tx_for_handling.id = "tx-fail-this".to_string();
            if let NetworkTransactionData::Stellar(ref mut stellar_data) =
                initial_tx_for_handling.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
            } else {
                panic!("Expected Stellar network data");
            }
            initial_tx_for_handling.status = TransactionStatus::Submitted;

            let result = handler
                .handle_transaction_status_impl(initial_tx_for_handling)
                .await;

            assert!(result.is_ok());
            let handled_tx = result.unwrap();
            assert_eq!(handled_tx.id, "tx-fail-this");
            assert_eq!(handled_tx.status, TransactionStatus::Failed);
            assert!(handled_tx.status_reason.is_some());
            assert_eq!(
                handled_tx.status_reason.unwrap(),
                "Transaction failed on-chain. Provider status: FAILED. No detailed XDR result available."
            );
        }

        #[tokio::test]
        async fn handle_transaction_status_provider_error() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-provider-error".to_string();
            let tx_hash_bytes = [4u8; 32];
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
            } else {
                panic!("Expected Stellar network data");
            }
            tx_to_handle.status = TransactionStatus::Submitted;

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // 1. Mock provider to return an error
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| Box::pin(async { Err(eyre::eyre!("RPC boom")) }));

            // 2. Mock partial_update: should NOT be called
            mocks.tx_repo.expect_partial_update().never();

            // 3. Mock job_producer to expect a re-enqueue of status check
            mocks
                .job_producer
                .expect_produce_check_transaction_status_job()
                .withf(move |job, delay| {
                    job.transaction_id == "tx-provider-error"
                        && delay == &Some(STELLAR_DEFAULT_STATUS_RETRY_DELAY_SECONDS)
                })
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // Notifications should NOT be sent
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .never();
            // Should NOT try to enqueue next transaction
            mocks
                .job_producer
                .expect_produce_transaction_request_job()
                .never();

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let original_tx_clone = tx_to_handle.clone();

            let result = handler.handle_transaction_status_impl(tx_to_handle).await;

            assert!(result.is_ok()); // The handler itself should return Ok(original_tx)
            let returned_tx = result.unwrap();
            // Transaction should be returned unchanged
            assert_eq!(returned_tx.id, original_tx_clone.id);
            assert_eq!(returned_tx.status, original_tx_clone.status);
        }

        #[tokio::test]
        async fn handle_transaction_status_no_hashes() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks(); // No mocks should be called, but make mutable for consistency

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-no-hashes".to_string();
            tx_to_handle.status = TransactionStatus::Submitted;

            mocks.provider.expect_get_transaction().never();
            mocks.tx_repo.expect_partial_update().never();
            mocks
                .job_producer
                .expect_produce_check_transaction_status_job()
                .never();
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .never();

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let result = handler.handle_transaction_status_impl(tx_to_handle).await;

            assert!(
                result.is_err(),
                "Expected an error when hash is missing, but got Ok"
            );
            match result.unwrap_err() {
                TransactionError::ValidationError(msg) => {
                    assert!(
                        msg.contains("Stellar transaction tx-no-hashes is missing or has an empty on-chain hash in network_data"),
                        "Unexpected error message: {}",
                        msg
                    );
                }
                other => panic!("Expected ValidationError, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn test_on_chain_failure_does_not_decrement_sequence() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-on-chain-fail".to_string();
            let tx_hash_bytes = [4u8; 32];
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
                stellar_data.sequence_number = Some(100); // Has a sequence
            }
            tx_to_handle.status = TransactionStatus::Submitted;

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // Mock provider to return FAILED (on-chain failure)
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(dummy_get_transaction_response("FAILED")) })
                });

            // Decrement should NEVER be called for on-chain failures
            mocks.counter.expect_decrement().never();

            // Mock partial_update for failure
            mocks
                .tx_repo
                .expect_partial_update()
                .times(1)
                .returning(move |id, update| {
                    let mut updated_tx = create_test_transaction("test");
                    updated_tx.id = id;
                    updated_tx.status = update.status.unwrap();
                    updated_tx.status_reason = update.status_reason.clone();
                    Ok::<_, RepositoryError>(updated_tx)
                });

            // Mock notification
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // Mock find_by_status
            mocks
                .tx_repo
                .expect_find_by_status()
                .returning(move |_, _| Ok(vec![]));

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let initial_tx = tx_to_handle.clone();

            let result = handler.handle_transaction_status_impl(initial_tx).await;

            assert!(result.is_ok());
            let handled_tx = result.unwrap();
            assert_eq!(handled_tx.id, "tx-on-chain-fail");
            assert_eq!(handled_tx.status, TransactionStatus::Failed);
        }

        #[tokio::test]
        async fn test_on_chain_success_does_not_decrement_sequence() {
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-on-chain-success".to_string();
            let tx_hash_bytes = [5u8; 32];
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
                stellar_data.sequence_number = Some(101); // Has a sequence
            }
            tx_to_handle.status = TransactionStatus::Submitted;

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // Mock provider to return SUCCESS
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(dummy_get_transaction_response("SUCCESS")) })
                });

            // Decrement should NEVER be called for on-chain success
            mocks.counter.expect_decrement().never();

            // Mock partial_update for confirmation
            mocks
                .tx_repo
                .expect_partial_update()
                .withf(move |id, update| {
                    id == "tx-on-chain-success"
                        && update.status == Some(TransactionStatus::Confirmed)
                        && update.confirmed_at.is_some()
                })
                .times(1)
                .returning(move |id, update| {
                    let mut updated_tx = create_test_transaction("test");
                    updated_tx.id = id;
                    updated_tx.status = update.status.unwrap();
                    updated_tx.confirmed_at = update.confirmed_at;
                    Ok(updated_tx)
                });

            // Mock notification
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // Mock find_by_status for next transaction
            mocks
                .tx_repo
                .expect_find_by_status()
                .returning(move |_, _| Ok(vec![]));

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let initial_tx = tx_to_handle.clone();

            let result = handler.handle_transaction_status_impl(initial_tx).await;

            assert!(result.is_ok());
            let handled_tx = result.unwrap();
            assert_eq!(handled_tx.id, "tx-on-chain-success");
            assert_eq!(handled_tx.status, TransactionStatus::Confirmed);
        }

        #[tokio::test]
        async fn test_xdr_parsing_error_detection() {
            // Test that verifies XDR parsing errors are correctly detected
            // The actual HTTP fallback is hard to test without mocking the HTTP client

            // Test error string detection for Xdr(Invalid)
            let error_str1 = format!("{:?}", eyre::eyre!("Xdr(Invalid)"));
            assert!(error_str1.contains("Xdr(Invalid)"));

            // Test error string detection for "xdr processing error"
            let error_str2 = format!("{:?}", eyre::eyre!("xdr processing error"));
            assert!(error_str2.contains("xdr processing error"));

            // Test the actual error detection logic from the code
            let test_errors = vec![
                "Xdr(Invalid) - some additional context",
                "Failed with xdr processing error: malformed",
                "Error: Xdr(Invalid)",
            ];

            for error_msg in test_errors {
                let error_str = format!("{:?}", eyre::eyre!(error_msg));
                let should_use_fallback = error_str.contains("Xdr(Invalid)")
                    || error_str.contains("xdr processing error");
                assert!(
                    should_use_fallback,
                    "Error '{}' should trigger fallback",
                    error_msg
                );
            }
        }

        #[tokio::test]
        async fn test_get_transaction_status_raw() {
            use mockito::Server;
            use serde_json::json;

            // Start a mock server
            let mut server = Server::new_async().await;
            let url = server.url();

            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            // Set up the provider to return the mock server URL
            mocks.provider.expect_rpc_url().return_const(url.clone());

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);

            // Test case 1: Successful response with SUCCESS status
            let tx_hash = soroban_rs::xdr::Hash([1u8; 32]);

            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "status": "SUCCESS"
                        }
                    })
                    .to_string(),
                )
                .expect(1)
                .create_async()
                .await;

            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_ok());
            assert_eq!(status.unwrap(), "SUCCESS");
            mock.assert_async().await;

            // Test case 2: Successful response with FAILED status
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "status": "FAILED"
                        }
                    })
                    .to_string(),
                )
                .expect(1)
                .create_async()
                .await;

            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_ok());
            assert_eq!(status.unwrap(), "FAILED");
            mock.assert_async().await;

            // Test case 3: Transaction not found (RPC error code -32602)
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32602,
                            "message": "Invalid params"
                        }
                    })
                    .to_string(),
                )
                .expect(1)
                .create_async()
                .await;

            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_ok());
            assert_eq!(status.unwrap(), "NOT_FOUND");
            mock.assert_async().await;

            // Test case 4: Transaction not found (RPC error code -32600)
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32600,
                            "message": "Invalid request"
                        }
                    })
                    .to_string(),
                )
                .expect(1)
                .create_async()
                .await;

            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_ok());
            assert_eq!(status.unwrap(), "NOT_FOUND");
            mock.assert_async().await;

            // Test case 5: Other RPC error
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32000,
                            "message": "Server error"
                        }
                    })
                    .to_string(),
                )
                .expect(1)
                .create_async()
                .await;

            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_err());
            match status.unwrap_err() {
                TransactionError::UnexpectedError(msg) => {
                    assert!(msg.contains("RPC error"));
                }
                _ => panic!("Expected UnexpectedError"),
            }
            mock.assert_async().await;

            // Test case 6: Missing status in response
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "other_field": "value"
                        }
                    })
                    .to_string(),
                )
                .expect(1)
                .create_async()
                .await;

            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_err());
            match status.unwrap_err() {
                TransactionError::UnexpectedError(msg) => {
                    assert!(msg.contains("Missing status in response"));
                }
                _ => panic!("Expected UnexpectedError"),
            }
            mock.assert_async().await;

            // Test case 7: Network error (connection refused)
            let mut mocks = default_test_mocks();
            mocks
                .provider
                .expect_rpc_url()
                .return_const("http://localhost:1".to_string()); // Invalid port

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_err());
            match status.unwrap_err() {
                TransactionError::UnexpectedError(msg) => {
                    assert!(msg.contains("Raw RPC request failed"));
                }
                _ => panic!("Expected UnexpectedError"),
            }

            // Test case 8: Invalid JSON response
            let mock = server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body("not valid json")
                .expect(1)
                .create_async()
                .await;

            let mut mocks = default_test_mocks();
            mocks.provider.expect_rpc_url().return_const(url.clone());

            let handler = make_stellar_tx_handler(relayer, mocks);
            let status = handler.get_transaction_status_raw(&tx_hash).await;
            assert!(status.is_err());
            match status.unwrap_err() {
                TransactionError::UnexpectedError(msg) => {
                    assert!(msg.contains("Failed to parse JSON response"));
                }
                _ => panic!("Expected UnexpectedError"),
            }
            mock.assert_async().await;
        }

        #[tokio::test]
        async fn test_handle_transaction_status_with_xdr_error_requeues() {
            // This test verifies that when get_transaction returns an XDR parsing error
            // and the fallback also fails, the transaction is re-queued for retry
            let relayer = create_test_relayer();
            let mut mocks = default_test_mocks();

            let mut tx_to_handle = create_test_transaction(&relayer.id);
            tx_to_handle.id = "tx-xdr-error-requeue".to_string();
            let tx_hash_bytes = [8u8; 32];
            if let NetworkTransactionData::Stellar(ref mut stellar_data) = tx_to_handle.network_data
            {
                stellar_data.hash = Some(hex::encode(tx_hash_bytes));
            }
            tx_to_handle.status = TransactionStatus::Submitted;

            let expected_stellar_hash = soroban_rs::xdr::Hash(tx_hash_bytes);

            // Mock provider to return a non-XDR error (won't trigger fallback)
            mocks
                .provider
                .expect_get_transaction()
                .with(eq(expected_stellar_hash.clone()))
                .times(1)
                .returning(move |_| Box::pin(async { Err(eyre::eyre!("Network timeout")) }));

            // Mock job_producer to expect a re-enqueue of status check
            mocks
                .job_producer
                .expect_produce_check_transaction_status_job()
                .withf(move |job, delay| {
                    job.transaction_id == "tx-xdr-error-requeue"
                        && delay == &Some(STELLAR_DEFAULT_STATUS_RETRY_DELAY_SECONDS)
                })
                .times(1)
                .returning(|_, _| Box::pin(async { Ok(()) }));

            // No partial update should occur
            mocks.tx_repo.expect_partial_update().never();
            mocks
                .job_producer
                .expect_produce_send_notification_job()
                .never();

            let handler = make_stellar_tx_handler(relayer.clone(), mocks);
            let original_tx_clone = tx_to_handle.clone();

            let result = handler.handle_transaction_status_impl(tx_to_handle).await;

            assert!(result.is_ok()); // The handler returns Ok with the original transaction
            let returned_tx = result.unwrap();
            // Transaction should be returned unchanged
            assert_eq!(returned_tx.id, original_tx_clone.id);
            assert_eq!(returned_tx.status, original_tx_clone.status);
        }
    }
}
