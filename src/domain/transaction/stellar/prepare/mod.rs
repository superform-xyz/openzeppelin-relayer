//! This module contains the preparation-related functionality for Stellar transactions.
//! It includes methods for preparing transactions with robust error handling,
//! ensuring lanes are always properly cleaned up on failure.

// Declare submodules from the prepare/ directory
pub mod common;
pub mod fee_bump;
pub mod operations;
pub mod unsigned_xdr;

use eyre::Result;
use log::{info, warn};

use super::{lane_gate, StellarRelayerTransaction};
use crate::models::RelayerRepoModel;
use crate::{
    jobs::JobProducerTrait,
    models::{TransactionError, TransactionInput, TransactionRepoModel, TransactionStatus},
    repositories::{Repository, TransactionCounterTrait, TransactionRepository},
    services::{Signer, StellarProviderTrait},
};

use common::{sign_and_finalize_transaction, update_and_notify_transaction};

impl<R, T, J, S, P, C> StellarRelayerTransaction<R, T, J, S, P, C>
where
    R: Repository<RelayerRepoModel, String> + Send + Sync,
    T: TransactionRepository + Send + Sync,
    J: JobProducerTrait + Send + Sync,
    S: Signer + Send + Sync,
    P: StellarProviderTrait + Send + Sync,
    C: TransactionCounterTrait + Send + Sync,
{
    /// Main preparation method with robust error handling and guaranteed lane cleanup.
    pub async fn prepare_transaction_impl(
        &self,
        tx: TransactionRepoModel,
    ) -> Result<TransactionRepoModel, TransactionError> {
        if !lane_gate::claim(&self.relayer().id, &tx.id) {
            info!(
                "Relayer {} already has a transaction in flight – {} must wait.",
                self.relayer().id,
                tx.id
            );
            return Ok(tx);
        }

        info!("Preparing transaction: {:?}", tx.id);

        // Call core preparation logic with error handling
        match self.prepare_core(tx.clone()).await {
            Ok(prepared_tx) => Ok(prepared_tx),
            Err(error) => {
                // Always cleanup on failure - this is the critical safety mechanism
                self.handle_prepare_failure(tx, error).await
            }
        }
    }

    /// Core preparation logic
    async fn prepare_core(
        &self,
        tx: TransactionRepoModel,
    ) -> Result<TransactionRepoModel, TransactionError> {
        let stellar_data = tx.network_data.get_stellar_transaction_data()?;

        // Simple dispatch to appropriate processing function based on input type
        match &stellar_data.transaction_input {
            TransactionInput::Operations(_) => {
                info!("Preparing operations-based transaction {}", tx.id);
                let stellar_data_with_sim = operations::process_operations(
                    self.transaction_counter_service(),
                    &self.relayer().id,
                    &self.relayer().address,
                    &tx,
                    stellar_data,
                    self.provider(),
                    self.signer(),
                )
                .await?;
                self.finalize_with_signature(tx, stellar_data_with_sim)
                    .await
            }
            TransactionInput::UnsignedXdr(_) => {
                info!("Preparing unsigned XDR transaction {}", tx.id);
                let stellar_data_with_sim = unsigned_xdr::process_unsigned_xdr(
                    self.transaction_counter_service(),
                    &self.relayer().id,
                    &self.relayer().address,
                    stellar_data,
                    self.provider(),
                    self.signer(),
                )
                .await?;
                self.finalize_with_signature(tx, stellar_data_with_sim)
                    .await
            }
            TransactionInput::SignedXdr { .. } => {
                info!("Preparing fee-bump transaction {}", tx.id);
                let stellar_data_with_fee_bump = fee_bump::process_fee_bump(
                    &self.relayer().address,
                    stellar_data,
                    self.provider(),
                    self.signer(),
                )
                .await?;
                update_and_notify_transaction(
                    self.transaction_repository(),
                    self.job_producer(),
                    tx.id,
                    stellar_data_with_fee_bump,
                    self.relayer().notification_id.as_deref(),
                )
                .await
            }
        }
    }

    /// Helper to sign and finalize transactions for Operations and UnsignedXdr inputs.
    async fn finalize_with_signature(
        &self,
        tx: TransactionRepoModel,
        stellar_data: crate::models::StellarTransactionData,
    ) -> Result<TransactionRepoModel, TransactionError> {
        let (tx, final_stellar_data) =
            sign_and_finalize_transaction(self.signer(), tx, stellar_data).await?;
        update_and_notify_transaction(
            self.transaction_repository(),
            self.job_producer(),
            tx.id,
            final_stellar_data,
            self.relayer().notification_id.as_deref(),
        )
        .await
    }

    /// Handles preparation failures with comprehensive cleanup and error reporting.
    /// This method ensures lanes are never left claimed after any failure.
    async fn handle_prepare_failure(
        &self,
        tx: TransactionRepoModel,
        error: TransactionError,
    ) -> Result<TransactionRepoModel, TransactionError> {
        let error_reason = format!("Preparation failed: {}", error);
        let tx_id = tx.id.clone(); // Clone the ID before moving tx
        warn!("Transaction {} preparation failed: {}", tx_id, error_reason);

        // Step 1: Mark transaction as Failed with detailed reason
        let _failed_tx = match self
            .finalize_transaction_state(
                tx_id.clone(),
                TransactionStatus::Failed,
                Some(error_reason.clone()),
                None,
            )
            .await
        {
            Ok(updated_tx) => updated_tx,
            Err(finalize_error) => {
                warn!(
                    "Failed to mark transaction {} as failed: {}. Proceeding with lane cleanup.",
                    tx_id, finalize_error
                );
                // Continue with cleanup even if we can't update the transaction
                tx
            }
        };

        // Step 2: Attempt to enqueue next pending transaction or release lane
        if let Err(enqueue_error) = self.enqueue_next_pending_transaction(&tx_id).await {
            warn!(
                "Failed to enqueue next pending transaction after {} failure: {}. Releasing lane directly.",
                tx_id, enqueue_error
            );
            // Fallback: release lane directly if we can't hand it over
            lane_gate::free(&self.relayer().id, &tx_id);
        }

        // Step 3: Log failure for monitoring (prepare_fail_total metric would go here)
        info!(
            "Transaction {} preparation failure handled. Lane cleaned up. Error: {}",
            tx_id, error_reason
        );

        // Step 4: Return original error to maintain API compatibility
        Err(error)
    }
}

#[cfg(test)]
mod prepare_transaction_tests {
    use super::*;
    use crate::{
        domain::SignTransactionResponse,
        models::{NetworkTransactionData, RepositoryError, TransactionStatus},
    };
    use soroban_rs::xdr::{Limits, ReadXdr, TransactionEnvelope};

    use crate::domain::transaction::stellar::test_helpers::*;

    #[tokio::test]
    async fn prepare_transaction_happy_path() {
        let relayer = create_test_relayer();
        let mut mocks = default_test_mocks();

        // sequence counter
        mocks
            .counter
            .expect_get_and_increment()
            .returning(|_, _| Ok(1));

        // signer
        mocks.signer.expect_sign_transaction().returning(|_| {
            Box::pin(async {
                Ok(SignTransactionResponse::Stellar(
                    crate::domain::SignTransactionResponseStellar {
                        signature: dummy_signature(),
                    },
                ))
            })
        });

        mocks
            .tx_repo
            .expect_partial_update()
            .withf(|_, upd| {
                upd.status == Some(TransactionStatus::Sent) && upd.network_data.is_some()
            })
            .returning(|id, upd| {
                let mut tx = create_test_transaction("relayer-1");
                tx.id = id;
                tx.status = upd.status.unwrap();
                tx.network_data = upd.network_data.unwrap();
                Ok::<_, RepositoryError>(tx)
            });

        // submit-job + notification
        mocks
            .job_producer
            .expect_produce_submit_transaction_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mocks
            .job_producer
            .expect_produce_send_notification_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        let handler = make_stellar_tx_handler(relayer.clone(), mocks);
        let tx = create_test_transaction(&relayer.id);

        assert!(handler.prepare_transaction_impl(tx).await.is_ok());
    }

    #[tokio::test]
    async fn prepare_transaction_stores_signed_envelope_xdr() {
        let relayer = create_test_relayer();
        let mut mocks = default_test_mocks();

        // sequence counter
        mocks
            .counter
            .expect_get_and_increment()
            .returning(|_, _| Ok(1));

        // signer
        mocks.signer.expect_sign_transaction().returning(|_| {
            Box::pin(async {
                Ok(SignTransactionResponse::Stellar(
                    crate::domain::SignTransactionResponseStellar {
                        signature: dummy_signature(),
                    },
                ))
            })
        });

        mocks
            .tx_repo
            .expect_partial_update()
            .withf(|_, upd| {
                upd.status == Some(TransactionStatus::Sent) && upd.network_data.is_some()
            })
            .returning(move |id, upd| {
                let mut tx = create_test_transaction("relayer-1");
                tx.id = id;
                tx.status = upd.status.unwrap();
                tx.network_data = upd.network_data.clone().unwrap();
                Ok::<_, RepositoryError>(tx)
            });

        // submit-job + notification
        mocks
            .job_producer
            .expect_produce_submit_transaction_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mocks
            .job_producer
            .expect_produce_send_notification_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        let handler = make_stellar_tx_handler(relayer.clone(), mocks);
        let tx = create_test_transaction(&relayer.id);

        let result = handler.prepare_transaction_impl(tx).await;
        assert!(result.is_ok());

        // Verify the signed_envelope_xdr was populated
        if let Ok(prepared_tx) = result {
            if let NetworkTransactionData::Stellar(stellar_data) = &prepared_tx.network_data {
                assert!(
                    stellar_data.signed_envelope_xdr.is_some(),
                    "signed_envelope_xdr should be populated"
                );

                // Verify it's valid XDR by attempting to parse it
                let xdr = stellar_data.signed_envelope_xdr.as_ref().unwrap();
                let envelope_result = TransactionEnvelope::from_xdr_base64(xdr, Limits::none());
                assert!(
                    envelope_result.is_ok(),
                    "signed_envelope_xdr should be valid XDR"
                );

                // Verify the envelope has signatures
                if let Ok(envelope) = envelope_result {
                    match envelope {
                        TransactionEnvelope::Tx(ref e) => {
                            assert!(!e.signatures.is_empty(), "Envelope should have signatures");
                        }
                        _ => panic!("Expected Tx envelope type"),
                    }
                }
            } else {
                panic!("Expected Stellar transaction data");
            }
        }
    }

    #[tokio::test]
    async fn prepare_transaction_sequence_failure_cleans_up_lane() {
        let relayer = create_test_relayer();
        let mut mocks = default_test_mocks();

        // Mock sequence counter to fail
        mocks.counter.expect_get_and_increment().returning(|_, _| {
            Err(crate::repositories::TransactionCounterError::NotFound(
                "Counter service failure".to_string(),
            ))
        });

        // Mock finalize_transaction_state for failure handling
        mocks
            .tx_repo
            .expect_partial_update()
            .withf(|_, upd| upd.status == Some(TransactionStatus::Failed))
            .returning(|id, upd| {
                let mut tx = create_test_transaction("relayer-1");
                tx.id = id;
                tx.status = upd.status.unwrap();
                Ok::<_, RepositoryError>(tx)
            });

        // Mock notification for failed transaction
        mocks
            .job_producer
            .expect_produce_send_notification_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        // Mock find_by_status for enqueue_next_pending_transaction
        mocks
            .tx_repo
            .expect_find_by_status()
            .returning(|_, _| Ok(vec![])); // No pending transactions

        let handler = make_stellar_tx_handler(relayer.clone(), mocks);
        let tx = create_test_transaction(&relayer.id);

        // Verify that lane is claimed initially
        assert!(lane_gate::claim(&relayer.id, &tx.id));

        let result = handler.prepare_transaction_impl(tx.clone()).await;

        // Should return error but lane should be cleaned up
        assert!(result.is_err());

        // Verify lane is released - another transaction should be able to claim it
        let another_tx_id = "another-tx";
        assert!(lane_gate::claim(&relayer.id, another_tx_id));
        lane_gate::free(&relayer.id, another_tx_id)
    }

    #[tokio::test]
    async fn prepare_transaction_signer_failure_cleans_up_lane() {
        let relayer = create_test_relayer();
        let mut mocks = default_test_mocks();

        // sequence counter succeeds
        mocks
            .counter
            .expect_get_and_increment()
            .returning(|_, _| Ok(1));

        // signer fails
        mocks.signer.expect_sign_transaction().returning(|_| {
            Box::pin(async {
                Err(crate::models::SignerError::SigningError(
                    "Signer failure".to_string(),
                ))
            })
        });

        // Mock finalize_transaction_state for failure handling
        mocks
            .tx_repo
            .expect_partial_update()
            .withf(|_, upd| upd.status == Some(TransactionStatus::Failed))
            .returning(|id, upd| {
                let mut tx = create_test_transaction("relayer-1");
                tx.id = id;
                tx.status = upd.status.unwrap();
                Ok::<_, RepositoryError>(tx)
            });

        // Mock notification for failed transaction
        mocks
            .job_producer
            .expect_produce_send_notification_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        // Mock find_by_status for enqueue_next_pending_transaction
        mocks
            .tx_repo
            .expect_find_by_status()
            .returning(|_, _| Ok(vec![])); // No pending transactions

        let handler = make_stellar_tx_handler(relayer.clone(), mocks);
        let tx = create_test_transaction(&relayer.id);

        let result = handler.prepare_transaction_impl(tx.clone()).await;

        // Should return error but lane should be cleaned up
        assert!(result.is_err());

        // Verify lane is released
        let another_tx_id = "another-tx";
        assert!(lane_gate::claim(&relayer.id, another_tx_id));
        lane_gate::free(&relayer.id, another_tx_id); // cleanup
    }

    #[tokio::test]
    async fn prepare_transaction_already_claimed_lane_returns_original() {
        let mut relayer = create_test_relayer();
        relayer.id = "unique-relayer-for-lane-test".to_string(); // Use unique relayer ID
        let mocks = default_test_mocks();

        let handler = make_stellar_tx_handler(relayer.clone(), mocks);
        let tx = create_test_transaction(&relayer.id);

        // Claim lane with different transaction
        assert!(lane_gate::claim(&relayer.id, "other-tx"));

        let result = handler.prepare_transaction_impl(tx.clone()).await;

        // Should return Ok with original transaction (waiting)
        assert!(result.is_ok());
        let returned_tx = result.unwrap();
        assert_eq!(returned_tx.id, tx.id);
        assert_eq!(returned_tx.status, tx.status);

        // Cleanup
        lane_gate::free(&relayer.id, "other-tx");
    }
}

#[cfg(test)]
mod refactoring_tests {
    use crate::domain::transaction::stellar::prepare::common::update_and_notify_transaction;
    use crate::domain::transaction::stellar::test_helpers::*;
    use crate::models::{
        NetworkTransactionData, RepositoryError, StellarTransactionData, TransactionInput,
        TransactionStatus,
    };

    #[tokio::test]
    async fn test_update_and_notify_transaction_consistency() {
        let relayer = create_test_relayer();
        let mut mocks = default_test_mocks();

        // Mock the repository update
        let expected_stellar_data = StellarTransactionData {
            source_account: TEST_PK.to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            fee: Some(100),
            sequence_number: Some(1),
            transaction_input: TransactionInput::Operations(vec![]),
            memo: None,
            valid_until: None,
            signatures: vec![],
            hash: None,
            simulation_transaction_data: None,
            signed_envelope_xdr: Some("test-xdr".to_string()),
        };

        let expected_xdr = expected_stellar_data.signed_envelope_xdr.clone();
        mocks
            .tx_repo
            .expect_partial_update()
            .withf(move |id, upd| {
                id == "tx-1"
                    && upd.status == Some(TransactionStatus::Sent)
                    && if let Some(NetworkTransactionData::Stellar(ref data)) = upd.network_data {
                        data.signed_envelope_xdr == expected_xdr
                    } else {
                        false
                    }
            })
            .returning(|id, upd| {
                let mut tx = create_test_transaction("relayer-1");
                tx.id = id;
                tx.status = upd.status.unwrap();
                tx.network_data = upd.network_data.unwrap();
                Ok::<_, RepositoryError>(tx)
            });

        // Mock job production
        mocks
            .job_producer
            .expect_produce_submit_transaction_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        mocks
            .job_producer
            .expect_produce_send_notification_job()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        let handler = make_stellar_tx_handler(relayer.clone(), mocks);

        // Test update_and_notify_transaction directly
        let result = update_and_notify_transaction(
            handler.transaction_repository(),
            handler.job_producer(),
            "tx-1".to_string(),
            expected_stellar_data,
            handler.relayer().notification_id.as_deref(),
        )
        .await;

        assert!(result.is_ok());
        let updated_tx = result.unwrap();
        assert_eq!(updated_tx.status, TransactionStatus::Sent);

        if let NetworkTransactionData::Stellar(data) = &updated_tx.network_data {
            assert_eq!(data.signed_envelope_xdr, Some("test-xdr".to_string()));
        } else {
            panic!("Expected Stellar transaction data");
        }
    }
}
