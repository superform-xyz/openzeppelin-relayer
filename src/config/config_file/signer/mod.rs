//! Configuration file definitions for signer services.
//!
//! Provides configuration structures and validation for different signer types:
//! - Test (temporary private keys)
//! - Local keystore (encrypted JSON files)
//! - HashiCorp Vault integration
//! - Turnkey service integration
//! - Google Cloud integration
//! - AWS KMS integration (EVM only)
use super::ConfigFileError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use validator::Validate;

mod local;
pub use local::*;

mod vault;
pub use vault::*;

mod vault_cloud;
pub use vault_cloud::*;

mod vault_transit;
pub use vault_transit::*;

mod turnkey;
pub use turnkey::*;

mod google_cloud_kms;
pub use google_cloud_kms::*;

mod aws_kms;
pub use aws_kms::*;

pub trait SignerConfigValidate {
    fn validate(&self) -> Result<(), ConfigFileError>;
}

fn collect_validation_errors(errors: &validator::ValidationErrors) -> Vec<String> {
    let mut messages = Vec::new();

    for (field, field_errors) in errors.field_errors().iter() {
        let field_msgs: Vec<String> = field_errors
            .iter()
            .map(|error| error.message.clone().unwrap_or_default().to_string())
            .collect();
        messages.push(format!("{}: {}", field, field_msgs.join(", ")));
    }

    for (struct_field, kind) in errors.errors().iter() {
        if let validator::ValidationErrorsKind::Struct(nested) = kind {
            let nested_msgs = collect_validation_errors(nested);
            for msg in nested_msgs {
                messages.push(format!("{}.{}", struct_field, msg));
            }
        }
    }

    messages
}

/// Validates a signer config using validator::Validate
pub fn validate_with_validator<T>(config: &T) -> Result<(), ConfigFileError>
where
    T: SignerConfigValidate + Validate,
{
    match Validate::validate(config) {
        Ok(_) => Ok(()),
        Err(errors) => Err(ConfigFileError::InvalidFormat(
            collect_validation_errors(&errors).join("; "),
        )),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TestSignerFileConfig {}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase", content = "config")]
pub enum SignerFileConfigEnum {
    Test(TestSignerFileConfig),
    Local(LocalSignerFileConfig),
    #[serde(rename = "aws_kms")]
    AwsKms(AwsKmsSignerFileConfig),
    Vault(VaultSignerFileConfig),
    #[serde(rename = "vault_cloud")]
    VaultCloud(VaultCloudSignerFileConfig),
    #[serde(rename = "vault_transit")]
    VaultTransit(VaultTransitSignerFileConfig),
    Turnkey(TurnkeySignerFileConfig),
    #[serde(rename = "google_cloud_kms")]
    GoogleCloudKms(GoogleCloudKmsSignerFileConfig),
}

impl SignerFileConfigEnum {
    pub fn get_local(&self) -> Option<&LocalSignerFileConfig> {
        match self {
            SignerFileConfigEnum::Local(local) => Some(local),
            _ => None,
        }
    }

    pub fn get_vault(&self) -> Option<&VaultSignerFileConfig> {
        match self {
            SignerFileConfigEnum::Vault(vault) => Some(vault),
            _ => None,
        }
    }

    pub fn get_vault_cloud(&self) -> Option<&VaultCloudSignerFileConfig> {
        match self {
            SignerFileConfigEnum::VaultCloud(vault_cloud) => Some(vault_cloud),
            _ => None,
        }
    }

    pub fn get_vault_transit(&self) -> Option<&VaultTransitSignerFileConfig> {
        match self {
            SignerFileConfigEnum::VaultTransit(vault_transit) => Some(vault_transit),
            _ => None,
        }
    }

    pub fn get_test(&self) -> Option<&TestSignerFileConfig> {
        match self {
            SignerFileConfigEnum::Test(test) => Some(test),
            _ => None,
        }
    }

    pub fn get_aws_kms(&self) -> Option<&AwsKmsSignerFileConfig> {
        match self {
            SignerFileConfigEnum::AwsKms(aws_kms) => Some(aws_kms),
            _ => None,
        }
    }

    pub fn get_turnkey(&self) -> Option<&TurnkeySignerFileConfig> {
        match self {
            SignerFileConfigEnum::Turnkey(turnkey) => Some(turnkey),
            _ => None,
        }
    }

    pub fn get_google_cloud_kms(&self) -> Option<&GoogleCloudKmsSignerFileConfig> {
        match self {
            SignerFileConfigEnum::GoogleCloudKms(google_cloud_kms) => Some(google_cloud_kms),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SignerFileConfig {
    pub id: String,
    #[serde(flatten)]
    pub config: SignerFileConfigEnum,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignerFileConfigPassphrase {
    Env { name: String },
    Plain { value: String },
}

impl SignerFileConfig {
    pub fn validate_signer(&self) -> Result<(), ConfigFileError> {
        if self.id.is_empty() {
            return Err(ConfigFileError::InvalidIdLength(
                "Signer ID cannot be empty".into(),
            ));
        }

        match &self.config {
            SignerFileConfigEnum::Test(_) => Ok(()),
            SignerFileConfigEnum::Local(local_config) => local_config.validate(),
            SignerFileConfigEnum::AwsKms(aws_kms_config) => {
                SignerConfigValidate::validate(aws_kms_config)
            }
            SignerFileConfigEnum::Vault(vault_config) => {
                SignerConfigValidate::validate(vault_config)
            }
            SignerFileConfigEnum::VaultCloud(vault_cloud_config) => {
                SignerConfigValidate::validate(vault_cloud_config)
            }
            SignerFileConfigEnum::VaultTransit(vault_transit_config) => {
                SignerConfigValidate::validate(vault_transit_config)
            }
            SignerFileConfigEnum::Turnkey(turnkey_config) => {
                SignerConfigValidate::validate(turnkey_config)
            }
            SignerFileConfigEnum::GoogleCloudKms(google_cloud_kms_config) => {
                SignerConfigValidate::validate(google_cloud_kms_config)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SignersFileConfig {
    pub signers: Vec<SignerFileConfig>,
}

impl SignersFileConfig {
    pub fn new(signers: Vec<SignerFileConfig>) -> Self {
        Self { signers }
    }

    pub fn validate(&self) -> Result<(), ConfigFileError> {
        if self.signers.is_empty() {
            return Err(ConfigFileError::MissingField("signers".into()));
        }

        let mut ids = HashSet::new();
        for signer in &self.signers {
            signer.validate_signer()?;
            if !ids.insert(signer.id.clone()) {
                return Err(ConfigFileError::DuplicateId(signer.id.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{PlainOrEnvValue, PlainOrEnvValueError, SecretString};

    use super::*;
    use serde_json::json;
    use std::env;

    #[test]
    fn test_plain_or_env_config_value_plain() {
        let plain = PlainOrEnvValue::Plain {
            value: SecretString::new("test-value"),
        };

        assert_eq!(
            plain.get_value().unwrap().to_str().as_str(),
            "test-value".to_string()
        );
    }

    #[test]
    fn test_plain_or_env_config_value_env_exists() {
        env::set_var("TEST_ENV_VAR", "env-test-value");

        let env_value = PlainOrEnvValue::Env {
            value: "TEST_ENV_VAR".to_string(),
        };

        assert_eq!(
            env_value.get_value().unwrap().to_str().as_str(),
            "env-test-value".to_string()
        );
        env::remove_var("TEST_ENV_VAR");
    }

    #[test]
    fn test_plain_or_env_config_value_env_missing() {
        env::remove_var("NONEXISTENT_TEST_VAR");

        let env_value = PlainOrEnvValue::Env {
            value: "NONEXISTENT_TEST_VAR".to_string(),
        };

        let result = env_value.get_value();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(PlainOrEnvValueError::MissingEnvVar(_))
        ));
    }

    #[test]
    fn test_valid_signer_config() {
        let config = json!({
            "id": "local-signer",
            "type": "local",
            "config": {
                "path": "tests/utils/test_keys/unit-test-local-signer.json",
                "passphrase": {
                    "type": "plain",
                    "value": "secret",
                }
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_valid_signer_config_env() {
        env::set_var("LOCAL_SIGNER_KEY_PASSPHRASE", "mocked_value");

        let config = json!({
            "id": "local-signer",
            "type": "local",
            "config": {
                "path": "tests/utils/test_keys/unit-test-local-signer.json",
                "passphrase": {
                    "type": "env",
                    "value": "LOCAL_SIGNER_KEY_PASSPHRASE"
                }
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
        env::remove_var("LOCAL_SIGNER_KEY_PASSPHRASE");
    }

    #[test]
    fn test_duplicate_signer_ids() {
        let config = json!({
            "signers": [
                {
                  "id": "local-signer",
                  "type": "local",
                  "config": {
                      "path": "tests/utils/test_keys/unit-test-local-signer.json",
                      "passphrase": {
                          "type": "plain",
                          "value": "secret",
                      }
                  }
                },
                {
                  "id": "local-signer",
                  "type": "local",
                  "config": {
                      "path": "tests/utils/test_keys/unit-test-local-signer.json",
                      "passphrase": {
                          "type": "plain",
                          "value": "secret",
                      }
                  }
                }
            ]
        });

        let signer_config: SignersFileConfig = serde_json::from_value(config).unwrap();
        assert!(matches!(
            signer_config.validate(),
            Err(ConfigFileError::DuplicateId(_))
        ));
    }

    #[test]
    fn test_empty_signer_id() {
        let config = json!({
            "signers": [
                {
                  "id": "",
                  "type": "local",
                  "config": {
                    "path": "tests/utils/test_keys/unit-test-local-signer.json",
                    "passphrase": {
                        "type": "plain",
                        "value": "secret",
                    }
                }

                }
            ]
        });

        let signer_config: SignersFileConfig = serde_json::from_value(config).unwrap();
        assert!(matches!(
            signer_config.validate(),
            Err(ConfigFileError::InvalidIdLength(_))
        ));
    }

    #[test]
    fn test_validate_test_signer() {
        let config = json!({
            "id": "test-signer",
            "type": "test",
            "config": {}
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_validate_vault_signer() {
        let config = json!({
            "id": "vault-signer",
            "type": "vault",
            "config": {
                "address": "https://vault.example.com",
                "role_id": {
                    "type":"plain",
                    "value":"role-123"
                },
                "secret_id": {
                    "type":"plain",
                    "value":"secret-456"
                },
                "key_name": "test-key"
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_validate_vault_cloud_signer() {
        let config = json!({
            "id": "vault-cloud-signer",
            "type": "vault_cloud",
            "config": {
                "client_id": "client-123",
                "client_secret": {
                    "type": "plain",
                    "value":"secret-abc"
                },
                "org_id": "org-456",
                "project_id": "proj-789",
                "app_name": "my-app",
                "key_name": "cloud-key"
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_validate_vault_transit_signer() {
        let config = json!({
            "id": "vault-transit-signer",
            "type": "vault_transit",
            "config": {
                "key_name": "transit-key",
                "address": "https://vault.example.com",
                "role_id": {
                    "type":"plain",
                    "value":"role-123"
                },
                "secret_id": {
                    "type":"plain",
                    "value":"secret-456"
                },
                "pubkey": "test-pubkey"
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_validate_vault_transit_signer_invalid() {
        let config = json!({
            "id": "vault-transit-signer",
            "type": "vault_transit",
            "config": {
                "key_name": "",
                "address": "https://vault.example.com",
                "role_id": {
                    "type":"plain",
                    "value":"role-123"
                },
                "secret_id": {
                    "type":"plain",
                    "value":"secret-456"
                },
                "pubkey": "test-pubkey"
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_err());
    }

    #[test]
    fn test_validate_turnkey_signer() {
        let config = json!({
            "id": "turnkey-signer",
            "type": "turnkey",
            "config": {
                "api_private_key": {"type": "plain", "value": "key"},
                "api_public_key": "api_public_key",
                "organization_id": "organization_id",
                "private_key_id": "private_key_id",
                "public_key": "public_key",
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_validate_turnkey_invalid() {
        let config = json!({
            "id": "turnkey-signer",
            "type": "turnkey",
            "config": {
                "api_private_key": {"type": "plain", "value": "key"},
                "api_public_key": "",
                "organization_id": "organization_id",
                "private_key_id": "private_key_id",
                "public_key": "public_key",
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_err());
    }

    #[test]
    fn test_validate_google_cloud_kms_signer() {
        let config = json!({
            "id": "google-signer",
            "type": "google_cloud_kms",
            "config": {
                "service_account": {
                    "private_key": {
                        "type": "plain",
                        "value": "key"
                    },
                    "client_email": {
                        "type": "plain",
                        "value": "email"
                    },
                    "private_key_id": {
                        "type": "plain",
                        "value": "key_id"
                    },
                    "project_id": "id",
                    "client_id": "client_id"
                },
                "key": {
                    "key_id": "my-key",
                    "key_ring_id": "my-keyring",
                    "key_version": 1
                }
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_ok());
    }

    #[test]
    fn test_validate_google_cloud_kms_invalid() {
        let config = json!({
            "id": "google-signer",
            "type": "google_cloud_kms",
            "config": {
                "service_account": {
                    "private_key": {
                        "type": "plain",
                        "value": "key"
                    },
                    "client_email": {
                        "type": "plain",
                        "value": "email"
                    },
                    "private_key_id": {
                        "type": "plain",
                        "value": "key_id"
                    },
                    "project_id": "",
                    "client_id": "client_id"
                },
                "key": {
                    "key_id": "my-key",
                    "key_ring_id": "my-keyring",
                    "key_version": 1
                }
            }
        });

        let signer_config: SignerFileConfig = serde_json::from_value(config).unwrap();
        assert!(signer_config.validate_signer().is_err());
    }

    #[test]
    fn test_empty_signers_array() {
        let config = json!({
            "signers": []
        });

        let signer_config: SignersFileConfig = serde_json::from_value(config).unwrap();
        let result = signer_config.validate();
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigFileError::MissingField(_))));
    }

    #[test]
    fn test_signers_file_config_new() {
        let signer = SignerFileConfig {
            id: "test-signer".to_string(),
            config: SignerFileConfigEnum::Test(TestSignerFileConfig {}),
        };

        let config = SignersFileConfig::new(vec![signer.clone()]);
        assert_eq!(config.signers.len(), 1);
        assert_eq!(config.signers[0].id, "test-signer");
        assert!(matches!(
            config.signers[0].config,
            SignerFileConfigEnum::Test(_)
        ));
    }

    #[test]
    fn test_serde_for_enum_variants() {
        let test_config = json!({
            "type": "test",
            "config": {}
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(test_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::Test(_)));

        let local_config = json!({
            "type": "local",
            "config": {
                "path": "test-path",
                "passphrase": {
                    "type": "plain",
                    "value": "test-passphrase"
                }
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(local_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::Local(_)));

        let vault_config = json!({
            "type": "vault",
            "config": {
                "address": "https://vault.example.com",
                "role_id": {"type": "plain", "value": "role-123"},
                "secret_id": { "type": "plain", "value": "secret-456"},
                "key_name": "test-key"
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(vault_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::Vault(_)));

        let vault_cloud_config = json!({
            "type": "vault_cloud",
            "config": {
                "client_id": "client-123",
                "client_secret": {"type": "plain", "value": "secret-abc"},
                "org_id": "org-456",
                "project_id": "proj-789",
                "app_name": "my-app",
                "key_name": "cloud-key"
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(vault_cloud_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::VaultCloud(_)));

        let vault_transit_config = json!({
            "type": "vault_transit",
            "config": {
                "key_name": "transit-key",
                "address": "https://vault.example.com",
                "role_id": {"type": "plain", "value": "role-123"},
                "secret_id": { "type": "plain", "value": "secret-456"},
                "pubkey": "test-pubkey"
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(vault_transit_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::VaultTransit(_)));

        let aws_kms_config = json!({
            "type": "aws_kms",
            "config": {
                "region": "us-east-1",
                "key_id": "test-key-id"
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(aws_kms_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::AwsKms(_)));

        let turnkey_config = json!({
            "type": "turnkey",
            "config": {
                "api_private_key": {"type": "plain", "value": "key"},
                "api_public_key": "api_public_key",
                "organization_id": "organization_id",
                "private_key_id": "private_key_id",
                "public_key": "public_key",
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(turnkey_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::Turnkey(_)));

        let google_config = json!({
            "type": "google_cloud_kms",
            "config": {
                "service_account": {
                    "private_key": {"type": "plain", "value": "key"},
                    "client_email": {"type": "plain", "value": "email"},
                    "private_key_id": {"type": "plain", "value": "key_id"},
                    "project_id": "id",
                    "client_id": "client_id"
                },
                "key": {
                    "key_id": "my-key",
                    "key_ring_id": "my-keyring",
                    "key_version": 1
                }
            }
        });
        let parsed: SignerFileConfigEnum = serde_json::from_value(google_config).unwrap();
        assert!(matches!(parsed, SignerFileConfigEnum::GoogleCloudKms(_)));
    }

    #[test]
    fn test_get_methods_for_signer_config() {
        let test_config = SignerFileConfigEnum::Test(TestSignerFileConfig {});
        assert!(test_config.get_test().is_some());
        assert!(test_config.get_local().is_none());
        assert!(test_config.get_vault().is_none());
        assert!(test_config.get_vault_cloud().is_none());
        assert!(test_config.get_vault_transit().is_none());
        assert!(test_config.get_aws_kms().is_none());
        assert!(test_config.get_turnkey().is_none());
        assert!(test_config.get_google_cloud_kms().is_none());

        let local_config = SignerFileConfigEnum::Local(LocalSignerFileConfig {
            path: "test-path".to_string(),
            passphrase: PlainOrEnvValue::Plain {
                value: SecretString::new("test-passphrase"),
            },
        });
        assert!(local_config.get_test().is_none());
        assert!(local_config.get_local().is_some());
        assert!(local_config.get_vault().is_none());
        assert!(local_config.get_vault_cloud().is_none());
        assert!(local_config.get_vault_transit().is_none());
        assert!(local_config.get_aws_kms().is_none());
        assert!(local_config.get_turnkey().is_none());
        assert!(local_config.get_google_cloud_kms().is_none());

        let vault_config = SignerFileConfigEnum::Vault(VaultSignerFileConfig {
            address: "https://vault.example.com".to_string(),
            namespace: None,
            role_id: PlainOrEnvValue::Plain {
                value: SecretString::new("role-123"),
            },
            secret_id: PlainOrEnvValue::Plain {
                value: SecretString::new("secret-456"),
            },
            key_name: "test-key".to_string(),
            mount_point: None,
        });
        assert!(vault_config.get_test().is_none());
        assert!(vault_config.get_local().is_none());
        assert!(vault_config.get_vault().is_some());
        assert!(vault_config.get_vault_cloud().is_none());
        assert!(vault_config.get_vault_transit().is_none());
        assert!(vault_config.get_aws_kms().is_none());
        assert!(vault_config.get_turnkey().is_none());
        assert!(vault_config.get_google_cloud_kms().is_none());

        let vault_cloud_config = SignerFileConfigEnum::VaultCloud(VaultCloudSignerFileConfig {
            client_id: "client-123".to_string(),
            client_secret: PlainOrEnvValue::Plain {
                value: SecretString::new("secret-abc"),
            },
            org_id: "org-456".to_string(),
            project_id: "proj-789".to_string(),
            app_name: "my-app".to_string(),
            key_name: "cloud-key".to_string(),
        });
        assert!(vault_cloud_config.get_test().is_none());
        assert!(vault_cloud_config.get_local().is_none());
        assert!(vault_cloud_config.get_vault().is_none());
        assert!(vault_cloud_config.get_vault_cloud().is_some());
        assert!(vault_cloud_config.get_vault_transit().is_none());
        assert!(vault_cloud_config.get_aws_kms().is_none());

        let vault_transit_config =
            SignerFileConfigEnum::VaultTransit(VaultTransitSignerFileConfig {
                key_name: "transit-key".to_string(),
                address: "https://vault.example.com".to_string(),
                role_id: PlainOrEnvValue::Plain {
                    value: SecretString::new("role-123"),
                },
                secret_id: PlainOrEnvValue::Plain {
                    value: SecretString::new("secret-456"),
                },
                pubkey: "test-pubkey".to_string(),
                mount_point: None,
                namespace: None,
            });
        assert!(vault_transit_config.get_test().is_none());
        assert!(vault_transit_config.get_local().is_none());
        assert!(vault_transit_config.get_vault().is_none());
        assert!(vault_transit_config.get_vault_cloud().is_none());
        assert!(vault_transit_config.get_vault_transit().is_some());
        assert!(vault_transit_config.get_aws_kms().is_none());
        assert!(vault_transit_config.get_turnkey().is_none());
        assert!(vault_transit_config.get_google_cloud_kms().is_none());

        let aws_kms_config = SignerFileConfigEnum::AwsKms(AwsKmsSignerFileConfig {
            region: Some("us-east-1".to_string()),
            key_id: "test-key-id".to_string(),
        });
        assert!(aws_kms_config.get_test().is_none());
        assert!(aws_kms_config.get_local().is_none());
        assert!(aws_kms_config.get_vault().is_none());
        assert!(aws_kms_config.get_vault_cloud().is_none());
        assert!(aws_kms_config.get_vault_transit().is_none());
        assert!(aws_kms_config.get_aws_kms().is_some());
        assert!(aws_kms_config.get_turnkey().is_none());
        assert!(aws_kms_config.get_google_cloud_kms().is_none());

        let turnkey_config = SignerFileConfigEnum::Turnkey(TurnkeySignerFileConfig {
            api_private_key: PlainOrEnvValue::Plain {
                value: SecretString::new("role-123"),
            },
            api_public_key: "api_public_key".to_string(),
            organization_id: "organization_id".to_string(),
            private_key_id: "private_key_id".to_string(),
            public_key: "public_key".to_string(),
        });
        assert!(turnkey_config.get_test().is_none());
        assert!(turnkey_config.get_local().is_none());
        assert!(turnkey_config.get_vault().is_none());
        assert!(turnkey_config.get_vault_cloud().is_none());
        assert!(turnkey_config.get_vault_transit().is_none());
        assert!(turnkey_config.get_aws_kms().is_none());
        assert!(turnkey_config.get_turnkey().is_some());
        assert!(turnkey_config.get_google_cloud_kms().is_none());

        let google_cloud_kms_config =
            SignerFileConfigEnum::GoogleCloudKms(GoogleCloudKmsSignerFileConfig {
                service_account: ServiceAccountConfig {
                    private_key: PlainOrEnvValue::Plain {
                        value: SecretString::new("key"),
                    },
                    client_email: PlainOrEnvValue::Plain {
                        value: SecretString::new("email"),
                    },
                    private_key_id: PlainOrEnvValue::Plain {
                        value: SecretString::new("key_id"),
                    },
                    project_id: "id".to_string(),
                    client_id: "client_id".to_string(),
                    auth_uri: "uri".to_string(),
                    token_uri: "uri".to_string(),
                    client_x509_cert_url: "uri".to_string(),
                    auth_provider_x509_cert_url: "uri".to_string(),
                    universe_domain: "uri".to_string(),
                },
                key: KmsKeyConfig {
                    location: "global".to_string(),
                    key_id: "my-key".to_string(),
                    key_ring_id: "my-keyring".to_string(),
                    key_version: 1,
                },
            });
        assert!(google_cloud_kms_config.get_test().is_none());
        assert!(google_cloud_kms_config.get_local().is_none());
        assert!(google_cloud_kms_config.get_vault().is_none());
        assert!(google_cloud_kms_config.get_vault_cloud().is_none());
        assert!(google_cloud_kms_config.get_vault_transit().is_none());
        assert!(google_cloud_kms_config.get_aws_kms().is_none());
        assert!(google_cloud_kms_config.get_turnkey().is_none());
        assert!(google_cloud_kms_config.get_google_cloud_kms().is_some());
    }
}
