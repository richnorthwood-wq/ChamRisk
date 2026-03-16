use crate::ai::provider::AiProviderKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiSecretStorageMode {
    InternalEncryptedStorage,
    LocalFileStorage,
}

impl Default for AiSecretStorageMode {
    fn default() -> Self {
        Self::InternalEncryptedStorage
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiProviderMetadata {
    pub kind: AiProviderKind,
    pub display_name: String,
    pub description: Option<String>,
    pub supports_custom_base_url: bool,
    pub supports_connection_test: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiConnectionConfig {
    pub base_url: Option<String>,
    pub api_key_env_var: Option<String>,
    pub api_key_file_name: Option<String>,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub custom_headers: Vec<(String, String)>,
}

impl Default for AiConnectionConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            api_key_env_var: None,
            api_key_file_name: None,
            organization_id: None,
            project_id: None,
            custom_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModelDescriptor {
    pub id: String,
    pub display_name: String,
    pub context_window_tokens: Option<u32>,
    pub supports_streaming: bool,
    pub supports_json_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultModelSelection {
    ProviderDefault,
    ExplicitModel,
    LastUsedPerProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModelPreferences {
    pub default_selection: DefaultModelSelection,
    pub explicit_default_model_id: Option<String>,
    pub remember_last_selected_model_per_provider: bool,
}

impl Default for AiModelPreferences {
    fn default() -> Self {
        Self {
            default_selection: DefaultModelSelection::ProviderDefault,
            explicit_default_model_id: None,
            remember_last_selected_model_per_provider: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiProviderConfig {
    pub metadata: AiProviderMetadata,
    pub connection: AiConnectionConfig,
    pub available_models: Vec<AiModelDescriptor>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSettings {
    #[serde(default)]
    pub selected_provider: AiProviderKind,
    #[serde(default)]
    pub provider_configs: Vec<AiProviderConfig>,
    #[serde(default)]
    pub model_preferences: AiModelPreferences,
    #[serde(default)]
    pub last_selected_model_by_provider: Vec<(AiProviderKind, String)>,
    #[serde(default)]
    pub storage_mode: AiSecretStorageMode,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            selected_provider: AiProviderKind::NoneSelected,
            provider_configs: Vec::new(),
            model_preferences: AiModelPreferences::default(),
            last_selected_model_by_provider: Vec::new(),
            storage_mode: AiSecretStorageMode::InternalEncryptedStorage,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiConnectionTestResult {
    pub provider: AiProviderKind,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub message: String,
    pub resolved_model_id: Option<String>,
}
