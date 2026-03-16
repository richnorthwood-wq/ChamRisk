use crate::ai::config::{
    AiConnectionConfig, AiConnectionTestResult, AiModelDescriptor, AiProviderMetadata,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    NoneSelected,
    OpenAi,
    Anthropic,
    Custom,
}

impl Default for AiProviderKind {
    fn default() -> Self {
        Self::NoneSelected
    }
}

pub trait AiProvider: Send + Sync {
    fn kind(&self) -> AiProviderKind;
    fn metadata(&self) -> AiProviderMetadata;
    fn connection_config(&self) -> &AiConnectionConfig;
    fn available_models(&self) -> &[AiModelDescriptor];
    fn validate_config(&self) -> Result<(), String>;
    fn test_connection(
        &self,
        resolved_api_key: Option<&str>,
    ) -> Result<AiConnectionTestResult, String>;
    fn list_models(&self, resolved_api_key: Option<&str>)
        -> Result<Vec<AiModelDescriptor>, String>;
    fn run_triage(
        &self,
        resolved_api_key: Option<&str>,
        model_id: &str,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, String>;
}
