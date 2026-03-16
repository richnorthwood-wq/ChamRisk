use crate::ai::provider::AiProviderKind;

pub trait SecretResolver {
    fn read_secret(&self, secret_ref: &str) -> Result<Option<String>, String>;
    fn write_secret(&self, secret_ref: &str, secret_value: &str) -> Result<(), String>;
    fn delete_secret(&self, secret_ref: &str) -> Result<(), String>;

    fn resolve_api_key(&self, provider: AiProviderKind) -> Result<Option<String>, String> {
        let secret_ref = match provider {
            AiProviderKind::NoneSelected => return Ok(None),
            AiProviderKind::OpenAi => "openai_default",
            AiProviderKind::Anthropic => "anthropic_default",
            AiProviderKind::Custom => "custom_default",
        };
        self.read_secret(secret_ref)
    }
}
