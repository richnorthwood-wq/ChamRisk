use crate::ai::providers::anthropic::AnthropicProvider;
use crate::ai::providers::openai::OpenAiProvider;
use chamrisk_core::ai::{AiProvider, AiProviderConfig, AiProviderKind};

pub fn provider_for_config(config: &AiProviderConfig) -> Option<Box<dyn AiProvider>> {
    match config.metadata.kind {
        AiProviderKind::NoneSelected => None,
        AiProviderKind::OpenAi => Some(Box::new(OpenAiProvider::new(config.clone()))),
        AiProviderKind::Anthropic => Some(Box::new(AnthropicProvider::new(config.clone()))),
        AiProviderKind::Custom => None,
    }
}

pub fn provider_for_kind(
    kind: AiProviderKind,
    config: AiProviderConfig,
) -> Option<Box<dyn AiProvider>> {
    if config.metadata.kind != kind {
        return None;
    }
    provider_for_config(&config)
}

#[cfg(test)]
mod tests {
    use super::provider_for_config;
    use crate::api::default_provider_config;
    use chamrisk_core::ai::AiProviderKind;

    #[test]
    fn registry_returns_openai_provider() {
        let config = default_provider_config(AiProviderKind::OpenAi);

        let provider = provider_for_config(&config).expect("openai provider");

        assert_eq!(provider.kind(), AiProviderKind::OpenAi);
        assert_eq!(provider.metadata().display_name, "OpenAI");
    }

    #[test]
    fn registry_returns_anthropic_provider() {
        let config = default_provider_config(AiProviderKind::Anthropic);

        let provider = provider_for_config(&config).expect("anthropic provider");

        assert_eq!(provider.kind(), AiProviderKind::Anthropic);
        assert_eq!(provider.metadata().display_name, "Anthropic");
    }
}
