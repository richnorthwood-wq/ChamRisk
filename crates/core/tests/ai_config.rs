use chamrisk_core::ai::{
    AiConnectionConfig, AiModelPreferences, AiProviderKind, AiSecretStorageMode, AiSettings,
    DefaultModelSelection,
};

#[test]
fn default_ai_settings_construction_is_empty_and_provider_neutral() {
    let settings = AiSettings::default();

    assert_eq!(settings.selected_provider, AiProviderKind::NoneSelected);
    assert!(settings.provider_configs.is_empty());
    assert!(settings.last_selected_model_by_provider.is_empty());
    assert_eq!(
        settings.model_preferences,
        AiModelPreferences {
            default_selection: DefaultModelSelection::ProviderDefault,
            explicit_default_model_id: None,
            remember_last_selected_model_per_provider: true,
        }
    );
    assert_eq!(
        settings.storage_mode,
        AiSecretStorageMode::InternalEncryptedStorage
    );
}

#[test]
fn provider_kind_serde_round_trip_uses_snake_case() {
    let encoded = serde_json::to_string(&AiProviderKind::OpenAi).expect("serialize provider kind");
    assert_eq!(encoded, "\"open_ai\"");

    let decoded: AiProviderKind =
        serde_json::from_str(&encoded).expect("deserialize provider kind");
    assert_eq!(decoded, AiProviderKind::OpenAi);
}

#[test]
fn anthropic_provider_kind_serde_round_trip_uses_snake_case() {
    let encoded =
        serde_json::to_string(&AiProviderKind::Anthropic).expect("serialize provider kind");
    assert_eq!(encoded, "\"anthropic\"");

    let decoded: AiProviderKind =
        serde_json::from_str(&encoded).expect("deserialize provider kind");
    assert_eq!(decoded, AiProviderKind::Anthropic);
}

#[test]
fn model_preference_persistence_shape_is_stable() {
    let settings = AiSettings {
        model_preferences: AiModelPreferences {
            default_selection: DefaultModelSelection::LastUsedPerProvider,
            explicit_default_model_id: Some("gpt-4.1-mini".to_string()),
            remember_last_selected_model_per_provider: true,
        },
        last_selected_model_by_provider: vec![
            (AiProviderKind::OpenAi, "gpt-4.1-mini".to_string()),
            (AiProviderKind::Anthropic, "claude-3-7-sonnet".to_string()),
        ],
        ..AiSettings::default()
    };

    let json = serde_json::to_value(&settings).expect("serialize settings");
    assert_eq!(
        json["model_preferences"]["default_selection"],
        "last_used_per_provider"
    );
    assert_eq!(
        json["model_preferences"]["explicit_default_model_id"],
        "gpt-4.1-mini"
    );
    assert_eq!(
        json["model_preferences"]["remember_last_selected_model_per_provider"],
        true
    );
    assert_eq!(json["last_selected_model_by_provider"][0][0], "open_ai");
    assert_eq!(
        json["last_selected_model_by_provider"][0][1],
        "gpt-4.1-mini"
    );
    assert_eq!(json["storage_mode"], "internal_encrypted_storage");
}

#[test]
fn connection_config_defaults_to_empty_optional_values() {
    let config = AiConnectionConfig::default();

    assert!(config.base_url.is_none());
    assert!(config.api_key_env_var.is_none());
    assert!(config.api_key_file_name.is_none());
    assert!(config.organization_id.is_none());
    assert!(config.project_id.is_none());
    assert!(config.custom_headers.is_empty());
}

#[test]
fn anthropic_provider_config_persistence_shape_is_stable() {
    let settings = AiSettings {
        selected_provider: AiProviderKind::Anthropic,
        provider_configs: vec![chamrisk_core::ai::AiProviderConfig {
            metadata: chamrisk_core::ai::AiProviderMetadata {
                kind: AiProviderKind::Anthropic,
                display_name: "Anthropic".to_string(),
                description: Some("Default Anthropic configuration.".to_string()),
                supports_custom_base_url: false,
                supports_connection_test: true,
            },
            connection: AiConnectionConfig {
                base_url: Some("https://api.anthropic.com".to_string()),
                api_key_env_var: Some("ANTHROPIC_API_KEY".to_string()),
                api_key_file_name: Some("anthropic_default".to_string()),
                organization_id: None,
                project_id: None,
                custom_headers: Vec::new(),
            },
            available_models: vec![chamrisk_core::ai::AiModelDescriptor {
                id: "claude-3-7-sonnet-latest".to_string(),
                display_name: "Claude 3.7 Sonnet".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            }],
            enabled: true,
        }],
        ..AiSettings::default()
    };

    let json = serde_json::to_value(&settings).expect("serialize anthropic settings");
    assert_eq!(json["selected_provider"], "anthropic");
    assert_eq!(
        json["provider_configs"][0]["metadata"]["display_name"],
        "Anthropic"
    );
    assert_eq!(
        json["provider_configs"][0]["metadata"]["supports_custom_base_url"],
        false
    );
    assert_eq!(
        json["provider_configs"][0]["metadata"]["supports_connection_test"],
        true
    );
    assert_eq!(
        json["provider_configs"][0]["connection"]["api_key_file_name"],
        "anthropic_default"
    );
    assert_eq!(json["provider_configs"][0]["enabled"], true);
}
