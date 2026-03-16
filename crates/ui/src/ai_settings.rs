use chamrisk_core::ai::{
    AiConnectionConfig, AiModelDescriptor, AiModelPreferences, AiProviderConfig, AiProviderKind,
    AiProviderMetadata, AiSecretStorageMode, AiSettings, DefaultModelSelection,
};
use std::fs;
use std::path::{Path, PathBuf};

const AI_SETTINGS_FILE_NAME: &str = "ai_settings.json";

pub fn ai_settings_path() -> Result<PathBuf, String> {
    Ok(crate::settings::config_dir()?.join(AI_SETTINGS_FILE_NAME))
}

pub fn default_ai_settings() -> AiSettings {
    AiSettings {
        selected_provider: AiProviderKind::NoneSelected,
        provider_configs: vec![
            AiProviderConfig {
                metadata: AiProviderMetadata {
                    kind: AiProviderKind::OpenAi,
                    display_name: "OpenAI".to_string(),
                    description: Some("Default OpenAI configuration.".to_string()),
                    supports_custom_base_url: true,
                    supports_connection_test: true,
                },
                connection: AiConnectionConfig {
                    base_url: Some("https://api.openai.com".to_string()),
                    api_key_env_var: Some("OPENAI_API_KEY".to_string()),
                    api_key_file_name: Some("openai_default".to_string()),
                    organization_id: None,
                    project_id: None,
                    custom_headers: Vec::new(),
                },
                available_models: vec![AiModelDescriptor {
                    id: "gpt-4.1-mini".to_string(),
                    display_name: "GPT-4.1 Mini".to_string(),
                    context_window_tokens: None,
                    supports_streaming: false,
                    supports_json_mode: true,
                }],
                enabled: true,
            },
            AiProviderConfig {
                metadata: AiProviderMetadata {
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
                available_models: vec![AiModelDescriptor {
                    id: "claude-3-7-sonnet-latest".to_string(),
                    display_name: "Claude 3.7 Sonnet".to_string(),
                    context_window_tokens: None,
                    supports_streaming: false,
                    supports_json_mode: false,
                }],
                enabled: true,
            },
        ],
        model_preferences: AiModelPreferences {
            default_selection: DefaultModelSelection::ProviderDefault,
            explicit_default_model_id: None,
            remember_last_selected_model_per_provider: true,
        },
        last_selected_model_by_provider: Vec::new(),
        storage_mode: AiSecretStorageMode::InternalEncryptedStorage,
    }
}

fn normalize_ai_settings(settings: &mut AiSettings) -> bool {
    let mut changed = false;

    if !settings
        .provider_configs
        .iter()
        .any(|config| config.metadata.kind == AiProviderKind::OpenAi)
    {
        settings
            .provider_configs
            .push(default_ai_settings().provider_configs[0].clone());
        changed = true;
    }

    if !settings
        .provider_configs
        .iter()
        .any(|config| config.metadata.kind == AiProviderKind::Anthropic)
    {
        settings
            .provider_configs
            .push(default_ai_settings().provider_configs[1].clone());
        changed = true;
    }

    changed
}

pub fn load_ai_settings() -> AiSettings {
    let Ok(path) = ai_settings_path() else {
        return default_ai_settings();
    };
    load_ai_settings_from_path(&path)
}

pub fn save_ai_settings(settings: &AiSettings) -> Result<(), String> {
    let path = ai_settings_path()?;
    save_ai_settings_to_path(&path, settings)
}

pub(crate) fn load_ai_settings_from_path(path: &Path) -> AiSettings {
    let Ok(raw) = fs::read_to_string(path) else {
        return default_ai_settings();
    };

    let mut settings =
        serde_json::from_str::<AiSettings>(&raw).unwrap_or_else(|_| default_ai_settings());
    let _ = normalize_ai_settings(&mut settings);
    settings
}

pub(crate) fn save_ai_settings_to_path(path: &Path, settings: &AiSettings) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("ai settings path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "failed to create ai settings dir {}: {err}",
            parent.display()
        )
    })?;
    let payload = serde_json::to_string_pretty(settings)
        .map_err(|err| format!("failed to serialize ai settings: {err}"))?;
    fs::write(path, payload)
        .map_err(|err| format!("failed to write ai settings file {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        default_ai_settings, load_ai_settings_from_path, save_ai_settings_to_path,
        AI_SETTINGS_FILE_NAME,
    };
    use chamrisk_core::ai::{AiProviderKind, AiSecretStorageMode, DefaultModelSelection};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn missing_file_returns_defaults() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join(AI_SETTINGS_FILE_NAME);

        let settings = load_ai_settings_from_path(&path);

        assert_eq!(settings, default_ai_settings());
        assert_eq!(settings.selected_provider, AiProviderKind::NoneSelected);
        assert_eq!(
            settings.storage_mode,
            AiSecretStorageMode::InternalEncryptedStorage
        );
        assert_eq!(settings.provider_configs.len(), 2);
        assert_eq!(
            settings.provider_configs[0].metadata.kind,
            AiProviderKind::OpenAi
        );
        assert_eq!(
            settings.provider_configs[1].metadata.kind,
            AiProviderKind::Anthropic
        );
        assert_eq!(
            settings.provider_configs[0]
                .connection
                .api_key_file_name
                .as_deref(),
            Some("openai_default")
        );
    }

    #[test]
    fn save_then_load_round_trip_preserves_non_secret_ai_settings() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join(AI_SETTINGS_FILE_NAME);
        let mut settings = default_ai_settings();
        settings.storage_mode = AiSecretStorageMode::LocalFileStorage;
        settings.model_preferences.default_selection = DefaultModelSelection::ExplicitModel;
        settings.model_preferences.explicit_default_model_id = Some("gpt-4.1-mini".to_string());
        settings.last_selected_model_by_provider =
            vec![(AiProviderKind::OpenAi, "gpt-4.1-mini".to_string())];

        save_ai_settings_to_path(&path, &settings).expect("save ai settings");
        let loaded = load_ai_settings_from_path(&path);

        assert_eq!(loaded, settings);
        let raw = fs::read_to_string(&path).expect("read ai settings file");
        assert!(!raw.contains("sk-"));
        assert!(!raw.contains("\"secret\""));
    }

    #[test]
    fn storage_mode_round_trip_persists_across_reload() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join(AI_SETTINGS_FILE_NAME);
        let mut settings = default_ai_settings();
        settings.storage_mode = AiSecretStorageMode::LocalFileStorage;

        save_ai_settings_to_path(&path, &settings).expect("save ai settings");
        let loaded = load_ai_settings_from_path(&path);

        assert_eq!(loaded.storage_mode, AiSecretStorageMode::LocalFileStorage);
    }

    #[test]
    fn malformed_json_returns_defaults() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join(AI_SETTINGS_FILE_NAME);
        fs::write(&path, "{ not valid json").expect("write malformed ai settings");

        let settings = load_ai_settings_from_path(&path);

        assert_eq!(settings, default_ai_settings());
    }

    #[test]
    fn default_json_shape_has_no_provider_selected_and_no_raw_secret_fields() {
        let settings = default_ai_settings();
        let json = serde_json::to_value(&settings).expect("serialize ai settings");

        assert_eq!(json["selected_provider"], "none_selected");
        assert_eq!(
            json["provider_configs"][0]["metadata"]["display_name"],
            "OpenAI"
        );
        assert_eq!(
            json["provider_configs"][0]["connection"]["api_key_file_name"],
            "openai_default"
        );
        assert_eq!(
            json["provider_configs"][1]["metadata"]["display_name"],
            "Anthropic"
        );
        assert_eq!(json["provider_configs"][1]["metadata"]["kind"], "anthropic");
        assert_eq!(
            json["provider_configs"][1]["connection"]["api_key_file_name"],
            "anthropic_default"
        );
        assert_eq!(
            json["model_preferences"]["default_selection"],
            "provider_default"
        );
        assert_eq!(json["storage_mode"], "internal_encrypted_storage");
        assert!(json.get("api_key").is_none());
    }

    #[test]
    fn missing_selected_provider_migrates_to_none_selected() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join(AI_SETTINGS_FILE_NAME);
        fs::write(
            &path,
            r#"{
  "provider_configs": [],
  "model_preferences": {
    "default_selection": "provider_default",
    "explicit_default_model_id": null,
    "remember_last_selected_model_per_provider": true
  },
  "last_selected_model_by_provider": []
}"#,
        )
        .expect("write ai settings without selected provider");

        let settings = load_ai_settings_from_path(&path);

        assert_eq!(settings.selected_provider, AiProviderKind::NoneSelected);
        assert_eq!(
            settings.storage_mode,
            AiSecretStorageMode::InternalEncryptedStorage
        );
    }
}
