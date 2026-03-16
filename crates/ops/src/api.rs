use crate::ai_secrets::{resolver_for_ai_settings_with_root, SecretServiceSecretResolver};
use crate::provider_registry::provider_for_config;
use chamrisk_core::ai::{
    AiConnectionConfig, AiModelDescriptor, AiModelPreferences, AiProvider, AiProviderConfig,
    AiProviderKind, AiProviderMetadata, AiSecretStorageMode, AiSettings, DefaultModelSelection,
    SecretResolver,
};
use std::fs;
use std::path::{Path, PathBuf};

const OPENAI_ENV_VAR: &str = "OPENAI_API_KEY";
const AI_SETTINGS_FILE_NAME: &str = "ai_settings.json";
const LEGACY_OPENAI_KEY_FILE_NAME: &str = "openai_key";
const OPENAI_SECRET_REF: &str = "openai_default";
const ANTHROPIC_ENV_VAR: &str = "ANTHROPIC_API_KEY";
const ANTHROPIC_SECRET_REF: &str = "anthropic_default";
const NO_API_KEY_CONFIGURED_MESSAGE: &str = "no API key configured for selected provider";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAiRuntimeConfig {
    pub provider_kind: AiProviderKind,
    pub model_id: String,
    pub base_url: String,
    pub api_key: String,
}

fn validate_key(k: String) -> Result<String, String> {
    let k = k.trim().to_string();
    if k.starts_with("sk-") && k.len() >= 20 {
        Ok(k)
    } else {
        Err("AI API key looks invalid".to_string())
    }
}

fn config_root() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Ok(PathBuf::from(home).join(".config").join("chamrisk"))
}

fn ai_settings_path(root: &Path) -> PathBuf {
    root.join(AI_SETTINGS_FILE_NAME)
}

fn legacy_openai_key_path(root: &Path) -> PathBuf {
    root.join(LEGACY_OPENAI_KEY_FILE_NAME)
}

pub(crate) fn default_provider_config(kind: AiProviderKind) -> AiProviderConfig {
    match kind {
        AiProviderKind::NoneSelected => AiProviderConfig {
            metadata: AiProviderMetadata {
                kind,
                display_name: "No API Selected".to_string(),
                description: Some("AI is disabled for this install.".to_string()),
                supports_custom_base_url: false,
                supports_connection_test: false,
            },
            connection: AiConnectionConfig::default(),
            available_models: Vec::new(),
            enabled: false,
        },
        AiProviderKind::OpenAi => AiProviderConfig {
            metadata: AiProviderMetadata {
                kind,
                display_name: "OpenAI".to_string(),
                description: Some("Default OpenAI configuration.".to_string()),
                supports_custom_base_url: true,
                supports_connection_test: true,
            },
            connection: AiConnectionConfig {
                base_url: Some("https://api.openai.com".to_string()),
                api_key_env_var: Some(OPENAI_ENV_VAR.to_string()),
                api_key_file_name: Some(OPENAI_SECRET_REF.to_string()),
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
        AiProviderKind::Anthropic => AiProviderConfig {
            metadata: AiProviderMetadata {
                kind,
                display_name: "Anthropic".to_string(),
                description: Some("Default Anthropic configuration.".to_string()),
                supports_custom_base_url: false,
                supports_connection_test: true,
            },
            connection: AiConnectionConfig {
                base_url: Some("https://api.anthropic.com".to_string()),
                api_key_env_var: Some(ANTHROPIC_ENV_VAR.to_string()),
                api_key_file_name: Some(ANTHROPIC_SECRET_REF.to_string()),
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
        AiProviderKind::Custom => AiProviderConfig {
            metadata: AiProviderMetadata {
                kind,
                display_name: "Custom".to_string(),
                description: Some("Custom provider configuration.".to_string()),
                supports_custom_base_url: true,
                supports_connection_test: false,
            },
            connection: AiConnectionConfig::default(),
            available_models: Vec::new(),
            enabled: false,
        },
    }
}

fn default_ai_settings() -> AiSettings {
    AiSettings {
        selected_provider: AiProviderKind::NoneSelected,
        provider_configs: vec![
            default_provider_config(AiProviderKind::OpenAi),
            default_provider_config(AiProviderKind::Anthropic),
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

fn load_ai_settings_from_path(path: &Path) -> AiSettings {
    let Ok(raw) = fs::read_to_string(path) else {
        return default_ai_settings();
    };
    serde_json::from_str::<AiSettings>(&raw).unwrap_or_else(|_| default_ai_settings())
}

fn save_ai_settings_to_path(path: &Path, settings: &AiSettings) -> Result<(), String> {
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

fn current_provider_config_mut(settings: &mut AiSettings) -> Option<&mut AiProviderConfig> {
    let selected_provider = settings.selected_provider;
    settings
        .provider_configs
        .iter_mut()
        .find(|config| config.metadata.kind == selected_provider)
}

fn current_provider_config(settings: &AiSettings) -> Option<&AiProviderConfig> {
    let selected_provider = settings.selected_provider;
    settings
        .provider_configs
        .iter()
        .find(|config| config.metadata.kind == selected_provider)
}

fn normalize_ai_settings(settings: &mut AiSettings) -> bool {
    let mut changed = false;

    if settings.selected_provider != AiProviderKind::NoneSelected
        && current_provider_config(settings).is_none()
    {
        settings
            .provider_configs
            .push(default_provider_config(settings.selected_provider));
        changed = true;
    }

    match settings.selected_provider {
        AiProviderKind::NoneSelected => {}
        AiProviderKind::OpenAi => {
            if let Some(config) = current_provider_config_mut(settings) {
                if config.connection.base_url.is_none() {
                    config.connection.base_url = Some("https://api.openai.com".to_string());
                    changed = true;
                }
                if config.connection.api_key_env_var.is_none() {
                    config.connection.api_key_env_var = Some(OPENAI_ENV_VAR.to_string());
                    changed = true;
                }
                if config.connection.api_key_file_name.is_none() {
                    config.connection.api_key_file_name = Some(OPENAI_SECRET_REF.to_string());
                    changed = true;
                }
                if config.available_models.is_empty() {
                    config.available_models =
                        default_provider_config(AiProviderKind::OpenAi).available_models;
                    changed = true;
                }
            }
        }
        AiProviderKind::Anthropic => {
            if let Some(config) = current_provider_config_mut(settings) {
                if config.connection.base_url.is_none() {
                    config.connection.base_url = Some("https://api.anthropic.com".to_string());
                    changed = true;
                }
                if config.connection.api_key_env_var.is_none() {
                    config.connection.api_key_env_var = Some(ANTHROPIC_ENV_VAR.to_string());
                    changed = true;
                }
                if config.connection.api_key_file_name.is_none() {
                    config.connection.api_key_file_name = Some(ANTHROPIC_SECRET_REF.to_string());
                    changed = true;
                }
                if config.available_models.is_empty() {
                    config.available_models =
                        default_provider_config(AiProviderKind::Anthropic).available_models;
                    changed = true;
                }
            }
        }
        AiProviderKind::Custom => {}
    }

    changed
}

fn migrate_legacy_openai_key_if_needed<R>(
    root: &Path,
    settings: &mut AiSettings,
    resolver: &SecretServiceSecretResolver<R>,
) -> Result<bool, String>
where
    R: crate::ai_secrets::SecureStoreBackend,
{
    let mut changed = false;
    if let Some(config) = settings
        .provider_configs
        .iter_mut()
        .find(|config| config.metadata.kind == AiProviderKind::OpenAi)
    {
        if config.connection.api_key_file_name.is_none() {
            config.connection.api_key_file_name = Some(OPENAI_SECRET_REF.to_string());
            changed = true;
        }
    }

    let migrated =
        resolver.import_plaintext_secret_file(OPENAI_SECRET_REF, legacy_openai_key_path(root))?;
    Ok(changed || migrated)
}

fn migrate_plaintext_secret_files_if_needed<R>(
    root: &Path,
    settings: &mut AiSettings,
    resolver: &SecretServiceSecretResolver<R>,
) -> Result<bool, String>
where
    R: crate::ai_secrets::SecureStoreBackend,
{
    let mut changed = false;
    for config in &mut settings.provider_configs {
        let provider = config.metadata.kind;
        if config.connection.api_key_file_name.is_none() {
            let default_secret_ref = match provider {
                AiProviderKind::NoneSelected => None,
                AiProviderKind::OpenAi => Some(OPENAI_SECRET_REF),
                AiProviderKind::Anthropic => Some(ANTHROPIC_SECRET_REF),
                AiProviderKind::Custom => None,
            };
            if let Some(secret_ref) = default_secret_ref {
                config.connection.api_key_file_name = Some(secret_ref.to_string());
                changed = true;
            }
        }

        let Some(secret_ref) = config
            .connection
            .api_key_file_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let migrated = resolver
            .import_plaintext_secret_file(secret_ref, root.join("secrets").join(secret_ref))?;
        changed |= migrated;
    }
    Ok(changed)
}

#[cfg(test)]
fn load_and_migrate_ai_settings_with_root<R>(
    root: &Path,
    resolver: &SecretServiceSecretResolver<R>,
) -> Result<AiSettings, String>
where
    R: crate::ai_secrets::SecureStoreBackend,
{
    let path = ai_settings_path(root);
    let mut settings = load_ai_settings_from_path(&path);
    let mut changed = normalize_ai_settings(&mut settings);
    changed |= migrate_plaintext_secret_files_if_needed(root, &mut settings, resolver)?;
    changed |= migrate_legacy_openai_key_if_needed(root, &mut settings, resolver)?;
    if changed {
        save_ai_settings_to_path(&path, &settings)?;
    }
    Ok(settings)
}

fn load_active_ai_settings_with_root(root: &Path) -> Result<AiSettings, String> {
    let path = ai_settings_path(root);
    let mut settings = load_ai_settings_from_path(&path);
    let mut changed = normalize_ai_settings(&mut settings);

    if settings.storage_mode == AiSecretStorageMode::InternalEncryptedStorage {
        let resolver = SecretServiceSecretResolver::with_legacy_root_dir(root);
        changed |= migrate_plaintext_secret_files_if_needed(root, &mut settings, &resolver)?;
        changed |= migrate_legacy_openai_key_if_needed(root, &mut settings, &resolver)?;
    }

    if changed {
        save_ai_settings_to_path(&path, &settings)?;
    }

    Ok(settings)
}

fn resolve_model_id_from_settings(settings: &AiSettings) -> Result<String, String> {
    let provider = settings.selected_provider;
    if provider == AiProviderKind::NoneSelected {
        return Err("no AI provider selected".to_string());
    }
    let provider_config = current_provider_config(settings)
        .ok_or_else(|| format!("selected AI provider is not configured: {provider:?}"))?;

    let first_model = provider_config
        .available_models
        .first()
        .map(|model| model.id.clone());

    match settings.model_preferences.default_selection {
        DefaultModelSelection::ProviderDefault => first_model
            .ok_or_else(|| format!("no default model configured for provider: {provider:?}")),
        DefaultModelSelection::ExplicitModel => settings
            .model_preferences
            .explicit_default_model_id
            .clone()
            .or(first_model)
            .ok_or_else(|| format!("no explicit model configured for provider: {provider:?}")),
        DefaultModelSelection::LastUsedPerProvider => settings
            .last_selected_model_by_provider
            .iter()
            .find(|(kind, _)| *kind == provider)
            .map(|(_, model_id)| model_id.clone())
            .or_else(|| settings.model_preferences.explicit_default_model_id.clone())
            .or(first_model)
            .ok_or_else(|| format!("no remembered model configured for provider: {provider:?}")),
    }
}

fn resolve_api_key_for_settings_with_env_and_resolver<R>(
    settings: &AiSettings,
    resolver: &R,
    env_lookup: impl FnOnce(&str) -> Option<String>,
) -> Result<String, String>
where
    R: SecretResolver,
{
    let provider = settings.selected_provider;
    if provider == AiProviderKind::NoneSelected {
        return Err("no AI provider selected".to_string());
    }
    let connection = current_provider_config(settings)
        .ok_or_else(|| format!("selected AI provider is not configured: {provider:?}"))?
        .connection
        .clone();

    if let Some(env_var) = connection
        .api_key_env_var
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(env_value) = env_lookup(env_var) {
            if !env_value.trim().is_empty() {
                return validate_key(env_value);
            }
        }
    }

    let secret_ref = connection
        .api_key_file_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| NO_API_KEY_CONFIGURED_MESSAGE.to_string())?;
    let key = resolver
        .read_secret(secret_ref)?
        .ok_or_else(|| NO_API_KEY_CONFIGURED_MESSAGE.to_string())?;
    validate_key(key)
}

pub(crate) fn is_no_api_key_configured_error(err: &str) -> bool {
    err.trim() == NO_API_KEY_CONFIGURED_MESSAGE
}

#[cfg(test)]
fn resolve_api_key_with_root_and_env_and_resolver<R>(
    root: &Path,
    resolver: &SecretServiceSecretResolver<R>,
    env_override: Option<&str>,
) -> Result<String, String>
where
    R: crate::ai_secrets::SecureStoreBackend,
{
    let settings = load_and_migrate_ai_settings_with_root(root, resolver)?;
    resolve_api_key_for_settings_with_env_and_resolver(&settings, resolver, |env_name| {
        if env_name == OPENAI_ENV_VAR {
            env_override.map(|value| value.to_string())
        } else {
            std::env::var(env_name).ok()
        }
    })
}

pub(crate) fn active_provider_with_root(root: &Path) -> Result<Box<dyn AiProvider>, String> {
    let settings = load_active_ai_settings_with_root(root)?;
    if settings.selected_provider == AiProviderKind::NoneSelected {
        return Err("no AI provider selected".to_string());
    }
    let config = current_provider_config(&settings)
        .ok_or_else(|| {
            format!(
                "selected AI provider is not configured: {:?}",
                settings.selected_provider
            )
        })?
        .clone();
    provider_for_config(&config).ok_or_else(|| {
        format!(
            "no provider adapter is registered for selected provider: {:?}",
            settings.selected_provider
        )
    })
}

pub(crate) fn active_provider() -> Result<Box<dyn AiProvider>, String> {
    active_provider_with_root(&config_root()?)
}

pub fn current_provider_kind() -> Result<AiProviderKind, String> {
    Ok(active_provider_with_root(&config_root()?)?.kind())
}

pub fn ai_enabled() -> Result<bool, String> {
    let settings = load_ai_settings_from_path(&ai_settings_path(&config_root()?));
    Ok(settings.selected_provider != AiProviderKind::NoneSelected)
}

pub fn current_provider_connection_config() -> Result<AiConnectionConfig, String> {
    Ok(active_provider_with_root(&config_root()?)?
        .connection_config()
        .clone())
}

fn resolved_ai_runtime_config_for_settings_and_resolver<R>(
    settings: &AiSettings,
    resolver: &R,
    env_lookup: impl FnOnce(&str) -> Option<String>,
) -> Result<ResolvedAiRuntimeConfig, String>
where
    R: SecretResolver,
{
    if settings.selected_provider == AiProviderKind::NoneSelected {
        return Err("no AI provider selected".to_string());
    }
    let config = current_provider_config(&settings)
        .ok_or_else(|| {
            format!(
                "selected AI provider is not configured: {:?}",
                settings.selected_provider
            )
        })?
        .clone();
    let provider = provider_for_config(&config).ok_or_else(|| {
        format!(
            "no provider adapter is registered for selected provider: {:?}",
            settings.selected_provider
        )
    })?;
    let provider_kind = provider.kind();
    provider.validate_config()?;
    let api_key =
        resolve_api_key_for_settings_with_env_and_resolver(settings, resolver, env_lookup)?;
    let model_id = resolve_model_id_from_settings(&settings)?;
    if !config
        .available_models
        .iter()
        .any(|descriptor| descriptor.id == model_id)
    {
        return Err(format!(
            "resolved model is not available from provider: {model_id}"
        ));
    }
    let base_url = provider
        .connection_config()
        .base_url
        .clone()
        .ok_or_else(|| {
            if provider_kind == AiProviderKind::Custom {
                "no base URL configured for custom AI provider".to_string()
            } else {
                format!("no base URL configured for selected provider: {provider_kind:?}")
            }
        })?;

    Ok(ResolvedAiRuntimeConfig {
        provider_kind,
        model_id,
        base_url,
        api_key,
    })
}

#[cfg(test)]
fn resolved_ai_runtime_config_with_root_and_resolver<R>(
    root: &Path,
    resolver: &R,
    env_lookup: impl FnOnce(&str) -> Option<String>,
) -> Result<ResolvedAiRuntimeConfig, String>
where
    R: SecretResolver,
{
    let settings = load_active_ai_settings_with_root(root)?;
    resolved_ai_runtime_config_for_settings_and_resolver(&settings, resolver, env_lookup)
}

fn resolved_ai_runtime_config_with_root(
    root: &Path,
    env_lookup: impl FnOnce(&str) -> Option<String>,
) -> Result<ResolvedAiRuntimeConfig, String> {
    let settings = load_active_ai_settings_with_root(root)?;
    let resolver = resolver_for_ai_settings_with_root(&settings, root);
    resolved_ai_runtime_config_for_settings_and_resolver(&settings, &resolver, env_lookup)
}

pub fn resolved_ai_runtime_config() -> Result<ResolvedAiRuntimeConfig, String> {
    let root = config_root()?;
    resolved_ai_runtime_config_with_root(&root, |env_name| std::env::var(env_name).ok())
}

pub fn resolved_model() -> Result<String, String> {
    Ok(resolved_ai_runtime_config()?.model_id)
}

pub fn base_url() -> Result<String, String> {
    Ok(resolved_ai_runtime_config()?.base_url)
}

pub fn api_key() -> Result<String, String> {
    Ok(resolved_ai_runtime_config()?.api_key)
}

#[cfg(test)]
mod tests {
    use super::{
        ai_settings_path, default_ai_settings, legacy_openai_key_path, load_ai_settings_from_path,
        resolve_api_key_for_settings_with_env_and_resolver,
        resolve_api_key_with_root_and_env_and_resolver, resolve_model_id_from_settings,
        resolved_ai_runtime_config_with_root_and_resolver, save_ai_settings_to_path,
    };
    use crate::ai_secrets::{
        resolver_for_ai_settings_with_root, LocalFileSecretResolver, SecretServiceSecretResolver,
        SecureStoreBackend,
    };
    use chamrisk_core::ai::{
        AiConnectionConfig, AiModelDescriptor, AiProviderConfig, AiProviderKind,
        AiProviderMetadata, AiSecretStorageMode, AiSettings, DefaultModelSelection, SecretResolver,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[derive(Debug, Default)]
    struct FakeSecureBackend {
        secrets: RefCell<HashMap<String, String>>,
        unavailable: bool,
    }

    impl Clone for FakeSecureBackend {
        fn clone(&self) -> Self {
            Self {
                secrets: RefCell::new(self.secrets.borrow().clone()),
                unavailable: self.unavailable,
            }
        }
    }

    impl SecureStoreBackend for FakeSecureBackend {
        fn lookup(&self, secret_ref: &str) -> Result<Option<String>, String> {
            if self.unavailable {
                return Err("secure secret store unavailable".to_string());
            }
            Ok(self.secrets.borrow().get(secret_ref).cloned())
        }

        fn store(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
            if self.unavailable {
                return Err("secure secret store unavailable".to_string());
            }
            self.secrets
                .borrow_mut()
                .insert(secret_ref.to_string(), secret_value.to_string());
            Ok(())
        }

        fn clear(&self, secret_ref: &str) -> Result<(), String> {
            if self.unavailable {
                return Err("secure secret store unavailable".to_string());
            }
            self.secrets.borrow_mut().remove(secret_ref);
            Ok(())
        }
    }

    fn test_resolver(root: &std::path::Path) -> SecretServiceSecretResolver<FakeSecureBackend> {
        SecretServiceSecretResolver::with_backend_and_legacy_root_dir(
            FakeSecureBackend::default(),
            root,
        )
    }

    #[test]
    fn legacy_key_is_imported_into_new_secret_store() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        fs::create_dir_all(&root).expect("create root");
        let resolver = test_resolver(&root);
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");
        fs::write(
            legacy_openai_key_path(&root),
            "sk-legacy-imported-key-12345",
        )
        .expect("write legacy key");

        let key = resolve_api_key_with_root_and_env_and_resolver(&root, &resolver, None)
            .expect("resolve key");

        assert_eq!(key, "sk-legacy-imported-key-12345");
        assert_eq!(
            resolver
                .read_secret("openai_default")
                .expect("read imported secret")
                .as_deref(),
            Some("sk-legacy-imported-key-12345")
        );
        assert!(!legacy_openai_key_path(&root).exists());
        let settings = load_ai_settings_from_path(&ai_settings_path(&root));
        let openai = settings
            .provider_configs
            .iter()
            .find(|config| config.metadata.kind == AiProviderKind::OpenAi)
            .expect("openai config");
        assert_eq!(
            openai.connection.api_key_file_name.as_deref(),
            Some("openai_default")
        );
    }

    #[test]
    fn environment_variable_override_wins_over_stored_secret_resolution() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        let resolver = test_resolver(&root);
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");
        resolver
            .write_secret("openai_default", "sk-stored-key-12345")
            .expect("write stored secret");

        let key = resolve_api_key_with_root_and_env_and_resolver(
            &root,
            &resolver,
            Some("sk-env-override-key-1234567890"),
        )
        .expect("resolve env override");

        assert_eq!(key, "sk-env-override-key-1234567890");
    }

    #[test]
    fn missing_secret_returns_clear_error() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        fs::create_dir_all(&root).expect("create root");
        let resolver = test_resolver(&root);
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save ai settings");

        let err = resolve_api_key_with_root_and_env_and_resolver(&root, &resolver, None)
            .expect_err("missing secret");

        assert!(err.contains("no API key configured for selected provider"));
    }

    #[test]
    fn model_resolution_prefers_last_selected_model_for_provider() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.model_preferences.default_selection = DefaultModelSelection::LastUsedPerProvider;
        settings.last_selected_model_by_provider =
            vec![(AiProviderKind::OpenAi, "gpt-4.1-custom".to_string())];

        let model = resolve_model_id_from_settings(&settings).expect("resolve model");

        assert_eq!(model, "gpt-4.1-custom");
    }

    #[test]
    fn runtime_config_uses_selected_provider_model_and_key() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        let resolver = test_resolver(&root);
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.model_preferences.default_selection = DefaultModelSelection::LastUsedPerProvider;
        settings.provider_configs[0].available_models = vec![
            AiModelDescriptor {
                id: "gpt-4.1-mini".to_string(),
                display_name: "GPT-4.1 Mini".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
            AiModelDescriptor {
                id: "gpt-4.1".to_string(),
                display_name: "GPT-4.1".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
        ];
        settings.last_selected_model_by_provider =
            vec![(AiProviderKind::OpenAi, "gpt-4.1".to_string())];
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");
        resolver
            .write_secret("openai_default", "sk-stored-key-1234567890")
            .expect("write secret");

        let runtime_config =
            resolved_ai_runtime_config_with_root_and_resolver(&root, &resolver, |_env| None)
                .expect("runtime config");

        assert_eq!(runtime_config.provider_kind, AiProviderKind::OpenAi);
        assert_eq!(runtime_config.model_id, "gpt-4.1");
        assert_eq!(runtime_config.base_url, "https://api.openai.com");
        assert_eq!(runtime_config.api_key, "sk-stored-key-1234567890");
    }

    #[test]
    fn anthropic_runtime_config_uses_selected_provider_model_and_key() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        let resolver = test_resolver(&root);
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::Anthropic;
        settings.model_preferences.default_selection = DefaultModelSelection::LastUsedPerProvider;
        settings.provider_configs[1].available_models = vec![
            AiModelDescriptor {
                id: "claude-3-5-haiku-latest".to_string(),
                display_name: "Claude 3.5 Haiku".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            },
            AiModelDescriptor {
                id: "claude-3-7-sonnet-latest".to_string(),
                display_name: "Claude 3.7 Sonnet".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            },
        ];
        settings.last_selected_model_by_provider = vec![(
            AiProviderKind::Anthropic,
            "claude-3-7-sonnet-latest".to_string(),
        )];
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");
        resolver
            .write_secret("anthropic_default", "sk-ant-stored-key-1234567890")
            .expect("write anthropic secret");

        let runtime_config =
            resolved_ai_runtime_config_with_root_and_resolver(&root, &resolver, |_env| None)
                .expect("runtime config");

        assert_eq!(runtime_config.provider_kind, AiProviderKind::Anthropic);
        assert_eq!(runtime_config.model_id, "claude-3-7-sonnet-latest");
        assert_eq!(runtime_config.base_url, "https://api.anthropic.com");
        assert_eq!(runtime_config.api_key, "sk-ant-stored-key-1234567890");
    }

    #[test]
    fn runtime_config_errors_when_selected_provider_has_no_registered_adapter() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        fs::create_dir_all(&root).expect("create root");
        let settings = AiSettings {
            selected_provider: AiProviderKind::Custom,
            provider_configs: vec![AiProviderConfig {
                metadata: AiProviderMetadata {
                    kind: AiProviderKind::Custom,
                    display_name: "Custom".to_string(),
                    description: None,
                    supports_custom_base_url: true,
                    supports_connection_test: false,
                },
                connection: AiConnectionConfig {
                    base_url: Some("https://example.invalid".to_string()),
                    api_key_env_var: Some("CUSTOM_API_KEY".to_string()),
                    api_key_file_name: Some("custom_default".to_string()),
                    organization_id: None,
                    project_id: None,
                    custom_headers: Vec::new(),
                },
                available_models: vec![AiModelDescriptor {
                    id: "custom-model".to_string(),
                    display_name: "Custom Model".to_string(),
                    context_window_tokens: None,
                    supports_streaming: false,
                    supports_json_mode: false,
                }],
                enabled: true,
            }],
            model_preferences: Default::default(),
            last_selected_model_by_provider: Vec::new(),
            storage_mode: AiSecretStorageMode::InternalEncryptedStorage,
        };
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");

        let resolver = test_resolver(&root);
        let err = resolved_ai_runtime_config_with_root_and_resolver(&root, &resolver, |_env| None)
            .expect_err("custom should not resolve without adapter");

        assert!(err.contains("no provider adapter is registered"));
    }

    #[test]
    fn runtime_config_uses_local_file_storage_when_selected() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        fs::create_dir_all(&root).expect("create root");
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.storage_mode = AiSecretStorageMode::LocalFileStorage;
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");

        let local_resolver = LocalFileSecretResolver::with_root_dir(&root);
        local_resolver
            .write_secret("openai_default", "sk-local-file-key-1234567890")
            .expect("write local secret");

        let active_resolver = resolver_for_ai_settings_with_root(&settings, &root);
        let runtime_config =
            resolved_ai_runtime_config_with_root_and_resolver(&root, &active_resolver, |_env| None)
                .expect("runtime config");

        assert_eq!(runtime_config.provider_kind, AiProviderKind::OpenAi);
        assert_eq!(runtime_config.api_key, "sk-local-file-key-1234567890");
        let secure_resolver = test_resolver(&root);
        assert_eq!(
            secure_resolver
                .read_secret("openai_default")
                .expect("read secure store")
                .as_deref(),
            None
        );
    }

    #[test]
    fn runtime_config_errors_when_selected_model_is_not_available() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        let resolver = test_resolver(&root);
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.model_preferences.default_selection = DefaultModelSelection::ExplicitModel;
        settings.model_preferences.explicit_default_model_id = Some("not-present".to_string());
        save_ai_settings_to_path(&ai_settings_path(&root), &settings).expect("save settings");
        resolver
            .write_secret("openai_default", "sk-stored-key-1234567890")
            .expect("write secret");

        let err = resolved_ai_runtime_config_with_root_and_resolver(&root, &resolver, |_env| None)
            .expect_err("missing model should fail");

        assert!(err.contains("resolved model is not available from provider"));
    }

    #[test]
    fn provider_specific_env_override_is_used_for_api_key_resolution() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");

        let resolver = test_resolver(&root);
        let key =
            resolve_api_key_for_settings_with_env_and_resolver(&settings, &resolver, |env_name| {
                if env_name == "OPENAI_API_KEY" {
                    Some("sk-env-override-key-1234567890".to_string())
                } else {
                    None
                }
            })
            .expect("resolve env override");

        assert_eq!(key, "sk-env-override-key-1234567890");
    }

    #[test]
    fn anthropic_provider_specific_env_override_is_used_for_api_key_resolution() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::Anthropic;
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");

        let resolver = test_resolver(&root);
        let key =
            resolve_api_key_for_settings_with_env_and_resolver(&settings, &resolver, |env_name| {
                if env_name == "ANTHROPIC_API_KEY" {
                    Some("sk-ant-env-override-key-1234567890".to_string())
                } else {
                    None
                }
            })
            .expect("resolve anthropic env override");

        assert_eq!(key, "sk-ant-env-override-key-1234567890");
    }

    #[test]
    fn runtime_config_errors_cleanly_when_no_provider_is_selected() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        let resolver = test_resolver(&root);
        save_ai_settings_to_path(&ai_settings_path(&root), &default_ai_settings())
            .expect("save settings");

        let err = resolved_ai_runtime_config_with_root_and_resolver(&root, &resolver, |_env| None)
            .expect_err("no provider should not resolve");

        assert!(err.contains("no AI provider selected"));
    }
}
