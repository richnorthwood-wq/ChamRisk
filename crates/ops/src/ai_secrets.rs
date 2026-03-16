use chamrisk_core::ai::secrets::SecretResolver;
use chamrisk_core::ai::{AiSecretStorageMode, AiSettings};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SECRET_TOOL_BIN: &str = "secret-tool";
const APPLICATION_ATTR_KEY: &str = "application";
const APPLICATION_ATTR_VALUE: &str = "chamrisk";
const SECRET_REF_ATTR_KEY: &str = "secret_ref";
const SECURE_STORE_UNAVAILABLE: &str = "secure secret store unavailable";
#[cfg(unix)]
const USER_ONLY_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const USER_ONLY_FILE_MODE: u32 = 0o600;

pub(crate) trait SecureStoreBackend {
    fn lookup(&self, secret_ref: &str) -> Result<Option<String>, String>;
    fn store(&self, secret_ref: &str, secret_value: &str) -> Result<(), String>;
    fn clear(&self, secret_ref: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Default)]
pub struct SecretToolBackend;

impl SecretToolBackend {
    fn build_label(secret_ref: &str) -> String {
        format!("ChamRisk AI credential ({secret_ref})")
    }

    fn unavailable_error(context: &str, stderr: &str) -> String {
        let detail = stderr.trim();
        if detail.is_empty() {
            SECURE_STORE_UNAVAILABLE.to_string()
        } else {
            format!("{context}: {SECURE_STORE_UNAVAILABLE}: {detail}")
        }
    }

    fn run_lookup(&self, secret_ref: &str) -> Result<(bool, String, String), String> {
        let output = Command::new(SECRET_TOOL_BIN)
            .args([
                "lookup",
                APPLICATION_ATTR_KEY,
                APPLICATION_ATTR_VALUE,
                SECRET_REF_ATTR_KEY,
                secret_ref,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("{SECURE_STORE_UNAVAILABLE}: {err}"))?;

        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }

    fn run_store(&self, secret_ref: &str, secret_value: &str) -> Result<(bool, String), String> {
        let mut child = Command::new(SECRET_TOOL_BIN)
            .args([
                "store",
                &format!("--label={}", Self::build_label(secret_ref)),
                APPLICATION_ATTR_KEY,
                APPLICATION_ATTR_VALUE,
                SECRET_REF_ATTR_KEY,
                secret_ref,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("{SECURE_STORE_UNAVAILABLE}: {err}"))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(secret_value.as_bytes())
                .map_err(|err| format!("failed to send secret to secure store: {err}"))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|err| format!("failed to wait for secure store command: {err}"))?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }

    fn run_clear(&self, secret_ref: &str) -> Result<(bool, String), String> {
        let output = Command::new(SECRET_TOOL_BIN)
            .args([
                "clear",
                APPLICATION_ATTR_KEY,
                APPLICATION_ATTR_VALUE,
                SECRET_REF_ATTR_KEY,
                secret_ref,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("{SECURE_STORE_UNAVAILABLE}: {err}"))?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}

impl SecureStoreBackend for SecretToolBackend {
    fn lookup(&self, secret_ref: &str) -> Result<Option<String>, String> {
        let (success, stdout, stderr) = self.run_lookup(secret_ref)?;
        if success {
            let secret = stdout.trim_end_matches(['\r', '\n']).to_string();
            return if secret.is_empty() {
                Ok(None)
            } else {
                Ok(Some(secret))
            };
        }
        if stderr.trim().is_empty() {
            return Ok(None);
        }
        Err(Self::unavailable_error(
            "failed to read secret from secure store",
            &stderr,
        ))
    }

    fn store(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
        let (success, stderr) = self.run_store(secret_ref, secret_value)?;
        if success {
            Ok(())
        } else {
            Err(Self::unavailable_error(
                "failed to write secret to secure store",
                &stderr,
            ))
        }
    }

    fn clear(&self, secret_ref: &str) -> Result<(), String> {
        let (success, stderr) = self.run_clear(secret_ref)?;
        if success || stderr.trim().is_empty() {
            Ok(())
        } else {
            Err(Self::unavailable_error(
                "failed to delete secret from secure store",
                &stderr,
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretServiceSecretResolver<B = SecretToolBackend> {
    backend: B,
    legacy_root_dir: PathBuf,
}

impl SecretServiceSecretResolver<SecretToolBackend> {
    pub fn new() -> Result<Self, String> {
        let home =
            dirs::home_dir().ok_or_else(|| "failed to resolve home directory".to_string())?;
        Ok(Self {
            backend: SecretToolBackend,
            legacy_root_dir: home.join(".config").join("chamrisk"),
        })
    }

    pub fn with_legacy_root_dir<P: AsRef<Path>>(legacy_root_dir: P) -> Self {
        Self {
            backend: SecretToolBackend,
            legacy_root_dir: legacy_root_dir.as_ref().to_path_buf(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalFileSecretResolver {
    root_dir: PathBuf,
}

impl LocalFileSecretResolver {
    pub fn new() -> Result<Self, String> {
        let home =
            dirs::home_dir().ok_or_else(|| "failed to resolve home directory".to_string())?;
        Ok(Self {
            root_dir: home.join(".config").join("chamrisk"),
        })
    }

    pub fn with_root_dir<P: AsRef<Path>>(root_dir: P) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
        }
    }

    fn validate_secret_ref(secret_ref: &str) -> Result<(), String> {
        SecretServiceSecretResolver::<SecretToolBackend>::validate_secret_ref(secret_ref)
    }

    fn file_name_for_secret_ref(secret_ref: &str) -> &str {
        match secret_ref {
            "openai_default" => "openai_key",
            "anthropic_default" => "anthropic_key",
            "custom_default" => "custom_key",
            other => other,
        }
    }

    fn secret_path(&self, secret_ref: &str) -> Result<PathBuf, String> {
        Self::validate_secret_ref(secret_ref)?;
        Ok(self
            .root_dir
            .join(Self::file_name_for_secret_ref(secret_ref)))
    }

    fn ensure_parent_dir_exists(&self, path: &Path) -> Result<(), String> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };

        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create local config dir {}: {err}",
                parent.display()
            )
        })?;
        set_user_only_permissions(parent, true)?;
        Ok(())
    }

    fn write_secret_atomically(&self, path: &Path, secret_value: &str) -> Result<(), String> {
        let temp_name = format!(
            ".{}.tmp-{}-{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("secret"),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        );
        let temp_path = path.with_file_name(temp_name);

        let mut file = open_user_only_file(&temp_path)?;
        file.write_all(secret_value.as_bytes()).map_err(|err| {
            format!(
                "failed to write local secret {}: {err}",
                temp_path.display()
            )
        })?;
        file.sync_all().map_err(|err| {
            format!(
                "failed to flush local secret {}: {err}",
                temp_path.display()
            )
        })?;
        drop(file);

        fs::rename(&temp_path, path)
            .map_err(|err| format!("failed to finalize local secret {}: {err}", path.display()))?;
        set_user_only_permissions(path, false)?;

        let reread = fs::read_to_string(path)
            .map_err(|err| format!("failed to verify local secret {}: {err}", path.display()))?;
        if reread != secret_value {
            return Err(format!(
                "failed to verify local secret after write: {}",
                path.display()
            ));
        }

        Ok(())
    }
}

impl SecretResolver for LocalFileSecretResolver {
    fn read_secret(&self, secret_ref: &str) -> Result<Option<String>, String> {
        let path = self.secret_path(secret_ref)?;
        match fs::read_to_string(&path) {
            Ok(raw) => {
                let secret = raw.trim().to_string();
                if secret.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(secret))
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!(
                "failed to read local secret {}: {err}",
                path.display()
            )),
        }
    }

    fn write_secret(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
        let path = self.secret_path(secret_ref)?;
        self.ensure_parent_dir_exists(&path)?;
        self.write_secret_atomically(&path, secret_value)
    }

    fn delete_secret(&self, secret_ref: &str) -> Result<(), String> {
        let path = self.secret_path(secret_ref)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to delete local secret {}: {err}",
                path.display()
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConfiguredSecretResolver {
    Internal(SecretServiceSecretResolver),
    LocalFile(LocalFileSecretResolver),
}

impl SecretResolver for ConfiguredSecretResolver {
    fn read_secret(&self, secret_ref: &str) -> Result<Option<String>, String> {
        match self {
            Self::Internal(resolver) => resolver.read_secret(secret_ref),
            Self::LocalFile(resolver) => resolver.read_secret(secret_ref),
        }
    }

    fn write_secret(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
        match self {
            Self::Internal(resolver) => resolver.write_secret(secret_ref, secret_value),
            Self::LocalFile(resolver) => resolver.write_secret(secret_ref, secret_value),
        }
    }

    fn delete_secret(&self, secret_ref: &str) -> Result<(), String> {
        match self {
            Self::Internal(resolver) => resolver.delete_secret(secret_ref),
            Self::LocalFile(resolver) => resolver.delete_secret(secret_ref),
        }
    }
}

pub fn resolver_for_ai_settings(settings: &AiSettings) -> Result<ConfiguredSecretResolver, String> {
    match settings.storage_mode {
        AiSecretStorageMode::InternalEncryptedStorage => Ok(ConfiguredSecretResolver::Internal(
            SecretServiceSecretResolver::new()?,
        )),
        AiSecretStorageMode::LocalFileStorage => Ok(ConfiguredSecretResolver::LocalFile(
            LocalFileSecretResolver::new()?,
        )),
    }
}

pub fn resolver_for_ai_settings_with_root<P: AsRef<Path>>(
    settings: &AiSettings,
    root_dir: P,
) -> ConfiguredSecretResolver {
    match settings.storage_mode {
        AiSecretStorageMode::InternalEncryptedStorage => ConfiguredSecretResolver::Internal(
            SecretServiceSecretResolver::with_legacy_root_dir(root_dir),
        ),
        AiSecretStorageMode::LocalFileStorage => {
            ConfiguredSecretResolver::LocalFile(LocalFileSecretResolver::with_root_dir(root_dir))
        }
    }
}

impl<B> SecretServiceSecretResolver<B>
where
    Self: SecretResolver,
{
    #[cfg(test)]
    pub(crate) fn with_backend_and_legacy_root_dir<P: AsRef<Path>>(
        backend: B,
        legacy_root_dir: P,
    ) -> Self {
        Self {
            backend,
            legacy_root_dir: legacy_root_dir.as_ref().to_path_buf(),
        }
    }

    fn validate_secret_ref(secret_ref: &str) -> Result<(), String> {
        if secret_ref.is_empty() {
            return Err("secret ref must not be empty".to_string());
        }
        if secret_ref.contains('/') || secret_ref.contains('\\') || secret_ref.contains("..") {
            return Err(format!("invalid secret ref: {secret_ref}"));
        }
        if !secret_ref
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        {
            return Err(format!("invalid secret ref: {secret_ref}"));
        }
        Ok(())
    }

    fn legacy_secret_path(&self, secret_ref: &str) -> Result<PathBuf, String> {
        Self::validate_secret_ref(secret_ref)?;
        Ok(self.legacy_root_dir.join("secrets").join(secret_ref))
    }

    pub fn migrate_plaintext_secret_if_present(&self, secret_ref: &str) -> Result<bool, String> {
        let legacy_path = self.legacy_secret_path(secret_ref)?;
        self.import_plaintext_secret_file(secret_ref, &legacy_path)
    }

    pub fn import_plaintext_secret_file<P: AsRef<Path>>(
        &self,
        secret_ref: &str,
        plaintext_path: P,
    ) -> Result<bool, String> {
        Self::validate_secret_ref(secret_ref)?;
        let plaintext_path = plaintext_path.as_ref();
        match fs::metadata(plaintext_path) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(format!(
                    "failed to inspect legacy plaintext secret {}: {err}",
                    plaintext_path.display()
                ))
            }
        }

        let secure_secret = self.read_secret(secret_ref)?;
        if secure_secret.is_some() {
            remove_plaintext_secret_if_present(plaintext_path)?;
            return Ok(false);
        }

        let raw = match fs::read_to_string(plaintext_path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(format!(
                    "failed to read legacy plaintext secret {}: {err}",
                    plaintext_path.display()
                ))
            }
        };

        let secret = raw.trim().to_string();
        if secret.is_empty() {
            remove_plaintext_secret_if_present(plaintext_path)?;
            return Ok(false);
        }

        self.write_secret(secret_ref, &secret)?;
        remove_plaintext_secret_if_present(plaintext_path)?;
        Ok(true)
    }
}

impl<B> SecretResolver for SecretServiceSecretResolver<B>
where
    B: SecureStoreBackend,
{
    fn read_secret(&self, secret_ref: &str) -> Result<Option<String>, String> {
        Self::validate_secret_ref(secret_ref)?;
        self.backend.lookup(secret_ref)
    }

    fn write_secret(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
        Self::validate_secret_ref(secret_ref)?;
        self.backend.store(secret_ref, secret_value)
    }

    fn delete_secret(&self, secret_ref: &str) -> Result<(), String> {
        Self::validate_secret_ref(secret_ref)?;
        self.backend.clear(secret_ref)
    }
}

fn remove_plaintext_secret_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to remove legacy plaintext secret {}: {err}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn open_user_only_file(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(USER_ONLY_FILE_MODE)
        .open(path)
        .map_err(|err| format!("failed to create local secret {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn open_user_only_file(path: &Path) -> Result<fs::File, String> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("failed to create local secret {}: {err}", path.display()))
}

#[cfg(unix)]
fn set_user_only_permissions(path: &Path, is_dir: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if is_dir {
        USER_ONLY_DIR_MODE
    } else {
        USER_ONLY_FILE_MODE
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|err| {
        format!(
            "failed to set secure permissions on {}: {err}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_user_only_permissions(_path: &Path, _is_dir: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LocalFileSecretResolver, SecretServiceSecretResolver, SecureStoreBackend,
        SECURE_STORE_UNAVAILABLE,
    };
    use chamrisk_core::ai::provider::AiProviderKind;
    use chamrisk_core::ai::secrets::SecretResolver;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[derive(Debug, Default)]
    struct FakeSecureBackend {
        secrets: RefCell<HashMap<String, String>>,
        unavailable: bool,
    }

    impl FakeSecureBackend {
        fn unavailable() -> Self {
            Self {
                secrets: RefCell::new(HashMap::new()),
                unavailable: true,
            }
        }
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
                return Err(SECURE_STORE_UNAVAILABLE.to_string());
            }
            Ok(self.secrets.borrow().get(secret_ref).cloned())
        }

        fn store(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
            if self.unavailable {
                return Err(SECURE_STORE_UNAVAILABLE.to_string());
            }
            self.secrets
                .borrow_mut()
                .insert(secret_ref.to_string(), secret_value.to_string());
            Ok(())
        }

        fn clear(&self, secret_ref: &str) -> Result<(), String> {
            if self.unavailable {
                return Err(SECURE_STORE_UNAVAILABLE.to_string());
            }
            self.secrets.borrow_mut().remove(secret_ref);
            Ok(())
        }
    }

    #[test]
    fn secure_secret_round_trip_reads_written_value() {
        let temp = tempdir().expect("tempdir");
        let resolver = SecretServiceSecretResolver::with_backend_and_legacy_root_dir(
            FakeSecureBackend::default(),
            temp.path(),
        );

        resolver
            .write_secret("openai_default", "sk-test-123")
            .expect("write secret");

        let loaded = resolver.read_secret("openai_default").expect("read secret");
        assert_eq!(loaded.as_deref(), Some("sk-test-123"));
    }

    #[test]
    fn provider_secret_resolution_reads_secure_backend() {
        let temp = tempdir().expect("tempdir");
        let resolver = SecretServiceSecretResolver::with_backend_and_legacy_root_dir(
            FakeSecureBackend::default(),
            temp.path(),
        );
        resolver
            .write_secret("anthropic_default", "sk-ant-test-123")
            .expect("write secret");

        assert_eq!(
            resolver
                .resolve_api_key(AiProviderKind::Anthropic)
                .expect("resolve provider secret")
                .as_deref(),
            Some("sk-ant-test-123")
        );
    }

    #[test]
    fn plaintext_migration_imports_and_removes_legacy_file() {
        let temp = tempdir().expect("tempdir");
        let legacy_dir = temp.path().join("secrets");
        fs::create_dir_all(&legacy_dir).expect("create secrets dir");
        let legacy_path = legacy_dir.join("openai_default");
        fs::write(&legacy_path, "sk-legacy-test-123").expect("write legacy secret");
        let resolver = SecretServiceSecretResolver::with_backend_and_legacy_root_dir(
            FakeSecureBackend::default(),
            temp.path(),
        );

        let migrated = resolver
            .migrate_plaintext_secret_if_present("openai_default")
            .expect("migrate plaintext secret");

        assert!(migrated);
        assert_eq!(
            resolver
                .read_secret("openai_default")
                .expect("read secure secret"),
            Some("sk-legacy-test-123".to_string())
        );
        assert!(!legacy_path.exists());
    }

    #[test]
    fn secure_store_unavailable_returns_explicit_error() {
        let temp = tempdir().expect("tempdir");
        let resolver = SecretServiceSecretResolver::with_backend_and_legacy_root_dir(
            FakeSecureBackend::unavailable(),
            temp.path(),
        );

        let err = resolver
            .write_secret("openai_default", "sk-test-123")
            .expect_err("secure store should be unavailable");

        assert!(err.contains(SECURE_STORE_UNAVAILABLE));
    }

    #[test]
    fn invalid_secret_refs_are_rejected() {
        let temp = tempdir().expect("tempdir");
        let resolver = SecretServiceSecretResolver::with_backend_and_legacy_root_dir(
            FakeSecureBackend::default(),
            temp.path(),
        );

        for secret_ref in ["../oops", "nested/path", "nested\\path", "", "bad ref"] {
            assert!(resolver.read_secret(secret_ref).is_err());
            assert!(resolver.write_secret(secret_ref, "value").is_err());
            assert!(resolver.delete_secret(secret_ref).is_err());
        }
    }

    #[test]
    fn local_file_secret_round_trip_uses_provider_key_file_names() {
        let temp = tempdir().expect("tempdir");
        let resolver = LocalFileSecretResolver::with_root_dir(temp.path());

        resolver
            .write_secret("openai_default", "sk-local-test-1234567890")
            .expect("write local secret");

        let loaded = resolver
            .read_secret("openai_default")
            .expect("read local secret");
        assert_eq!(loaded.as_deref(), Some("sk-local-test-1234567890"));
        assert!(temp.path().join("openai_key").exists());
    }

    #[test]
    fn local_file_secret_persists_across_resolver_reload() {
        let temp = tempdir().expect("tempdir");
        let resolver = LocalFileSecretResolver::with_root_dir(temp.path());
        resolver
            .write_secret("anthropic_default", "sk-ant-reload-test-1234567890")
            .expect("write local secret");

        let reloaded = LocalFileSecretResolver::with_root_dir(temp.path());
        let loaded = reloaded
            .read_secret("anthropic_default")
            .expect("read local secret after reload");

        assert_eq!(loaded.as_deref(), Some("sk-ant-reload-test-1234567890"));
    }

    #[test]
    fn local_file_missing_secret_is_treated_as_not_configured() {
        let temp = tempdir().expect("tempdir");
        let resolver = LocalFileSecretResolver::with_root_dir(temp.path());

        let loaded = resolver
            .read_secret("anthropic_default")
            .expect("read missing local secret");

        assert_eq!(loaded, None);
    }

    #[test]
    fn local_file_delete_removes_secret_file_cleanly() {
        let temp = tempdir().expect("tempdir");
        let resolver = LocalFileSecretResolver::with_root_dir(temp.path());
        let secret_path = temp.path().join("anthropic_key");

        resolver
            .write_secret("anthropic_default", "sk-ant-local-test-1234567890")
            .expect("write local secret");
        resolver
            .delete_secret("anthropic_default")
            .expect("delete local secret");

        assert!(!secret_path.exists());
        assert_eq!(
            resolver
                .read_secret("anthropic_default")
                .expect("read deleted local secret"),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_file_secret_is_written_with_user_only_permissions() {
        use crate::ai_secrets::USER_ONLY_FILE_MODE;
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().expect("tempdir");
        let resolver = LocalFileSecretResolver::with_root_dir(temp.path());
        let secret_path = temp.path().join("openai_key");

        resolver
            .write_secret("openai_default", "sk-local-test-1234567890")
            .expect("write local secret");

        let mode = fs::metadata(&secret_path)
            .expect("secret metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, USER_ONLY_FILE_MODE);
    }
}
