use chamrisk_core::ai::{
    AiConnectionConfig, AiConnectionTestResult, AiModelDescriptor, AiProvider, AiProviderConfig,
    AiProviderKind, AiProviderMetadata,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct OpenAiProvider {
    config: AiProviderConfig,
}

impl OpenAiProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self { config }
    }

    fn default_models() -> Vec<AiModelDescriptor> {
        vec![
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
        ]
    }

    fn models(&self) -> Vec<AiModelDescriptor> {
        if self.config.available_models.is_empty() {
            Self::default_models()
        } else {
            self.config.available_models.clone()
        }
    }

    fn validate_api_key(api_key: &str) -> Result<(), String> {
        if api_key.starts_with("sk-") {
            Ok(())
        } else {
            Err("invalid API key for OpenAI provider".to_string())
        }
    }

    fn extract_http_status(stdout: &str) -> Option<u16> {
        stdout.lines().find_map(|line| {
            line.strip_prefix("HTTP_STATUS:")
                .and_then(|value| value.trim().parse::<u16>().ok())
        })
    }

    fn provider_error_message(stdout: &str) -> Option<String> {
        let body = stdout
            .lines()
            .take_while(|line| !line.starts_with("HTTP_STATUS:"))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed: Value = serde_json::from_str(&body).ok()?;
        parsed
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|message| !message.is_empty())
            .map(|message| message.to_string())
    }

    fn classify_curl_exit(exit_code: i32) -> String {
        match exit_code {
            6 | 7 => "Network error".to_string(),
            28 => "Connection timed out".to_string(),
            35 | 60 => "TLS/certificate error".to_string(),
            code => format!("Connection test failed (curl exit {code})"),
        }
    }

    fn classify_http_failure(http_status: u16, stdout: &str) -> String {
        match http_status {
            401 | 403 => "Authentication failed".to_string(),
            429 => "Rate limited".to_string(),
            500..=599 => "OpenAI service unavailable".to_string(),
            code => Self::provider_error_message(stdout)
                .unwrap_or_else(|| format!("OpenAI returned HTTP {code}")),
        }
    }

    fn test_connection_with_runner<F>(
        &self,
        resolved_api_key: Option<&str>,
        runner: F,
    ) -> Result<AiConnectionTestResult, String>
    where
        F: FnOnce(&str, &str) -> Result<(bool, Option<u64>, String), String>,
    {
        self.validate_config()?;
        let api_key = resolved_api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing API key for OpenAI provider".to_string())?;
        Self::validate_api_key(api_key)?;

        let base_url = self
            .config
            .connection
            .base_url
            .as_deref()
            .ok_or_else(|| "OpenAI base URL is not configured".to_string())?;
        let (success, latency_ms, message) = runner(base_url, api_key)?;
        Ok(AiConnectionTestResult {
            provider: AiProviderKind::OpenAi,
            success,
            latency_ms,
            message,
            resolved_model_id: self.models().first().map(|model| model.id.clone()),
        })
    }

    fn parse_model_list(raw: &str) -> Result<Vec<AiModelDescriptor>, String> {
        #[derive(Deserialize)]
        struct ModelsResponse {
            data: Vec<ModelItem>,
        }

        #[derive(Deserialize)]
        struct ModelItem {
            id: String,
        }

        let parsed: ModelsResponse = serde_json::from_str(raw)
            .map_err(|err| format!("invalid model list response: {err}"))?;

        let mut models = parsed
            .data
            .into_iter()
            .filter(|item| item.id.starts_with("gpt-"))
            .map(|item| AiModelDescriptor {
                display_name: item.id.clone(),
                id: item.id,
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            })
            .collect::<Vec<_>>();
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);

        if models.is_empty() {
            return Err("no compatible models returned by OpenAI".to_string());
        }

        Ok(models)
    }

    fn list_models_with_runner<F>(
        &self,
        resolved_api_key: Option<&str>,
        runner: F,
    ) -> Result<Vec<AiModelDescriptor>, String>
    where
        F: FnOnce(&str, &str) -> Result<String, String>,
    {
        self.validate_config()?;
        let api_key = resolved_api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing API key for OpenAI provider".to_string())?;
        Self::validate_api_key(api_key)?;
        let base_url = self
            .config
            .connection
            .base_url
            .as_deref()
            .ok_or_else(|| "OpenAI base URL is not configured".to_string())?;
        let raw = runner(base_url, api_key)?;
        Self::parse_model_list(&raw)
    }

    fn parse_triage_response(raw: &str) -> Result<String, String> {
        #[derive(Deserialize)]
        struct Response {
            choices: Vec<Choice>,
        }

        #[derive(Deserialize)]
        struct Choice {
            message: Message,
        }

        #[derive(Deserialize)]
        struct Message {
            content: String,
        }

        let parsed: Response = serde_json::from_str(raw)
            .map_err(|err| format!("invalid OpenAI triage response: {err}"))?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content.trim().to_string())
            .filter(|content| !content.is_empty())
            .ok_or_else(|| "OpenAI triage response contained no message content".to_string())?;
        Ok(content)
    }

    fn run_triage_with_runner<F>(
        &self,
        resolved_api_key: Option<&str>,
        model_id: &str,
        system_prompt: &str,
        user_prompt: &str,
        runner: F,
    ) -> Result<String, String>
    where
        F: FnOnce(&str, &str, &str) -> Result<String, String>,
    {
        self.validate_config()?;
        let api_key = resolved_api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing API key for OpenAI provider".to_string())?;
        Self::validate_api_key(api_key)?;
        let model_id = model_id.trim();
        if model_id.is_empty() {
            return Err("missing model for OpenAI provider".to_string());
        }
        let base_url = self
            .config
            .connection
            .base_url
            .as_deref()
            .ok_or_else(|| "OpenAI base URL is not configured".to_string())?;
        let body = json!({
            "model": model_id,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
            "temperature": 0,
        })
        .to_string();
        let raw = runner(base_url, api_key, &body)?;
        Self::parse_triage_response(&raw)
    }
}

impl AiProvider for OpenAiProvider {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::OpenAi
    }

    fn metadata(&self) -> AiProviderMetadata {
        self.config.metadata.clone()
    }

    fn connection_config(&self) -> &AiConnectionConfig {
        &self.config.connection
    }

    fn available_models(&self) -> &[AiModelDescriptor] {
        &self.config.available_models
    }

    fn validate_config(&self) -> Result<(), String> {
        let connection = &self.config.connection;
        if connection
            .base_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err("OpenAI base URL is not configured".to_string());
        }
        if connection
            .api_key_file_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
            && connection
                .api_key_env_var
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err("OpenAI API key source is not configured".to_string());
        }
        Ok(())
    }

    fn test_connection(
        &self,
        resolved_api_key: Option<&str>,
    ) -> Result<AiConnectionTestResult, String> {
        self.test_connection_with_runner(resolved_api_key, |base_url, api_key| {
            let output = Command::new("curl")
                .args([
                    "-sS",
                    "--max-time",
                    "4",
                    "-H",
                    &format!("Authorization: Bearer {api_key}"),
                    "-H",
                    "Content-Type: application/json",
                    "-w",
                    "\nHTTP_STATUS:%{http_code}\n",
                    &format!("{base_url}/v1/models"),
                ])
                .output()
                .map_err(|err| format!("failed to execute OpenAI connection test: {err}"))?;

            if !output.status.success() {
                let exit_code = output.status.code().unwrap_or(-1);
                return Ok((false, None, Self::classify_curl_exit(exit_code)));
            }

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let Some(http_status) = Self::extract_http_status(&stdout) else {
                return Ok((
                    false,
                    None,
                    "OpenAI connection test returned no HTTP status".to_string(),
                ));
            };

            let success = (200..300).contains(&http_status);
            let message = if success {
                "OpenAI connection test succeeded".to_string()
            } else {
                Self::classify_http_failure(http_status, &stdout)
            };

            Ok((success, None, message))
        })
    }

    fn list_models(
        &self,
        resolved_api_key: Option<&str>,
    ) -> Result<Vec<AiModelDescriptor>, String> {
        self.list_models_with_runner(resolved_api_key, |base_url, api_key| {
            let output = Command::new("curl")
                .args([
                    "-sS",
                    "--max-time",
                    "6",
                    "-H",
                    &format!("Authorization: Bearer {api_key}"),
                    "-H",
                    "Content-Type: application/json",
                    &format!("{base_url}/v1/models"),
                ])
                .output()
                .map_err(|err| format!("failed to fetch OpenAI models: {err}"))?;

            if !output.status.success() {
                return Err(format!(
                    "failed to fetch OpenAI models: curl exit {}",
                    output.status
                ));
            }

            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        })
    }

    fn run_triage(
        &self,
        resolved_api_key: Option<&str>,
        model_id: &str,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, String> {
        self.run_triage_with_runner(
            resolved_api_key,
            model_id,
            system_prompt,
            user_prompt,
            |base_url, api_key, body| {
                let output = Command::new("curl")
                    .args([
                        "-sS",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "60",
                        "-H",
                        &format!("Authorization: Bearer {api_key}"),
                        "-H",
                        "Content-Type: application/json",
                        "--data-binary",
                        body,
                        &format!("{base_url}/v1/chat/completions"),
                    ])
                    .output()
                    .map_err(|err| format!("failed to execute OpenAI triage request: {err}"))?;

                if !output.status.success() {
                    return Err("OpenAI triage request failed".to_string());
                }

                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::OpenAiProvider;
    use crate::api::default_provider_config;
    use chamrisk_core::ai::{AiProvider, AiProviderKind};
    use serde_json::Value;

    #[test]
    fn validates_openai_config() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));
        provider.validate_config().expect("valid openai config");
    }

    #[test]
    fn rejects_missing_key_source_in_config() {
        let mut config = default_provider_config(AiProviderKind::OpenAi);
        config.connection.api_key_env_var = None;
        config.connection.api_key_file_name = None;

        let provider = OpenAiProvider::new(config);

        assert_eq!(
            provider
                .validate_config()
                .expect_err("missing key source should fail"),
            "OpenAI API key source is not configured"
        );
    }

    #[test]
    fn connection_test_rejects_missing_or_invalid_key() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));

        assert_eq!(
            provider
                .test_connection_with_runner(None, |_base_url, _api_key| {
                    Ok((true, Some(10), "ok".to_string()))
                })
                .expect_err("missing key should fail"),
            "missing API key for OpenAI provider"
        );
        assert_eq!(
            provider
                .test_connection_with_runner(Some("not-a-real-key"), |_base_url, _api_key| {
                    Ok((true, Some(10), "ok".to_string()))
                })
                .expect_err("invalid key should fail"),
            "invalid API key for OpenAI provider"
        );
    }

    #[test]
    fn connection_test_uses_runner_seam() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));

        let result = provider
            .test_connection_with_runner(
                Some("sk-valid-test-key-1234567890"),
                |base_url, api_key| {
                    assert_eq!(base_url, "https://api.openai.com");
                    assert_eq!(api_key, "sk-valid-test-key-1234567890");
                    Ok((
                        true,
                        Some(42),
                        "OpenAI connection test succeeded".to_string(),
                    ))
                },
            )
            .expect("connection test result");

        assert!(result.success);
        assert_eq!(result.provider, AiProviderKind::OpenAi);
        assert_eq!(result.latency_ms, Some(42));
        assert_eq!(result.message, "OpenAI connection test succeeded");
        assert_eq!(result.resolved_model_id.as_deref(), Some("gpt-4.1-mini"));
    }

    #[test]
    fn connection_test_classifies_auth_failure() {
        assert_eq!(
            OpenAiProvider::classify_http_failure(
                401,
                r#"{"error":{"message":"Incorrect API key provided"}}
HTTP_STATUS:401
"#
            ),
            "Authentication failed"
        );
    }

    #[test]
    fn connection_test_classifies_network_and_tls_failures() {
        assert_eq!(OpenAiProvider::classify_curl_exit(7), "Network error");
        assert_eq!(
            OpenAiProvider::classify_curl_exit(28),
            "Connection timed out"
        );
        assert_eq!(
            OpenAiProvider::classify_curl_exit(60),
            "TLS/certificate error"
        );
    }

    #[test]
    fn list_models_returns_provider_fetched_models() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));

        let models = provider
            .list_models_with_runner(Some("sk-valid-test-key-1234567890"), |base_url, api_key| {
                assert_eq!(base_url, "https://api.openai.com");
                assert_eq!(api_key, "sk-valid-test-key-1234567890");
                Ok(r#"{"data":[{"id":"gpt-4.1"},{"id":"gpt-4.1-mini"},{"id":"text-embedding-3-small"}]}"#.to_string())
            })
            .expect("model list");

        assert_eq!(
            models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            vec!["gpt-4.1", "gpt-4.1-mini"]
        );
    }

    #[test]
    fn list_models_errors_without_falling_back_to_seeded_defaults() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));

        let err = provider
            .list_models_with_runner(
                Some("sk-valid-test-key-1234567890"),
                |_base_url, _api_key| Err("network down".to_string()),
            )
            .expect_err("model fetch should fail");

        assert_eq!(err, "network down");
    }

    #[test]
    fn run_triage_builds_openai_request_and_maps_response_content() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));

        let content = provider
            .run_triage_with_runner(
                Some("sk-valid-test-key-1234567890"),
                "gpt-4.1",
                "system prompt",
                "user prompt",
                |base_url, api_key, body| {
                    assert_eq!(base_url, "https://api.openai.com");
                    assert_eq!(api_key, "sk-valid-test-key-1234567890");
                    let body: Value = serde_json::from_str(body).expect("request body json");
                    assert_eq!(body["model"], "gpt-4.1");
                    assert_eq!(body["messages"][0]["role"], "system");
                    assert_eq!(body["messages"][0]["content"], "system prompt");
                    assert_eq!(body["messages"][1]["role"], "user");
                    assert_eq!(body["messages"][1]["content"], "user prompt");
                    Ok(r#"{"choices":[{"message":{"content":"Risk: Green\n1) A\n2) B\n3) C\n4) D\n5) E"}}]}"#.to_string())
                },
            )
            .expect("triage content");

        assert!(content.starts_with("Risk: Green"));
    }

    #[test]
    fn run_triage_errors_for_missing_model() {
        let provider = OpenAiProvider::new(default_provider_config(AiProviderKind::OpenAi));

        let err = provider
            .run_triage_with_runner(
                Some("sk-valid-test-key-1234567890"),
                "",
                "system prompt",
                "user prompt",
                |_base_url, _api_key, _body| Ok("{}".to_string()),
            )
            .expect_err("missing model should fail");

        assert_eq!(err, "missing model for OpenAI provider");
    }
}
