use chamrisk_core::ai::{
    AiConnectionConfig, AiConnectionTestResult, AiModelDescriptor, AiProvider, AiProviderConfig,
    AiProviderKind, AiProviderMetadata,
};
use serde::Deserialize;
use serde_json::json;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct AnthropicProvider {
    config: AiProviderConfig,
}

impl AnthropicProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self { config }
    }

    fn default_models() -> Vec<AiModelDescriptor> {
        vec![
            AiModelDescriptor {
                id: "claude-3-7-sonnet-latest".to_string(),
                display_name: "Claude 3.7 Sonnet".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            },
            AiModelDescriptor {
                id: "claude-3-5-haiku-latest".to_string(),
                display_name: "Claude 3.5 Haiku".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
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
        let api_key = api_key.trim();
        if api_key.starts_with("sk-ant-") && api_key.len() >= 20 {
            Ok(())
        } else {
            Err("invalid API key for Anthropic provider".to_string())
        }
    }

    fn connection_result(&self, success: bool, message: &str) -> AiConnectionTestResult {
        AiConnectionTestResult {
            provider: AiProviderKind::Anthropic,
            success,
            latency_ms: None,
            message: message.to_string(),
            resolved_model_id: self.models().first().map(|model| model.id.clone()),
        }
    }

    fn test_connection_with_runner<F>(
        &self,
        resolved_api_key: Option<&str>,
        runner: F,
    ) -> Result<AiConnectionTestResult, String>
    where
        F: FnOnce(&str, &str) -> Result<(u16, Option<u64>), String>,
    {
        if self
            .config
            .connection
            .base_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Ok(self.connection_result(false, "Anthropic base URL is not configured"));
        }
        if self
            .config
            .connection
            .api_key_file_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
            && self
                .config
                .connection
                .api_key_env_var
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Ok(self.connection_result(false, "Anthropic API key source is not configured"));
        }

        let api_key = match resolved_api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(api_key) => api_key,
            None => return Ok(self.connection_result(false, "Missing API key")),
        };
        if Self::validate_api_key(api_key).is_err() {
            return Ok(self.connection_result(false, "Invalid API key"));
        }

        let base_url = self
            .config
            .connection
            .base_url
            .as_deref()
            .expect("base_url already validated");
        let (status_code, latency_ms) = match runner(base_url, api_key) {
            Ok(result) => result,
            Err(_) => {
                return Ok(self.connection_result(false, "Anthropic connection test failed"));
            }
        };

        let mut result = match status_code {
            200..=299 => self.connection_result(true, "Anthropic connection test succeeded"),
            401 | 403 => self.connection_result(false, "Anthropic authentication failed"),
            _ => self.connection_result(false, "Anthropic connection test failed"),
        };
        result.latency_ms = latency_ms;
        Ok(result)
    }

    fn parse_model_list(raw: &str) -> Result<Vec<AiModelDescriptor>, String> {
        #[derive(Deserialize)]
        struct ModelsResponse {
            data: Vec<ModelItem>,
        }

        #[derive(Deserialize)]
        struct ModelItem {
            id: String,
            #[serde(default)]
            display_name: Option<String>,
        }

        let parsed: ModelsResponse = serde_json::from_str(raw)
            .map_err(|err| format!("invalid model list response: {err}"))?;

        let mut models = parsed
            .data
            .into_iter()
            .filter(|item| item.id.starts_with("claude-"))
            .map(|item| AiModelDescriptor {
                display_name: item.display_name.unwrap_or_else(|| item.id.clone()),
                id: item.id,
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            })
            .collect::<Vec<_>>();
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);

        if models.is_empty() {
            return Err("no compatible models returned by Anthropic".to_string());
        }

        Ok(models)
    }

    fn list_models_with_runner<F>(
        &self,
        resolved_api_key: Option<&str>,
        runner: F,
    ) -> Result<Vec<AiModelDescriptor>, String>
    where
        F: FnOnce(&str, &str) -> Result<(u16, String), String>,
    {
        self.validate_config()?;
        let api_key = resolved_api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing API key for Anthropic provider".to_string())?;
        Self::validate_api_key(api_key)?;
        let base_url = self
            .config
            .connection
            .base_url
            .as_deref()
            .ok_or_else(|| "Anthropic base URL is not configured".to_string())?;
        let (status_code, raw) = runner(base_url, api_key)?;
        match status_code {
            200..=299 => Self::parse_model_list(&raw),
            401 | 403 => Err("Anthropic authentication failed".to_string()),
            _ => Err("failed to fetch Anthropic models".to_string()),
        }
    }

    fn parse_triage_response(raw: &str) -> Result<String, String> {
        #[derive(Deserialize)]
        struct Response {
            content: Vec<ContentBlock>,
        }

        #[derive(Deserialize)]
        struct ContentBlock {
            #[serde(rename = "type")]
            block_type: String,
            #[serde(default)]
            text: Option<String>,
        }

        let parsed: Response = serde_json::from_str(raw)
            .map_err(|err| format!("invalid Anthropic triage response: {err}"))?;
        let content = parsed
            .content
            .into_iter()
            .filter(|block| block.block_type == "text")
            .filter_map(|block| block.text)
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if content.is_empty() {
            return Err("Anthropic triage response contained no text content".to_string());
        }
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
        F: FnOnce(&str, &str, &str) -> Result<(u16, String), String>,
    {
        self.validate_config()?;
        let api_key = resolved_api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing API key for Anthropic provider".to_string())?;
        Self::validate_api_key(api_key)?;
        let model_id = model_id.trim();
        if model_id.is_empty() {
            return Err("missing model for Anthropic provider".to_string());
        }
        let base_url = self
            .config
            .connection
            .base_url
            .as_deref()
            .ok_or_else(|| "Anthropic base URL is not configured".to_string())?;
        let body = json!({
            "model": model_id,
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
            "temperature": 0,
            "max_tokens": 700,
        })
        .to_string();
        let (status_code, raw) = runner(base_url, api_key, &body)?;
        match status_code {
            200..=299 => Self::parse_triage_response(&raw),
            401 | 403 => Err("Anthropic authentication failed".to_string()),
            _ => Err("Anthropic triage request failed".to_string()),
        }
    }
}

impl AiProvider for AnthropicProvider {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::Anthropic
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
            return Err("Anthropic base URL is not configured".to_string());
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
            return Err("Anthropic API key source is not configured".to_string());
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
                    &format!("x-api-key: {api_key}"),
                    "-H",
                    "anthropic-version: 2023-06-01",
                    "-H",
                    "Content-Type: application/json",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    &format!("{base_url}/v1/models"),
                ])
                .output()
                .map_err(|err| format!("failed to execute Anthropic connection test: {err}"))?;

            let status_text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let status_code = status_text
                .parse::<u16>()
                .map_err(|err| format!("failed to parse Anthropic status code: {err}"))?;

            Ok((status_code, None))
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
                    &format!("x-api-key: {api_key}"),
                    "-H",
                    "anthropic-version: 2023-06-01",
                    "-H",
                    "Content-Type: application/json",
                    "-w",
                    "\nHTTP_STATUS:%{http_code}\n",
                    &format!("{base_url}/v1/models"),
                ])
                .output()
                .map_err(|err| format!("failed to fetch Anthropic models: {err}"))?;

            if !output.status.success() {
                return Err("failed to fetch Anthropic models".to_string());
            }

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let (body, status_line) = stdout
                .rsplit_once("\nHTTP_STATUS:")
                .ok_or_else(|| "failed to parse Anthropic model response status".to_string())?;
            let status_code = status_line
                .trim()
                .parse::<u16>()
                .map_err(|err| format!("failed to parse Anthropic model status code: {err}"))?;

            Ok((status_code, body.to_string()))
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
                        &format!("x-api-key: {api_key}"),
                        "-H",
                        "anthropic-version: 2023-06-01",
                        "-H",
                        "Content-Type: application/json",
                        "-w",
                        "\nHTTP_STATUS:%{http_code}\n",
                        "--data-binary",
                        body,
                        &format!("{base_url}/v1/messages"),
                    ])
                    .output()
                    .map_err(|err| format!("failed to execute Anthropic triage request: {err}"))?;

                if !output.status.success() {
                    return Err("Anthropic triage request failed".to_string());
                }

                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let (body, status_line) =
                    stdout.rsplit_once("\nHTTP_STATUS:").ok_or_else(|| {
                        "failed to parse Anthropic triage response status".to_string()
                    })?;
                let status_code = status_line
                    .trim()
                    .parse::<u16>()
                    .map_err(|err| format!("failed to parse Anthropic status code: {err}"))?;

                Ok((status_code, body.to_string()))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AnthropicProvider;
    use crate::ai::parse_assessment;
    use crate::api::default_provider_config;
    use chamrisk_core::ai::{AiProvider, AiProviderKind};
    use serde_json::Value;

    fn fixture(name: &str) -> &'static str {
        match name {
            "model_list_success" => {
                include_str!("../../../tests/fixtures/anthropic/model_list_success.json")
            }
            "model_list_empty" => {
                include_str!("../../../tests/fixtures/anthropic/model_list_empty.json")
            }
            "triage_success" => {
                include_str!("../../../tests/fixtures/anthropic/triage_success.json")
            }
            "invalid_auth" => {
                include_str!("../../../tests/fixtures/anthropic/invalid_auth.json")
            }
            "malformed_model_list" => {
                include_str!("../../../tests/fixtures/anthropic/malformed_model_list.json")
            }
            "malformed_triage" => {
                include_str!("../../../tests/fixtures/anthropic/malformed_triage.json")
            }
            other => panic!("unknown anthropic fixture: {other}"),
        }
    }

    #[test]
    fn validates_anthropic_config() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));
        provider.validate_config().expect("valid anthropic config");
    }

    #[test]
    fn rejects_missing_key_source_in_config() {
        let mut config = default_provider_config(AiProviderKind::Anthropic);
        config.connection.api_key_env_var = None;
        config.connection.api_key_file_name = None;

        let provider = AnthropicProvider::new(config);

        assert_eq!(
            provider
                .validate_config()
                .expect_err("missing key source should fail"),
            "Anthropic API key source is not configured"
        );
    }

    #[test]
    fn connection_test_returns_success_for_available_provider() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let result = provider
            .test_connection_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |base_url, api_key| {
                    assert_eq!(base_url, "https://api.anthropic.com");
                    assert_eq!(api_key, "sk-ant-valid-test-key-1234567890");
                    Ok((200, Some(42)))
                },
            )
            .expect("connection test result");

        assert!(result.success);
        assert_eq!(result.provider, AiProviderKind::Anthropic);
        assert_eq!(result.latency_ms, Some(42));
        assert_eq!(result.message, "Anthropic connection test succeeded");
        assert_eq!(
            result.resolved_model_id.as_deref(),
            Some("claude-3-7-sonnet-latest")
        );
    }

    #[test]
    fn connection_test_returns_not_available_for_unauthorized_key() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let result = provider
            .test_connection_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Ok((401, None)),
            )
            .expect("unauthorized result");

        assert!(!result.success);
        assert_eq!(result.message, "Anthropic authentication failed");
    }

    #[test]
    fn connection_test_returns_not_available_for_network_error() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let result = provider
            .test_connection_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Err("network down".to_string()),
            )
            .expect("network failure result");

        assert!(!result.success);
        assert_eq!(result.message, "Anthropic connection test failed");
    }

    #[test]
    fn connection_test_returns_not_available_for_missing_key_or_config() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let missing_key = provider
            .test_connection_with_runner(None, |_base_url, _api_key| Ok((200, None)))
            .expect("missing key result");
        assert!(!missing_key.success);
        assert_eq!(missing_key.message, "Missing API key");

        let mut missing_config = default_provider_config(AiProviderKind::Anthropic);
        missing_config.connection.api_key_env_var = None;
        missing_config.connection.api_key_file_name = None;
        let provider = AnthropicProvider::new(missing_config);
        let missing_source = provider
            .test_connection_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Ok((200, None)),
            )
            .expect("missing config result");
        assert!(!missing_source.success);
        assert_eq!(
            missing_source.message,
            "Anthropic API key source is not configured"
        );
    }

    #[test]
    fn list_models_returns_provider_fetched_models() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let models = provider
            .list_models_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |base_url, api_key| {
                    assert_eq!(base_url, "https://api.anthropic.com");
                    assert_eq!(api_key, "sk-ant-valid-test-key-1234567890");
                    Ok((200, fixture("model_list_success").to_string()))
                },
            )
            .expect("model list");

        assert_eq!(
            models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            vec!["claude-3-5-haiku-latest", "claude-3-7-sonnet-latest"]
        );
        assert_eq!(models[0].display_name, "Claude 3.5 Haiku");
        assert_eq!(models[1].display_name, "Claude 3.7 Sonnet");
    }

    #[test]
    fn list_models_returns_error_for_empty_model_list() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let err = provider
            .list_models_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Ok((200, fixture("model_list_empty").to_string())),
            )
            .expect_err("empty model list should fail");

        assert_eq!(err, "no compatible models returned by Anthropic");
    }

    #[test]
    fn list_models_returns_error_for_invalid_auth() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let err = provider
            .list_models_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Ok((401, fixture("invalid_auth").to_string())),
            )
            .expect_err("unauthorized model list should fail");

        assert_eq!(err, "Anthropic authentication failed");
    }

    #[test]
    fn list_models_returns_error_for_malformed_provider_response() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let err = provider
            .list_models_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Ok((200, fixture("malformed_model_list").to_string())),
            )
            .expect_err("malformed model payload should fail");

        assert!(err.contains("invalid model list response"));
    }

    #[test]
    fn list_models_errors_without_falling_back_to_seeded_defaults() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let err = provider
            .list_models_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                |_base_url, _api_key| Err("network down".to_string()),
            )
            .expect_err("model fetch should fail");

        assert_eq!(err, "network down");
    }

    #[test]
    fn run_triage_builds_anthropic_request_and_maps_response_content() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let content = provider
            .run_triage_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                "claude-3-7-sonnet-latest",
                "system prompt",
                "user prompt",
                |base_url, api_key, body| {
                    assert_eq!(base_url, "https://api.anthropic.com");
                    assert_eq!(api_key, "sk-ant-valid-test-key-1234567890");
                    let body: Value = serde_json::from_str(body).expect("request body json");
                    assert_eq!(body["model"], "claude-3-7-sonnet-latest");
                    assert_eq!(body["system"], "system prompt");
                    assert_eq!(body["messages"][0]["role"], "user");
                    assert_eq!(body["messages"][0]["content"], "user prompt");
                    Ok((200, fixture("triage_success").to_string()))
                },
            )
            .expect("triage content");

        assert!(content.starts_with("Risk: Green"));
    }

    #[test]
    fn run_triage_maps_fixture_into_provider_neutral_assessment() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let content = provider
            .run_triage_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                "claude-3-7-sonnet-latest",
                "system prompt",
                "user prompt",
                |_base_url, _api_key, _body| Ok((200, fixture("triage_success").to_string())),
            )
            .expect("triage content");
        let assessment = parse_assessment(&content).expect("provider-neutral assessment");

        assert_eq!(assessment.risk, "Green");
        assert!(assessment.summary.contains("Snapshot first."));
        assert!(assessment.summary.contains("Reboot after update."));
    }

    #[test]
    fn run_triage_returns_auth_failure_for_invalid_auth_fixture() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let err = provider
            .run_triage_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                "claude-3-7-sonnet-latest",
                "system prompt",
                "user prompt",
                |_base_url, _api_key, _body| Ok((401, fixture("invalid_auth").to_string())),
            )
            .expect_err("invalid auth should fail");

        assert_eq!(err, "Anthropic authentication failed");
    }

    #[test]
    fn run_triage_returns_parse_error_for_malformed_fixture() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let err = provider
            .run_triage_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                "claude-3-7-sonnet-latest",
                "system prompt",
                "user prompt",
                |_base_url, _api_key, _body| Ok((200, fixture("malformed_triage").to_string())),
            )
            .expect_err("malformed fixture should fail");

        assert_eq!(err, "Anthropic triage response contained no text content");
    }

    #[test]
    fn run_triage_errors_for_missing_model_or_key() {
        let provider = AnthropicProvider::new(default_provider_config(AiProviderKind::Anthropic));

        let missing_key = provider
            .run_triage_with_runner(
                None,
                "claude-3-7-sonnet-latest",
                "system prompt",
                "user prompt",
                |_base_url, _api_key, _body| Ok((200, "{}".to_string())),
            )
            .expect_err("missing key should fail");
        assert_eq!(missing_key, "missing API key for Anthropic provider");

        let missing_model = provider
            .run_triage_with_runner(
                Some("sk-ant-valid-test-key-1234567890"),
                "",
                "system prompt",
                "user prompt",
                |_base_url, _api_key, _body| Ok((200, "{}".to_string())),
            )
            .expect_err("missing model should fail");
        assert_eq!(missing_model, "missing model for Anthropic provider");
    }
}
