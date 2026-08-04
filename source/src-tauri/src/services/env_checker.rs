use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "windows"))]
use std::fs;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvConflict {
    pub var_name: String,
    pub var_value: String,
    pub source_type: String, // "system" | "file"
    pub source_path: String, // Registry path or file path
}

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Check environment variables for conflicts
pub fn check_env_conflicts(app: &str) -> Result<Vec<EnvConflict>, String> {
    let keywords = get_keywords_for_app(app);
    let mut conflicts = Vec::new();

    // Check system environment variables
    conflicts.extend(check_system_env(&keywords)?);

    // Check shell configuration files (Unix only)
    #[cfg(not(target_os = "windows"))]
    conflicts.extend(check_shell_configs(&keywords)?);

    conflicts.retain(|conflict| !is_allowed_science_route(app, conflict));
    Ok(conflicts)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvKeyword {
    Exact(&'static str),
    Prefix(&'static str),
}

fn is_allowed_science_route(app: &str, conflict: &EnvConflict) -> bool {
    if !app.eq_ignore_ascii_case("claude") || conflict.var_name != "ANTHROPIC_BASE_URL" {
        return false;
    }
    let Ok(url) = Url::parse(conflict.var_value.trim().trim_end_matches('/')) else {
        return false;
    };
    url.scheme() == "http"
        && matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "::1" | "[::1]")
        )
        && url.port() == Some(9876)
        && url.query().is_none()
        && url.fragment().is_none()
}

/// Get relevant keywords for each app
fn get_keywords_for_app(app: &str) -> Vec<EnvKeyword> {
    match app.to_lowercase().as_str() {
        "claude" => vec![EnvKeyword::Prefix("ANTHROPIC")],
        "codex" => vec![EnvKeyword::Prefix("OPENAI")],
        "gemini" => vec![
            EnvKeyword::Prefix("GEMINI"),
            EnvKeyword::Prefix("GOOGLE_GEMINI"),
        ],
        "grokbuild" | "grok" => vec![
            EnvKeyword::Exact("XAI_API_KEY"),
            EnvKeyword::Exact("GROK_DEFAULT_MODEL"),
        ],
        _ => vec![],
    }
}

fn matches_env_keyword(name: &str, keywords: &[EnvKeyword]) -> bool {
    let upper_name = name.to_uppercase();
    keywords.iter().any(|keyword| match keyword {
        EnvKeyword::Exact(name) => upper_name == *name,
        EnvKeyword::Prefix(prefix) => upper_name.starts_with(prefix),
    })
}

/// Check system environment variables (Windows Registry or Unix env)
#[cfg(target_os = "windows")]
fn check_system_env(keywords: &[EnvKeyword]) -> Result<Vec<EnvConflict>, String> {
    let mut conflicts = Vec::new();

    // Check HKEY_CURRENT_USER\Environment
    if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Environment") {
        for (name, value) in hkcu.enum_values().filter_map(Result::ok) {
            if matches_env_keyword(&name, keywords) {
                conflicts.push(EnvConflict {
                    var_name: name.clone(),
                    var_value: value.to_string(),
                    source_type: "system".to_string(),
                    source_path: "HKEY_CURRENT_USER\\Environment".to_string(),
                });
            }
        }
    }

    // Check HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
    {
        for (name, value) in hklm.enum_values().filter_map(Result::ok) {
            if matches_env_keyword(&name, keywords) {
                conflicts.push(EnvConflict {
                    var_name: name.clone(),
                    var_value: value.to_string(),
                    source_type: "system".to_string(),
                    source_path: "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment".to_string(),
                });
            }
        }
    }

    Ok(conflicts)
}

#[cfg(not(target_os = "windows"))]
fn check_system_env(keywords: &[EnvKeyword]) -> Result<Vec<EnvConflict>, String> {
    let mut conflicts = Vec::new();

    // Check current process environment
    for (key, value) in std::env::vars() {
        if matches_env_keyword(&key, keywords) {
            conflicts.push(EnvConflict {
                var_name: key,
                var_value: value,
                source_type: "system".to_string(),
                source_path: "Process Environment".to_string(),
            });
        }
    }

    Ok(conflicts)
}

/// Check shell configuration files for environment variable exports (Unix only)
#[cfg(not(target_os = "windows"))]
fn check_shell_configs(keywords: &[EnvKeyword]) -> Result<Vec<EnvConflict>, String> {
    let mut conflicts = Vec::new();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let config_files = vec![
        format!("{}/.bashrc", home),
        format!("{}/.bash_profile", home),
        format!("{}/.zshrc", home),
        format!("{}/.zprofile", home),
        format!("{}/.profile", home),
        "/etc/profile".to_string(),
        "/etc/bashrc".to_string(),
    ];

    for file_path in config_files {
        if let Ok(content) = fs::read_to_string(&file_path) {
            // Parse lines for export statements
            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();

                // Match patterns like: export VAR=value or VAR=value
                if trimmed.starts_with("export ")
                    || (!trimmed.starts_with('#') && trimmed.contains('='))
                {
                    let export_line = trimmed.strip_prefix("export ").unwrap_or(trimmed);

                    if let Some(eq_pos) = export_line.find('=') {
                        let var_name = export_line[..eq_pos].trim();
                        let var_value = export_line[eq_pos + 1..].trim();

                        // Check if variable name contains any keyword
                        if matches_env_keyword(var_name, keywords) {
                            conflicts.push(EnvConflict {
                                var_name: var_name.to_string(),
                                var_value: var_value
                                    .trim_matches('"')
                                    .trim_matches('\'')
                                    .to_string(),
                                source_type: "file".to_string(),
                                source_path: format!("{}:{}", file_path, line_num + 1),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_keywords() {
        assert_eq!(
            get_keywords_for_app("claude"),
            vec![EnvKeyword::Prefix("ANTHROPIC")]
        );
        assert_eq!(
            get_keywords_for_app("codex"),
            vec![EnvKeyword::Prefix("OPENAI")]
        );
        assert_eq!(
            get_keywords_for_app("gemini"),
            vec![
                EnvKeyword::Prefix("GEMINI"),
                EnvKeyword::Prefix("GOOGLE_GEMINI")
            ]
        );
        assert_eq!(
            get_keywords_for_app("grokbuild"),
            vec![
                EnvKeyword::Exact("XAI_API_KEY"),
                EnvKeyword::Exact("GROK_DEFAULT_MODEL")
            ]
        );
        assert_eq!(
            get_keywords_for_app("grok"),
            get_keywords_for_app("grokbuild")
        );
        assert_eq!(get_keywords_for_app("unknown"), Vec::<EnvKeyword>::new());
    }

    #[test]
    fn grok_keywords_only_match_credentials() {
        let keywords = get_keywords_for_app("grokbuild");

        assert!(matches_env_keyword("XAI_API_KEY", &keywords));
        assert!(matches_env_keyword("xai_api_key", &keywords));
        assert!(matches_env_keyword("GROK_DEFAULT_MODEL", &keywords));
        assert!(matches_env_keyword("grok_default_model", &keywords));
        assert!(!matches_env_keyword("MY_XAI_API_KEY", &keywords));
        assert!(!matches_env_keyword("XAI_API_KEY_BACKUP", &keywords));
        assert!(!matches_env_keyword("MY_GROK_DEFAULT_MODEL", &keywords));
        assert!(!matches_env_keyword("GROK_DEFAULT_MODEL_BACKUP", &keywords));
        assert!(!matches_env_keyword("GROK_BIN_DIR", &keywords));
        assert!(!matches_env_keyword("GROK_HOME", &keywords));
    }

    #[test]
    fn broad_app_keywords_match_only_at_the_start() {
        let keywords = get_keywords_for_app("claude");

        assert!(matches_env_keyword("ANTHROPIC_API_KEY", &keywords));
        assert!(matches_env_keyword("anthropic_base_url", &keywords));
        assert!(!matches_env_keyword("MY_ANTHROPIC_API_KEY", &keywords));
        assert!(!matches_env_keyword("NOT_ANTHROPIC", &keywords));
    }

    #[test]
    fn allows_the_managed_local_science_route() {
        for value in [
            "http://127.0.0.1:9876",
            "http://127.0.0.1:9876/",
            "http://localhost:9876/science",
            "http://[::1]:9876",
        ] {
            let conflict = EnvConflict {
                var_name: "ANTHROPIC_BASE_URL".into(),
                var_value: value.into(),
                source_type: "system".into(),
                source_path: "Process Environment".into(),
            };
            assert!(is_allowed_science_route("claude", &conflict), "{value}");
        }
    }

    #[test]
    fn keeps_other_anthropic_routes_as_conflicts() {
        for value in [
            "https://api.example.com",
            "http://127.0.0.1:9999",
            "http://127.0.0.1:9876?token=value",
        ] {
            let conflict = EnvConflict {
                var_name: "ANTHROPIC_BASE_URL".into(),
                var_value: value.into(),
                source_type: "system".into(),
                source_path: "Process Environment".into(),
            };
            assert!(!is_allowed_science_route("claude", &conflict), "{value}");
        }
    }
}
