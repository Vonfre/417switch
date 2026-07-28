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
fn get_keywords_for_app(app: &str) -> Vec<&str> {
    match app.to_lowercase().as_str() {
        "claude" => vec!["ANTHROPIC"],
        "codex" => vec!["OPENAI"],
        "gemini" => vec!["GEMINI", "GOOGLE_GEMINI"],
        _ => vec![],
    }
}

/// Check system environment variables (Windows Registry or Unix env)
#[cfg(target_os = "windows")]
fn check_system_env(keywords: &[&str]) -> Result<Vec<EnvConflict>, String> {
    let mut conflicts = Vec::new();

    // Check HKEY_CURRENT_USER\Environment
    if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Environment") {
        for (name, value) in hkcu.enum_values().filter_map(Result::ok) {
            if keywords.iter().any(|k| name.to_uppercase().contains(k)) {
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
            if keywords.iter().any(|k| name.to_uppercase().contains(k)) {
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
fn check_system_env(keywords: &[&str]) -> Result<Vec<EnvConflict>, String> {
    let mut conflicts = Vec::new();

    // Check current process environment
    for (key, value) in std::env::vars() {
        if keywords.iter().any(|k| key.to_uppercase().contains(k)) {
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
fn check_shell_configs(keywords: &[&str]) -> Result<Vec<EnvConflict>, String> {
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
                        if keywords.iter().any(|k| var_name.to_uppercase().contains(k)) {
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
        assert_eq!(get_keywords_for_app("claude"), vec!["ANTHROPIC"]);
        assert_eq!(get_keywords_for_app("codex"), vec!["OPENAI"]);
        assert_eq!(
            get_keywords_for_app("gemini"),
            vec!["GEMINI", "GOOGLE_GEMINI"]
        );
        assert_eq!(get_keywords_for_app("unknown"), Vec::<&str>::new());
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
