//! Claude Science integration.
//!
//! The isolated-login format and runtime boundaries are adapted from the
//! MIT-licensed SuperJJ007/CSSwitch project. 417Switch keeps Science account
//! data and credentials in its own data directory, exposes approved real user
//! folders through Science's built-in browser, and routes inference through
//! the configured local loopback endpoint.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hkdf::Hkdf;
use reqwest::header::{COOKIE, ORIGIN, SET_COOKIE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use url::Url;

use crate::provider::Provider;
use crate::store::AppState;

const SCIENCE_PORT: u16 = 15_890;
const SCIENCE_PREVIEW_PORT: u16 = 15_891;
const REAL_SCIENCE_PORT: u16 = 8_765;
const OFFICIAL_APP_BIN: &str =
    "/Applications/Claude Science.app/Contents/Resources/bin/claude-science";
const UPDATED_BIN_RELATIVE: &str = ".claude-science/bin/claude-science";
const VIRTUAL_EMAIL: &str = "417switch@localhost.invalid";
const HKDF_INFO: &[u8] = b"operon:aes-256-gcm:oauth";
const AAD: &[u8] = b"v2:oauth";
const MODELS_CREATED_AT: &str = "2026-01-01T00:00:00Z";
const SCIENCE_LAUNCH_MODE: &str = "real-home-explicit-config-science-provider-v2";
const KEY_NAMES: [&str; 4] = [
    "ANTHROPIC_API_KEY_ENCRYPTION_KEY",
    "OAUTH_ENCRYPTION_KEY",
    "JWT_SIGNING_SECRET",
    "USER_SECRET_ENCRYPTION_KEY",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeSource {
    Explicit,
    OfficialUpdated,
    InstalledApp,
}

impl RuntimeSource {
    fn label(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::OfficialUpdated => "official_updated",
            Self::InstalledApp => "installed_app",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeRecord {
    path: PathBuf,
    source: RuntimeSource,
    version: String,
    sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TemporaryHostBrowseState {
    #[serde(default)]
    paths: Vec<PathBuf>,
    #[serde(default)]
    legacy_cleaned: bool,
}

#[derive(Debug, Deserialize)]
struct ScienceProcessRecord {
    pid: u32,
    port: u16,
    sandbox_port: u16,
    sock: PathBuf,
}

struct ScienceLocalSession {
    client: reqwest::Client,
    origin: String,
    auth_cookie: String,
    csrf_cookie: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceStatus {
    pub supported: bool,
    pub installed: bool,
    pub running: bool,
    pub healthy: bool,
    pub port: u16,
    pub provider_name: Option<String>,
    pub runtime_source: Option<String>,
    pub runtime_version: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceStartResult {
    pub url: String,
    pub provider_name: String,
    pub runtime_source: String,
    pub runtime_version: String,
}

fn science_root() -> PathBuf {
    crate::config::get_app_config_dir().join("science")
}

fn sandbox_home() -> PathBuf {
    science_root().join("sandbox/home")
}

fn sandbox_data_dir() -> PathBuf {
    sandbox_home().join(".claude-science")
}

fn sandbox_config_path() -> PathBuf {
    science_root().join("config.toml")
}

fn launch_mode_path() -> PathBuf {
    science_root().join("launch-mode")
}

fn launch_mode_is_current() -> bool {
    std::fs::read_to_string(launch_mode_path())
        .map(|value| value.trim() == SCIENCE_LAUNCH_MODE)
        .unwrap_or(false)
}

fn save_launch_mode() -> Result<(), String> {
    safe_write(
        &launch_mode_path(),
        format!("{SCIENCE_LAUNCH_MODE}\n").as_bytes(),
        0o600,
    )
}

fn runtime_record_path() -> PathBuf {
    science_root().join("runtime.json")
}

fn temporary_host_browse_state_path() -> PathBuf {
    science_root().join("temporary-host-browse.v2.json")
}

fn process_record_path() -> PathBuf {
    sandbox_data_dir().join("operon.lock")
}

fn real_home_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("无法定位真实用户 HOME")?;
    let home = std::fs::canonicalize(&home).map_err(|e| format!("确认真实用户 HOME 失败：{e}"))?;
    if !home.is_dir() || home == sandbox_home() {
        return Err("真实用户 HOME 无效或命中 Science 隔离 HOME".into());
    }
    Ok(home)
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

fn path_contains_symlink(path: &Path) -> bool {
    if !path.is_absolute() {
        return true;
    }
    let mut probe = path;
    loop {
        if std::fs::symlink_metadata(probe)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return true;
        }
        let Some(parent) = probe.parent() else {
            break;
        };
        if parent == probe {
            break;
        }
        probe = parent;
    }
    false
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    if path_contains_symlink(path) {
        return Err(format!("拒绝使用包含符号链接的目录：{}", path.display()));
    }
    std::fs::create_dir_all(path).map_err(|e| format!("创建目录失败：{e}"))?;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("检查目录失败：{e}"))?;
    if !metadata.is_dir() || metadata.uid() != current_uid() {
        return Err("Science 隔离目录不是当前用户拥有的普通目录".into());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("收紧目录权限失败：{e}"))
}

fn random_bytes(size: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open("/dev/urandom").map_err(|e| format!("打开系统随机源失败：{e}"))?;
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("读取系统随机源失败：{e}"))?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn safe_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!("拒绝覆盖符号链接：{}", path.display()));
    }
    let parent = path.parent().ok_or("目标路径缺少父目录")?;
    ensure_private_dir(parent)?;
    let suffix = hex(&random_bytes(6)?);
    let temp = parent.join(format!(".science-{suffix}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)
        .map_err(|e| format!("创建临时文件失败：{e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("写入临时文件失败：{e}"))?;
    file.sync_all()
        .map_err(|e| format!("持久化临时文件失败：{e}"))?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("设置临时文件权限失败：{e}"))?;
    std::fs::rename(&temp, path).map_err(|e| format!("提交文件失败：{e}"))?;
    Ok(())
}

fn uuid_v4() -> Result<String, String> {
    let mut bytes = random_bytes(16)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

fn derive_key(oauth_key: &str) -> Result<[u8; 32], String> {
    let input = B64
        .decode(oauth_key.trim())
        .map_err(|e| format!("OAUTH_ENCRYPTION_KEY 不是合法 base64：{e}"))?;
    let hkdf = Hkdf::<Sha256>::new(Some(&[]), &input);
    let mut output = [0; 32];
    hkdf.expand(HKDF_INFO, &mut output)
        .map_err(|_| "HKDF 派生失败".to_string())?;
    Ok(output)
}

fn encrypt_token(plaintext: &[u8], oauth_key: &str) -> Result<String, String> {
    let derived = derive_key(oauth_key)?;
    let nonce = random_bytes(12)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| "Science 虚拟登录加密失败".to_string())?;
    let mut framed = nonce;
    framed.extend_from_slice(&ciphertext);
    Ok(format!("v2:{}", B64.encode(framed)))
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
}

fn active_org(auth_dir: &Path) -> Option<String> {
    let value: Value =
        serde_json::from_slice(&std::fs::read(auth_dir.join("active-org.json")).ok()?).ok()?;
    let org = value.get("org_uuid")?.as_str()?;
    looks_like_uuid(org).then(|| org.to_string())
}

fn ensure_virtual_login() -> Result<(), String> {
    let root = science_root();
    let sandbox = sandbox_home();
    let auth_dir = sandbox_data_dir();
    let real = dirs::home_dir()
        .ok_or("无法定位用户 HOME")?
        .join(".claude-science");

    ensure_private_dir(&root)?;
    ensure_private_dir(&root.join("sandbox"))?;
    ensure_private_dir(&sandbox)?;
    if path_contains_symlink(&auth_dir) || path_contains_symlink(&real) {
        return Err("Science 隔离目录或真实目录路径包含符号链接，已拒绝写入".into());
    }
    let resolved_root =
        std::fs::canonicalize(&sandbox).map_err(|e| format!("确认沙箱 HOME 失败：{e}"))?;
    let resolved_auth = auth_dir
        .parent()
        .map(|parent| {
            std::fs::canonicalize(parent)
                .unwrap_or_else(|_| parent.to_path_buf())
                .join(".claude-science")
        })
        .ok_or("Science 隔离目录无父目录")?;
    if !resolved_auth.starts_with(&resolved_root) || resolved_auth == real {
        return Err("Science 虚拟登录目标不在 417Switch 隔离 HOME 内".into());
    }

    ensure_private_dir(&auth_dir)?;
    let marker_path = root.join("virtual-org.v1.json");
    let marked_org = std::fs::read(&marker_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("org_uuid")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|value| looks_like_uuid(value));
    let existing_org = active_org(&auth_dir);
    let org_uuid = match (marked_org, existing_org) {
        (Some(marker), Some(active)) if marker == active => marker,
        (Some(marker), None) => marker,
        (None, Some(active)) => active,
        (Some(_), Some(_)) => {
            return Err("Science 隔离历史标记与 active-org 不一致，已拒绝静默覆盖".into())
        }
        (None, None) => uuid_v4()?,
    };

    let key_path = auth_dir.join("encryption.key");
    let mut keys = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(&key_path) {
        for line in text.lines() {
            if let Some((name, value)) = line.split_once('=') {
                if KEY_NAMES.contains(&name.trim()) && !value.trim().is_empty() {
                    keys.insert(name.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }
    let oauth_valid = keys
        .get("OAUTH_ENCRYPTION_KEY")
        .and_then(|value| B64.decode(value).ok())
        .is_some_and(|bytes| bytes.len() >= 16);
    if !oauth_valid {
        keys.remove("OAUTH_ENCRYPTION_KEY");
    }
    for name in KEY_NAMES {
        if !keys.contains_key(name) {
            keys.insert(name.to_string(), B64.encode(random_bytes(32)?));
        }
    }
    let key_file = KEY_NAMES
        .iter()
        .map(|name| format!("{name}={}", keys[*name]))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    safe_write(&key_path, key_file.as_bytes(), 0o600)?;

    let account_uuid = uuid_v4()?;
    let access_token = format!("sk-ant-virtual-{}", hex(&random_bytes(24)?));
    let token = json!({
        "access_token": access_token,
        "refresh_token": "",
        "api_key": null,
        "token_expires_at": "2099-01-01T00:00:00.000Z",
        "provider": "claude_ai",
        "scopes": "user:inference user:file_upload user:profile user:mcp_servers user:plugins",
        "email": VIRTUAL_EMAIL,
        "account_uuid": account_uuid,
        "subscription_type": "max",
        "rate_limit_tier": null,
        "seat_tier": null,
        "org_uuid": org_uuid,
        "billing_type": null,
        "has_extra_usage_enabled": false
    });
    let encrypted = encrypt_token(
        &serde_json::to_vec(&token).map_err(|e| format!("序列化虚拟登录失败：{e}"))?,
        keys.get("OAUTH_ENCRYPTION_KEY")
            .ok_or("缺少 OAUTH_ENCRYPTION_KEY")?,
    )?;
    let token_dir = auth_dir.join(".oauth-tokens");
    ensure_private_dir(&token_dir)?;
    for entry in std::fs::read_dir(&token_dir).map_err(|e| format!("读取 token 目录失败：{e}"))?
    {
        let path = entry
            .map_err(|e| format!("读取 token 条目失败：{e}"))?
            .path();
        if path.extension().is_some_and(|extension| extension == "enc") {
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|e| format!("检查旧 token 失败：{e}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("Science 隔离 token 目录包含不安全条目".into());
            }
            std::fs::remove_file(&path).map_err(|e| format!("清理旧 token 失败：{e}"))?;
        }
    }
    safe_write(
        &token_dir.join(format!("{account_uuid}.enc")),
        encrypted.as_bytes(),
        0o600,
    )?;
    safe_write(
        &auth_dir.join("active-org.json"),
        (serde_json::to_string_pretty(&json!({ "org_uuid": org_uuid }))
            .map_err(|e| format!("序列化 active-org 失败：{e}"))?
            + "\n")
            .as_bytes(),
        0o600,
    )?;
    safe_write(
        &marker_path,
        (serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "org_uuid": org_uuid
        }))
        .map_err(|e| format!("序列化虚拟组织标记失败：{e}"))?
            + "\n")
            .as_bytes(),
        0o600,
    )?;
    Ok(())
}

fn is_macho(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xbe, 0xba, 0xfe, 0xca])
    )
}

fn validate_executable(path: &Path, require_current_owner: bool) -> Result<Vec<u8>, String> {
    if path_contains_symlink(path) {
        return Err(format!(
            "Science executable 路径包含符号链接：{}",
            path.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("读取 Science executable 信息失败：{e}"))?;
    if !metadata.is_file()
        || metadata.len() < 4
        || metadata.len() > 512 * 1024 * 1024
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || (require_current_owner && metadata.uid() != current_uid())
    {
        return Err("Science executable 类型、大小、属主或权限不安全".into());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("读取 Science executable 失败：{e}"))?;
    if !is_macho(&bytes) {
        return Err("Science executable 不是可识别的 Mach-O 文件".into());
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn snapshot_updated_runtime(source: &Path) -> Result<PathBuf, String> {
    let before = std::fs::symlink_metadata(source)
        .map_err(|e| format!("检查 updater Science executable 失败：{e}"))?;
    let bytes = validate_executable(source, true)?;
    let after = std::fs::symlink_metadata(source)
        .map_err(|e| format!("复核 updater Science executable 失败：{e}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
    {
        return Err("updater Science executable 在读取期间发生变化".into());
    }
    let digest = sha256(&bytes);
    let root = science_root().join("runtime-snapshots/science");
    ensure_private_dir(&root)?;
    let target = root.join(format!("claude-science-{digest}"));
    if target.exists() {
        let existing = validate_executable(&target, true)?;
        if sha256(&existing) != digest {
            return Err("Science runtime snapshot 文件名与内容不一致".into());
        }
        return Ok(target);
    }
    safe_write(&target, &bytes, 0o500)?;
    Ok(target)
}

fn runtime_version(path: &Path) -> Result<String, String> {
    let output = Command::new(path)
        .arg("--version")
        .env("HOME", real_home_dir()?)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("执行 Science --version 失败：{e}"))?;
    if !output.status.success() {
        return Err("Science --version 未成功".into());
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() || version.len() > 256 {
        return Err("Science 版本输出无效".into());
    }
    Ok(version)
}

fn build_runtime(
    path: PathBuf,
    source: RuntimeSource,
    require_current_owner: bool,
) -> Result<RuntimeRecord, String> {
    let bytes = validate_executable(&path, require_current_owner)?;
    let version = runtime_version(&path)?;
    Ok(RuntimeRecord {
        path,
        source,
        version,
        sha256: sha256(&bytes),
    })
}

fn select_runtime() -> Result<RuntimeRecord, String> {
    if !cfg!(target_os = "macos") {
        return Err("Claude Science 集成当前仅支持 macOS".into());
    }
    if let Some(explicit) = std::env::var_os("CC_SWITCH_SCIENCE_BIN").map(PathBuf::from) {
        return build_runtime(explicit, RuntimeSource::Explicit, true);
    }
    let home = dirs::home_dir().ok_or("无法定位用户 HOME")?;
    let updated = home.join(UPDATED_BIN_RELATIVE);
    if updated.exists() {
        let snapshot = snapshot_updated_runtime(&updated)?;
        return build_runtime(snapshot, RuntimeSource::OfficialUpdated, true);
    }
    let installed = PathBuf::from(OFFICIAL_APP_BIN);
    if installed.exists() {
        return build_runtime(installed, RuntimeSource::InstalledApp, false);
    }
    Err("未找到 Claude Science；请先安装 Claude Science".into())
}

fn runtime_is_current(runtime: &RuntimeRecord) -> bool {
    validate_executable(
        &runtime.path,
        !matches!(runtime.source, RuntimeSource::InstalledApp),
    )
    .map(|bytes| sha256(&bytes) == runtime.sha256)
    .unwrap_or(false)
}

fn save_runtime(runtime: &RuntimeRecord) -> Result<(), String> {
    safe_write(
        &runtime_record_path(),
        &(serde_json::to_vec_pretty(runtime).map_err(|e| format!("序列化 runtime 失败：{e}"))?),
        0o600,
    )
}

fn load_runtime() -> Option<RuntimeRecord> {
    let runtime: RuntimeRecord =
        serde_json::from_slice(&std::fs::read(runtime_record_path()).ok()?).ok()?;
    runtime_is_current(&runtime).then_some(runtime)
}

fn port_accepts_tcp(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        Duration::from_millis(200),
    )
    .is_ok()
}

async fn health_ready(port: u16) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    else {
        return false;
    };
    client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .ok()
        .is_some_and(|response| response.status().is_success())
}

fn process_matches_runtime(pid: u32, runtime: &RuntimeRecord) -> bool {
    if pid == 0 || !runtime_is_current(runtime) {
        return false;
    }
    let Ok(expected) = std::fs::canonicalize(&runtime.path) else {
        return false;
    };
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "txt", "-Fn"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix('n'))
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .any(|path| path == expected)
}

fn verified_runtime_children(parent_pid: u32, runtime: &RuntimeRecord) -> Vec<u32> {
    let Ok(output) = Command::new("/usr/bin/pgrep")
        .args(["-P", &parent_pid.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| process_matches_runtime(*pid, runtime))
        .collect()
}

fn managed_process(runtime: &RuntimeRecord) -> Option<ScienceProcessRecord> {
    let path = process_record_path();
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return None;
    }
    let record: ScienceProcessRecord = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    if record.pid > i32::MAX as u32
        || record.port != SCIENCE_PORT
        || record.sandbox_port != SCIENCE_PREVIEW_PORT
        || record.sock != sandbox_data_dir().join("daemon.sock")
        || !process_matches_runtime(record.pid, runtime)
    {
        return None;
    }
    Some(record)
}

fn first_http_url(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.split_whitespace()
            .find(|word| word.starts_with("http://") || word.starts_with("https://"))
            .map(|word| {
                word.trim_matches(|ch: char| ch == ',' || ch == '"')
                    .to_string()
            })
    })
}

fn science_url(runtime: &RuntimeRecord) -> Result<String, String> {
    if !runtime_is_current(runtime) {
        return Err("Science runtime 在获取登录地址前发生变化".into());
    }

    let home = real_home_dir()?;
    let output = Command::new(&runtime.path)
        .arg("url")
        .arg("--data-dir")
        .arg(sandbox_data_dir())
        .arg("--config")
        .arg(sandbox_config_path())
        .env("HOME", home)
        .output()
        .map_err(|e| format!("获取 Science 登录地址失败：{e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let url = first_http_url(&stdout).ok_or_else(|| {
        let detail = stderr
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("Science 未返回登录地址");
        format!("获取 Science 一次性登录地址失败：{detail}")
    })?;
    let parsed = Url::parse(&url).map_err(|e| format!("Science 登录地址无效：{e}"))?;
    let has_nonce = parsed
        .query_pairs()
        .any(|(key, value)| key == "nonce" && !value.is_empty());
    if !has_nonce {
        return Err("Science 返回的登录地址缺少一次性授权 nonce".into());
    }
    Ok(url)
}

fn open_science_surface(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("Science 登录地址无效：{e}"))?;
    let allowed_host = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if !allowed_host || parsed.port_or_known_default() != Some(SCIENCE_PORT) {
        return Err("Science 登录地址不是 417Switch 隔离 loopback 端口".into());
    }

    if let Some(window) = app.get_webview_window("science") {
        window
            .navigate(parsed)
            .map_err(|e| format!("刷新 Claude Science 窗口失败：{e}"))?;
        let _ = window.unminimize();
        let _ = window.show();
        window
            .set_focus()
            .map_err(|e| format!("聚焦 Claude Science 窗口失败：{e}"))?;
        return Ok(());
    }

    // The nonce page is Science's local loopback gate, not an Anthropic login.
    // Auto-submit only that exact root page; after the redirect the query no
    // longer contains a nonce, so unrelated or upstream sign-in buttons can
    // never be clicked by this script.
    const AUTO_LOCAL_SIGN_IN: &str = r#"
(() => {
  if (location.pathname !== '/' || !new URLSearchParams(location.search).has('nonce')) return;
  let attempts = 0;
  const timer = setInterval(() => {
    attempts += 1;
    const form = document.querySelector('form[action$="/api/auth/nonce"]');
    if (form instanceof HTMLFormElement) {
      clearInterval(timer);
      form.requestSubmit();
      return;
    }
    const button = [...document.querySelectorAll('button')]
      .find((item) => item.textContent?.trim() === 'Sign in');
    if (button) {
      clearInterval(timer);
      button.click();
    } else if (attempts >= 100) {
      clearInterval(timer);
    }
  }, 50);
})();
"#;

    let window = WebviewWindowBuilder::new(app, "science", WebviewUrl::External(parsed))
        .title("Claude Science · 417Switch")
        .inner_size(1180.0, 820.0)
        .min_inner_size(900.0, 650.0)
        .initialization_script(AUTO_LOCAL_SIGN_IN)
        .build()
        .map_err(|e| format!("创建 Claude Science 窗口失败：{e}"))?;
    window
        .set_focus()
        .map_err(|e| format!("聚焦 Claude Science 窗口失败：{e}"))?;
    Ok(())
}

fn response_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

async fn science_local_session(runtime: &RuntimeRecord) -> Result<ScienceLocalSession, String> {
    let url = science_url(runtime)?;
    let parsed = Url::parse(&url).map_err(|e| format!("Science 登录地址无效：{e}"))?;
    let nonce = parsed
        .query_pairs()
        .find_map(|(key, value)| (key == "nonce").then(|| value.into_owned()))
        .filter(|value| !value.is_empty())
        .ok_or("Science 未返回一次性授权 nonce")?;
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return Err("Science 登录地址缺少有效 origin".into());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| format!("创建 Science 本地控制客户端失败：{e}"))?;
    let auth = client
        .post(format!("{origin}/api/auth/nonce"))
        .header(ORIGIN, &origin)
        .form(&[("nonce", nonce.as_str()), ("dest", "/")])
        .send()
        .await
        .map_err(|e| format!("连接 Science 本地认证接口失败：{e}"))?;
    if !auth.status().is_success() {
        return Err(format!("Science 本地认证失败（HTTP {}）", auth.status()));
    }
    let auth_cookie =
        response_cookie(&auth, "operon_auth").ok_or("Science 本地认证响应缺少 operon_auth")?;

    let csrf = client
        .get(format!("{origin}/api/csrf"))
        .header(ORIGIN, &origin)
        .header(COOKIE, format!("operon_auth={auth_cookie}"))
        .send()
        .await
        .map_err(|e| format!("初始化 Science CSRF 失败：{e}"))?;
    if !csrf.status().is_success() {
        return Err(format!("Science CSRF 初始化失败（HTTP {}）", csrf.status()));
    }
    let csrf_cookie =
        response_cookie(&csrf, "operon_csrf").ok_or("Science CSRF 响应缺少 operon_csrf")?;

    let status = client
        .get(format!("{origin}/api/auth/status"))
        .header(ORIGIN, &origin)
        .header(
            COOKIE,
            format!("operon_auth={auth_cookie}; operon_csrf={csrf_cookie}"),
        )
        .send()
        .await
        .map_err(|e| format!("读取 Science 登录状态失败：{e}"))?;
    if !status.status().is_success() {
        return Err(format!(
            "读取 Science 登录状态失败（HTTP {}）",
            status.status()
        ));
    }
    let status: Value = status
        .json()
        .await
        .map_err(|e| format!("解析 Science 登录状态失败：{e}"))?;
    if status.get("authenticated").and_then(Value::as_bool) != Some(true)
        || status.get("email").and_then(Value::as_str) != Some(VIRTUAL_EMAIL)
    {
        return Err("Claude Science 虚拟登录未生效，已拒绝继续打开登录页".into());
    }

    Ok(ScienceLocalSession {
        client,
        origin,
        auth_cookie,
        csrf_cookie,
    })
}

fn load_temporary_host_browse_state() -> Result<TemporaryHostBrowseState, String> {
    let path = temporary_host_browse_state_path();
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(TemporaryHostBrowseState::default());
    };
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|e| format!("检查 Science 临时目录授权状态失败：{e}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.len() > 1024 * 1024
    {
        return Err("Science 临时目录授权状态文件不安全".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("解析 Science 临时目录授权状态失败：{e}"))
}

fn save_temporary_host_browse_state(state: &TemporaryHostBrowseState) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| format!("序列化 Science 临时目录授权状态失败：{e}"))?;
    safe_write(
        &temporary_host_browse_state_path(),
        &[bytes, b"\n".to_vec()].concat(),
        0o600,
    )
}

fn remove_host_grant_keys(preferences: &mut Value, temporary_keys: &[String]) -> bool {
    let mut changed = false;
    if let Some(hosts) = preferences
        .pointer_mut("/approvalGrants/always/allow/host")
        .and_then(Value::as_array_mut)
    {
        let old_len = hosts.len();
        hosts.retain(|item| {
            item.as_str()
                .is_none_or(|value| !temporary_keys.iter().any(|key| key == value))
        });
        changed |= hosts.len() != old_len;
    }
    if let Some(origins) = preferences
        .pointer_mut("/approvalGrants/alwaysOrigins/host")
        .and_then(Value::as_object_mut)
    {
        for key in temporary_keys {
            changed |= origins.remove(key).is_some();
        }
    }
    changed
}

fn remove_temporary_host_browse_grants() -> Result<(), String> {
    let mut state = load_temporary_host_browse_state()?;
    let mut temporary_keys = state
        .paths
        .iter()
        .map(|path| format!("ro:{}", path.display()))
        .collect::<Vec<_>>();
    if !state.legacy_cleaned {
        let home = real_home_dir()?;
        temporary_keys.push(format!("ro:{}", home.display()));
        if let Some(documents) = dirs::document_dir()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .filter(|path| path.is_dir() && path != &home)
        {
            temporary_keys.push(format!("ro:{}", documents.display()));
        }
    }
    if let Some(org_uuid) = active_org(&sandbox_data_dir()) {
        let preferences_path = sandbox_data_dir()
            .join("orgs")
            .join(org_uuid)
            .join("preferences.json");
        if let Ok(bytes) = std::fs::read(&preferences_path) {
            let metadata = std::fs::symlink_metadata(&preferences_path)
                .map_err(|e| format!("检查 Science 偏好设置失败：{e}"))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != current_uid()
                || metadata.len() > 8 * 1024 * 1024
            {
                return Err("Science 偏好设置文件不安全，已拒绝清理临时目录根".into());
            }
            let mut preferences: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("解析 Science 偏好设置失败：{e}"))?;
            if remove_host_grant_keys(&mut preferences, &temporary_keys) {
                let output = serde_json::to_vec_pretty(&preferences)
                    .map_err(|e| format!("序列化 Science 偏好设置失败：{e}"))?;
                safe_write(&preferences_path, &[output, b"\n".to_vec()].concat(), 0o600)?;
            }
        }
    }
    state.paths.clear();
    state.legacy_cleaned = true;
    save_temporary_host_browse_state(&state)?;
    Ok(())
}

fn host_grant_mode<'a>(grants: &'a Value, path: &str) -> Option<&'a str> {
    grants
        .get("grants")
        .and_then(Value::as_array)?
        .iter()
        .find(|item| {
            item.get("hostPath")
                .or_else(|| item.get("host_path"))
                .and_then(Value::as_str)
                == Some(path)
        })?
        .get("mode")
        .and_then(Value::as_str)
}

async fn fetch_host_grants(session: &ScienceLocalSession, cookie: &str) -> Result<Value, String> {
    let response = session
        .client
        .get(format!("{}/api/preferences/host-grants", session.origin))
        .header(ORIGIN, &session.origin)
        .header(COOKIE, cookie)
        .send()
        .await
        .map_err(|e| format!("读取 Science 目录根失败：{e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "读取 Science 目录根失败（HTTP {}）",
            response.status()
        ));
    }
    response
        .json()
        .await
        .map_err(|e| format!("解析 Science 目录根失败：{e}"))
}

async fn revoke_host_browse_roots(runtime: &RuntimeRecord) -> Result<(), String> {
    let mut state = load_temporary_host_browse_state()?;
    if state.paths.is_empty() {
        return Ok(());
    }
    let session = science_local_session(runtime).await?;
    let cookie = format!(
        "operon_auth={}; operon_csrf={}",
        session.auth_cookie, session.csrf_cookie
    );
    let grants = fetch_host_grants(&session, &cookie).await?;
    let mut remaining = Vec::new();
    let mut first_error = None;
    for path in &state.paths {
        let path_text = path.to_string_lossy().to_string();
        if host_grant_mode(&grants, &path_text) != Some("ro") {
            continue;
        }
        let response = session
            .client
            .delete(format!("{}/api/preferences/host-grants", session.origin))
            .header(ORIGIN, &session.origin)
            .header(COOKIE, &cookie)
            .header("x-operon-csrf", &session.csrf_cookie)
            .json(&json!({ "path": path_text }))
            .send()
            .await
            .map_err(|e| format!("撤销 Science 临时宿主浏览入口失败：{e}"))?;
        if !response.status().is_success() {
            first_error
                .get_or_insert_with(|| format!("{}（HTTP {}）", path.display(), response.status()));
            remaining.push(path.clone());
        }
    }
    state.paths = remaining;
    save_temporary_host_browse_state(&state)?;
    first_error
        .map(|detail| Err(format!("撤销部分 Science 临时宿主浏览入口失败：{detail}")))
        .unwrap_or(Ok(()))
}

fn current_science_provider(state: &AppState) -> Result<Provider, String> {
    crate::commands::ensure_science_provider_seed(state)?;
    let id = state
        .db
        .get_current_provider("science")
        .map_err(|e| e.to_string())?
        .ok_or("请先为 Claude Science 选择一个 Provider")?;
    state
        .db
        .get_provider_by_id(&id, "science")
        .map_err(|e| e.to_string())?
        .ok_or("当前 Claude Science Provider 不存在".into())
}

fn valid_model_text(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control))
        .then_some(value)
}

fn provider_model_entries(provider: &Provider) -> Vec<(&'static str, String)> {
    let Some(env) = provider
        .settings_config
        .get("env")
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let value = |key: &str| {
        env.get(key)
            .and_then(Value::as_str)
            .and_then(valid_model_text)
    };
    let display = |model_key: &str, name_key: &str, fallback: Option<&str>| {
        let target = value(model_key).or(fallback)?;
        Some(value(name_key).unwrap_or(target).to_string())
    };

    // Claude Science only exposes model IDs beginning with `claude-`. Use the
    // same stable role aliases that cc-switch's existing model mapper already
    // resolves per provider; this also keeps failover provider-specific.
    let default = value("ANTHROPIC_MODEL");
    let sonnet = display(
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME",
        default,
    );
    let opus = display(
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL_NAME",
        default,
    );
    let haiku = display(
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME",
        default,
    );
    let fable_fallback = value("ANTHROPIC_DEFAULT_OPUS_MODEL").or(default);
    let fable = display(
        "ANTHROPIC_DEFAULT_FABLE_MODEL",
        "ANTHROPIC_DEFAULT_FABLE_MODEL_NAME",
        fable_fallback,
    );

    [
        ("claude-sonnet-4-6", sonnet),
        ("claude-opus-4-8", opus),
        ("claude-haiku-4-5", haiku),
        ("claude-fable-5", fable),
    ]
    .into_iter()
    .filter_map(|(id, name)| name.map(|name| (id, name)))
    .collect()
}

fn apply_provider_model_env(command: &mut Command, provider: &Provider) {
    if let Some(env) = provider
        .settings_config
        .get("env")
        .and_then(Value::as_object)
    {
        for key in [
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "ANTHROPIC_DEFAULT_FABLE_MODEL",
        ] {
            if let Some(value) = env.get(key).and_then(Value::as_str).map(str::trim) {
                if !value.is_empty() {
                    command.env(key, value);
                }
            }
        }
    }
}

pub fn model_list_response(provider: &Provider) -> Value {
    let entries = provider_model_entries(provider);
    let first_id = entries.first().map(|(id, _)| *id);
    let last_id = entries.last().map(|(id, _)| *id);
    json!({
        "data": entries
            .into_iter()
            .map(|(id, display_name)| json!({
                "id": id,
                "type": "model",
                "display_name": display_name,
                "supports_tools": true,
                "created_at": MODELS_CREATED_AT
            }))
            .collect::<Vec<_>>(),
        "has_more": false,
        "first_id": first_id,
        "last_id": last_id
    })
}

pub async fn status(state: &AppState) -> ScienceStatus {
    let provider_name = current_science_provider(state)
        .ok()
        .map(|provider| provider.name);
    if !cfg!(target_os = "macos") {
        return ScienceStatus {
            supported: false,
            installed: false,
            running: false,
            healthy: false,
            port: SCIENCE_PORT,
            provider_name,
            runtime_source: None,
            runtime_version: None,
            message: Some("Claude Science 集成当前仅支持 macOS".into()),
        };
    }
    let runtime = load_runtime().or_else(|| select_runtime().ok());
    let installed = runtime.is_some();
    let healthy = health_ready(SCIENCE_PORT).await;
    // Science 0.1.25 can report `running: false` while its detached daemon is
    // healthy and listening. UI status is intentionally a short HTTP probe;
    // start/open/stop keep the stronger runtime and PID identity checks.
    let launch_mode_current = launch_mode_is_current();
    let running = installed && healthy && launch_mode_current;
    ScienceStatus {
        supported: true,
        installed,
        running,
        healthy,
        port: SCIENCE_PORT,
        provider_name,
        runtime_source: runtime.as_ref().map(|item| item.source.label().to_string()),
        runtime_version: runtime.as_ref().map(|item| item.version.clone()),
        message: if !installed {
            Some("未找到 Claude Science".to_string())
        } else if healthy && !launch_mode_current {
            Some("Claude Science 需要重启一次以启用独立 Provider 路由".to_string())
        } else {
            None
        },
    }
}

async fn ensure_science_proxy(state: &AppState) -> Result<u16, String> {
    let proxy = state.proxy_service.start().await?;
    if proxy.address != "127.0.0.1" && proxy.address != "localhost" {
        return Err("本地代理必须绑定 loopback 才能用于 Claude Science".into());
    }
    if proxy.port == SCIENCE_PREVIEW_PORT || proxy.port == SCIENCE_PORT {
        return Err("本地代理端口与 Science 隔离端口冲突".into());
    }
    Ok(proxy.port)
}

pub async fn restore_proxy_if_running(state: &AppState) -> Result<bool, String> {
    if !cfg!(target_os = "macos") || !launch_mode_is_current() || !health_ready(SCIENCE_PORT).await
    {
        return Ok(false);
    }
    let provider = current_science_provider(state)?;
    crate::commands::validate_science_provider(&provider)?;
    ensure_science_proxy(state).await?;
    Ok(true)
}

pub async fn start(app: &tauri::AppHandle, state: &AppState) -> Result<ScienceStartResult, String> {
    if SCIENCE_PORT == REAL_SCIENCE_PORT || SCIENCE_PREVIEW_PORT == REAL_SCIENCE_PORT {
        return Err("Science 隔离端口命中真实实例保留端口".into());
    }
    let provider = current_science_provider(state)?;
    crate::commands::validate_science_provider(&provider)?;
    // Science always enters through 417Switch's isolated `/science` route so
    // its selected provider is independent from Claude Code. A provider may
    // still point ANTHROPIC_BASE_URL at http://127.0.0.1:9876; in that case the
    // local route forwards Science traffic to 9876 without sharing Claude's
    // current-provider state.
    let proxy_port = ensure_science_proxy(state).await?;
    let proxy_base = format!("http://127.0.0.1:{proxy_port}/science");

    if let Some(existing) = load_runtime() {
        if managed_process(&existing).is_some() && health_ready(SCIENCE_PORT).await {
            if launch_mode_is_current() {
                let url = science_url(&existing)?;
                open_science_surface(app, &url)?;
                return Ok(ScienceStartResult {
                    url,
                    provider_name: provider.name,
                    runtime_source: existing.source.label().to_string(),
                    runtime_version: existing.version,
                });
            }
            // Older 417Switch builds launched Science with the isolated HOME.
            // Restart once so the folder picker sees the real HOME while the
            // explicit data/config paths continue to isolate login and state.
            stop().await?;
        }
    }
    if port_accepts_tcp(SCIENCE_PORT) || port_accepts_tcp(SCIENCE_PREVIEW_PORT) {
        return Err("Science 隔离端口已被其他进程占用".into());
    }

    let runtime = select_runtime()?;
    let host_home = real_home_dir()?;
    ensure_virtual_login()?;
    ensure_private_dir(&sandbox_data_dir())?;
    remove_temporary_host_browse_grants()?;

    let mut command = Command::new(&runtime.path);
    command
        .arg("serve")
        .arg("--data-dir")
        .arg(sandbox_data_dir())
        .arg("--config")
        .arg(sandbox_config_path())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(SCIENCE_PORT.to_string())
        .arg("--sandbox-port")
        .arg(SCIENCE_PREVIEW_PORT.to_string())
        .arg("--no-browser")
        .arg("--no-auto-update")
        .arg("--detached")
        .env("HOME", host_home)
        .env("ANTHROPIC_BASE_URL", &proxy_base)
        .env("NO_PROXY", "127.0.0.1,localhost,::1")
        .env("no_proxy", "127.0.0.1,localhost,::1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_provider_model_env(&mut command, &provider);
    if !runtime_is_current(&runtime) {
        return Err("Science runtime 在启动前发生变化".into());
    }
    let mut launch = command
        .spawn()
        .map_err(|e| format!("启动 Claude Science 失败：{e}"))?;
    let launch_pid = launch.id();
    let mut launch_status = None;
    // With the real HOME visible, Science's first sandbox policy build may
    // inspect a large directory tree before the detached launcher returns.
    // Keep the UI pending instead of reporting a false failure while the
    // daemon is already progressing toward its loopback listener.
    for _ in 0..360 {
        if let Some(status) = launch
            .try_wait()
            .map_err(|e| format!("等待 Claude Science 启动命令失败：{e}"))?
        {
            launch_status = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let Some(launch_status) = launch_status else {
        let children = verified_runtime_children(launch_pid, &runtime);
        for pid in children {
            // SAFETY: each PID was resolved from the launch parent and then
            // verified against the exact private runtime immediately above.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        if process_matches_runtime(launch_pid, &runtime) {
            let _ = launch.kill();
        }
        let _ = launch.wait();
        return Err("Claude Science 后台启动命令等待超过 90 秒，已终止本次受管启动".into());
    };
    if !launch_status.success() {
        return Err("Claude Science 启动命令未成功".into());
    }
    save_runtime(&runtime)?;

    let mut ready = false;
    for _ in 0..240 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if health_ready(SCIENCE_PORT).await && managed_process(&runtime).is_some() {
            ready = true;
            break;
        }
    }
    if !ready {
        return Err("Claude Science 启动后健康检查超时".into());
    }
    save_launch_mode()?;
    let url = science_url(&runtime)?;
    open_science_surface(app, &url)?;
    Ok(ScienceStartResult {
        url,
        provider_name: provider.name,
        runtime_source: runtime.source.label().to_string(),
        runtime_version: runtime.version,
    })
}

pub async fn open(app: &tauri::AppHandle, state: &AppState) -> Result<String, String> {
    let provider = current_science_provider(state)?;
    crate::commands::validate_science_provider(&provider)?;
    ensure_science_proxy(state).await?;
    let runtime = load_runtime().ok_or("没有可确认的 417Switch Science runtime")?;
    if managed_process(&runtime).is_none() || !health_ready(SCIENCE_PORT).await {
        return Err("417Switch 管理的 Claude Science 当前未运行".into());
    }
    let url = science_url(&runtime)?;
    open_science_surface(app, &url)?;
    Ok(url)
}

pub async fn stop() -> Result<(), String> {
    if !sandbox_data_dir().exists() {
        return Ok(());
    }
    let runtime =
        load_runtime().ok_or("无法确认 417Switch 管理的 Science runtime，已拒绝猜测停止")?;
    let Some(process) = managed_process(&runtime) else {
        if !port_accepts_tcp(SCIENCE_PORT) {
            return Ok(());
        }
        return Err("Science 状态或 runtime 身份无法确认，已拒绝停止".into());
    };
    // Revocation is best-effort. A stale Science daemon can keep its HTTP
    // control endpoint half-open, so never let cleanup delay the actual stop.
    let _ = tokio::time::timeout(Duration::from_secs(3), revoke_host_browse_roots(&runtime)).await;
    let mut stop_command = Command::new(&runtime.path)
        .arg("stop")
        .arg("--data-dir")
        .arg(sandbox_data_dir())
        .arg("--config")
        .arg(sandbox_config_path())
        .env("HOME", real_home_dir()?)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("停止 Claude Science 失败：{e}"))?;
    let stop_pid = stop_command.id();
    let mut stop_status = None;
    for _ in 0..50 {
        if let Some(status) = stop_command
            .try_wait()
            .map_err(|e| format!("等待 Claude Science stop 命令失败：{e}"))?
        {
            stop_status = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if stop_status.is_none() {
        // Science 0.1.25 can leave the foreground `stop` helper waiting on a
        // stale daemon socket forever. The helper was launched from the exact
        // snapshotted runtime above; revalidate it before terminating it.
        if process_matches_runtime(stop_pid, &runtime) {
            let _ = stop_command.kill();
        }
        let _ = stop_command.wait();
    }
    for _ in 0..50 {
        if !port_accepts_tcp(SCIENCE_PORT) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Science 0.1.25 may report a stale lock and return success after deleting
    // the lock while leaving the detached daemon alive. We captured the
    // private lock before invoking stop; revalidate that the same PID still
    // executes the exact snapshotted runtime before asking it to terminate.
    if process_matches_runtime(process.pid, &runtime) {
        // SAFETY: the PID is range-checked above and was revalidated against
        // the exact private Science runtime immediately before this signal.
        let signaled = unsafe { libc::kill(process.pid as i32, libc::SIGTERM) } == 0;
        if signaled {
            for _ in 0..50 {
                if !port_accepts_tcp(SCIENCE_PORT) && !port_accepts_tcp(SCIENCE_PREVIEW_PORT) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    let stop_detail = match stop_status {
        Some(status) if status.success() => "stop 返回成功",
        Some(_) => "stop 返回失败",
        None => "stop 命令超时",
    };
    Err(format!(
        "Science {stop_detail}，但隔离端口仍在监听；未向未知 PID 发送信号"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_first_http_url() {
        assert_eq!(
            first_http_url("note\nopen https://127.0.0.1:15890/path next"),
            Some("https://127.0.0.1:15890/path".into())
        );
    }

    #[test]
    fn provider_model_catalog_uses_science_visible_role_aliases() {
        let provider = Provider::with_id(
            "test".into(),
            "Test".into(),
            json!({
                "env": {
                    "ANTHROPIC_MODEL": "model-b",
                    "ANTHROPIC_DEFAULT_SONNET_MODEL": "model-a",
                    "ANTHROPIC_DEFAULT_OPUS_MODEL": "model-b"
                }
            }),
            None,
        );
        let response = model_list_response(&provider);
        let data = response["data"].as_array().unwrap();
        assert_eq!(data.len(), 4);
        assert_eq!(data[0]["id"], "claude-sonnet-4-6");
        assert_eq!(data[0]["display_name"], "model-a");
        assert_eq!(data[1]["id"], "claude-opus-4-8");
        assert_eq!(data[1]["display_name"], "model-b");
        assert!(data.iter().all(|model| model["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("claude-"))));
        assert_eq!(response["first_id"], "claude-sonnet-4-6");
        assert_eq!(response["last_id"], "claude-fable-5");
    }

    #[test]
    fn reserved_real_port_is_not_used() {
        assert_ne!(SCIENCE_PORT, REAL_SCIENCE_PORT);
        assert_ne!(SCIENCE_PREVIEW_PORT, REAL_SCIENCE_PORT);
    }

    #[test]
    fn temporary_root_cleanup_preserves_specific_folder_grants() {
        let mut preferences = json!({
            "approvalGrants": {
                "always": {
                    "allow": {
                        "host": [
                            "ro:/Users/example",
                            "ro:/Users/example/Documents",
                            "rw:/Users/example/Documents/project"
                        ]
                    }
                },
                "alwaysOrigins": {
                    "host": {
                        "ro:/Users/example": { "userId": "local-dev" },
                        "ro:/Users/example/Documents": { "userId": "local-dev" },
                        "rw:/Users/example/Documents/project": { "userId": "local-dev" }
                    }
                }
            }
        });
        let temporary = vec![
            "ro:/Users/example".to_string(),
            "ro:/Users/example/Documents".to_string(),
        ];

        assert!(remove_host_grant_keys(&mut preferences, &temporary));
        assert_eq!(
            preferences.pointer("/approvalGrants/always/allow/host"),
            Some(&json!(["rw:/Users/example/Documents/project"]))
        );
        assert_eq!(
            preferences
                .pointer("/approvalGrants/alwaysOrigins/host")
                .and_then(Value::as_object)
                .map(|origins| origins.keys().cloned().collect::<Vec<_>>()),
            Some(vec!["rw:/Users/example/Documents/project".to_string()])
        );
    }
}
