//! Claude Science integration.
//!
//! The isolated-login format and runtime boundaries are adapted from the
//! MIT-licensed SuperJJ007/CSSwitch project. 417Switch keeps Science account
//! data and credentials in its own data directory, exposes approved real user
//! folders through Science's built-in browser, and routes inference through
//! the configured local loopback endpoint.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aho_corasick::AhoCorasick;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use flate2::read::GzDecoder;
use hkdf::Hkdf;
use reqwest::header::{COOKIE, ORIGIN, SET_COOKIE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tauri_plugin_opener::OpenerExt;
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
const SCIENCE_LAUNCH_MODE_ZH: &str =
    "real-home-explicit-config-science-provider-zh-cn-v7-complete-settings-auto-update";
const SCIENCE_LAUNCH_MODE_ORIGINAL: &str =
    "real-home-explicit-config-science-provider-original-v1-auto-update";
const SCIENCE_ZH_PATCH_VERSION: &str = "zh-cn-v5";
const BUN_TRAILER: &[u8] = b"\n---- Bun! ----\n";
const SCIENCE_ZH_PATCH_SENTINEL: &str = "417switch-science-zh-cn-v5";
const SCIENCE_ZH_PATCH_ASSET: &str = "web-dist/assets/417switch-zh-cn-v5.js";
const SCIENCE_ZH_PATCH_TAG: &str = r#"<script defer data-417switch-science-zh-cn-v5 src="./assets/417switch-zh-cn-v5.js"></script>"#;
const SCIENCE_ZH_CATALOG: &str = include_str!("science_zh_cn.json");
const SCIENCE_ZH_PATCH_SCRIPT: &str = r#"// 417switch-science-zh-cn-v5
(() => {
  'use strict';
  if (document.documentElement.dataset.switch417ScienceZhCn) return;
  document.documentElement.dataset.switch417ScienceZhCn = '1';
  document.documentElement.lang = 'zh-CN';

  const exact = new Map(Object.entries({
    'New session': '新建会话',
    'New Session': '新建会话',
    'New project': '新建项目',
    'New Project': '新建项目',
    'Projects': '项目',
    'Project': '项目',
    'Sessions': '会话',
    'Session': '会话',
    'Files': '文件',
    'File': '文件',
    'Customize': '自定义',
    'Settings': '设置',
    'General': '通用',
    'Appearance': '外观',
    'Permissions': '权限',
    'Compute': '计算',
    'Skills': '技能',
    'Skill': '技能',
    'Connectors': '连接器',
    'Connector': '连接器',
    'Search': '搜索',
    'Search projects': '搜索项目',
    'Search sessions': '搜索会话',
    'Search files': '搜索文件',
    'Upload': '上传',
    'Upload files': '上传文件',
    'Cancel': '取消',
    'Save': '保存',
    'Save changes': '保存更改',
    'Delete': '删除',
    'Delete project': '删除项目',
    'Continue': '继续',
    'Sign in': '登录',
    'Sign out': '退出登录',
    'Start': '开始',
    'Stop': '停止',
    'Retry': '重试',
    'Run': '运行',
    'Running': '运行中',
    'Share': '分享',
    'Download': '下载',
    'Open': '打开',
    'Open file': '打开文件',
    'Close': '关闭',
    'Back': '返回',
    'Next': '下一步',
    'Done': '完成',
    'Create': '创建',
    'Edit': '编辑',
    'Rename': '重命名',
    'Duplicate': '创建副本',
    'Move': '移动',
    'Copy': '复制',
    'Refresh': '刷新',
    'Add': '添加',
    'Remove': '移除',
    'Confirm': '确认',
    'Apply': '应用',
    'Reset': '重置',
    'Clear': '清除',
    'Select': '选择',
    'Select all': '全选',
    'Learn more': '了解更多',
    'Show more': '显示更多',
    'Show less': '收起',
    'Details': '详情',
    'Overview': '概览',
    'Activity': '活动',
    'History': '历史记录',
    'Recent': '最近',
    'Favorites': '收藏',
    'Archived': '已归档',
    'Archive': '归档',
    'Unarchive': '取消归档',
    'Name': '名称',
    'Description': '说明',
    'Status': '状态',
    'Created': '创建时间',
    'Updated': '更新时间',
    'Type': '类型',
    'Size': '大小',
    'Actions': '操作',
    'Enabled': '已启用',
    'Disabled': '已停用',
    'Enable': '启用',
    'Disable': '停用',
    'Connected': '已连接',
    'Disconnected': '未连接',
    'Connect': '连接',
    'Disconnect': '断开连接',
    'Loading...': '正在加载…',
    'Saving...': '正在保存…',
    'Uploading...': '正在上传…',
    'Processing...': '正在处理…',
    'No results': '没有结果',
    'No files': '没有文件',
    'No projects yet': '还没有项目',
    'No sessions yet': '还没有会话',
    'Something went wrong': '出现了一些问题',
    'Try again': '重试',
    'Are you sure?': '确定要继续吗？',
    'This action cannot be undone.': '此操作无法撤销。',
    'Ask Claude anything': '向 Claude 提问',
    'What would you like to work on?': '你想研究什么？',
    'Send message': '发送消息',
    'Attach files': '添加附件',
    'Thinking': '思考中',
    'Working': '处理中',
    'Completed': '已完成',
    'Failed': '失败',
    'Pending': '等待中',
    'Queued': '排队中',
    'Approve': '批准',
    'Deny': '拒绝',
    'Allow': '允许',
    'Always allow': '始终允许',
    'Allow once': '仅允许一次',
    'Model': '模型',
    'Data': '数据',
    'Sources': '来源',
    'Artifacts': '产物',
    'Preview': '预览',
    'Terminal': '终端',
    'Environment': '环境',
    'Local': '本地',
    'Remote': '远程',
    'Documentation': '文档',
    'Help': '帮助',
    'Feedback': '反馈',
    'Account': '账户',
    'Language': '语言',
    'Theme': '主题',
    'System': '跟随系统',
    'Light': '浅色',
    'Dark': '深色'
    ,'About': '关于'
    ,'Active model': '当前模型'
    ,'Add & configure': '添加并配置'
    ,'Add connector': '添加连接器'
    ,'Add to message': '添加到消息'
    ,'Agree & save': '同意并保存'
    ,'Allow for this conversation on': '本次会话允许访问'
    ,'Allow for this project on': '本项目允许访问'
    ,'Allow globally on': '全局允许访问'
    ,'Allow scope': '允许范围'
    ,'Allowed domains': '已允许的域名'
    ,'Always allow downloads from': '始终允许从此处下载'
    ,'Always allow this host': '始终允许此主机'
    ,'Ask each time': '每次询问'
    ,'Attach connector': '添加连接器'
    ,'Attach skill': '添加技能'
    ,'Back to Claude': '返回 Claude'
    ,'Back to dashboard': '返回主页'
    ,'Back to parent': '返回上一级'
    ,'Back to session root': '返回会话根目录'
    ,'Back to sessions': '返回会话列表'
    ,'Back to settings': '返回设置'
    ,'Bookmark': '添加书签'
    ,'Bookmarked': '已添加书签'
    ,'Bookmarks': '书签'
    ,'Branch in new session': '在新会话中分支'
    ,'Browse host filesystem': '浏览本机文件系统'
    ,'Browsing artifacts': '正在浏览产物'
    ,'Browsing sessions': '正在浏览会话'
    ,'Cancel edit': '取消编辑'
    ,'Cancelled': '已取消'
    ,'Change': '更改'
    ,'Chat': '聊天'
    ,'Chats': '聊天'
    ,'Clear search': '清除搜索'
    ,'Close Files': '关闭文件面板'
    ,'Close artifact': '关闭产物'
    ,'Close others': '关闭其他标签页'
    ,'Close session': '关闭会话'
    ,'Close settings': '关闭设置'
    ,'Close side chat': '关闭侧边聊天'
    ,'Close tab': '关闭标签页'
    ,'Cloud compute': '云端计算'
    ,'Connector tools': '连接器工具'
    ,'Connectors & skills': '连接器与技能'
    ,'Current session': '当前会话'
    ,'Default model': '默认模型'
    ,'Delete agent': '删除智能体'
    ,'Delete annotation': '删除批注'
    ,'Delete bookmark': '删除书签'
    ,'Delete comment': '删除评论'
    ,'Delete skill': '删除技能'
    ,'Detach connector': '移除连接器'
    ,'Detach skill': '移除技能'
    ,'Distill this session': '提炼此会话'
    ,'Download All (Zip)': '全部下载（ZIP）'
    ,'Download artifacts': '下载产物'
    ,'Download logs': '下载日志'
    ,'Download this artifact': '下载此产物'
    ,'Drop files to attach': '拖放文件以添加附件'
    ,'Edit bookmark': '编辑书签'
    ,'Edit message': '编辑消息'
    ,'Edit session': '编辑会话'
    ,'Edit skill': '编辑技能'
    ,'Export session': '导出会话'
    ,'Feedback comment': '反馈说明'
    ,'Full history': '完整历史记录'
    ,'Give negative feedback': '提供负面反馈'
    ,'Give positive feedback': '提供正面反馈'
    ,'Go back': '返回'
    ,'Host files': '本机文件'
    ,'Jump to bookmark': '跳转到书签'
    ,'Jump to your last message': '跳转到你的上一条消息'
    ,'Load skill': '加载技能'
    ,'Loading allowlist': '正在加载允许列表'
    ,'Local compute': '本地计算'
    ,'Manage compute': '管理计算资源'
    ,'Match session model': '使用会话模型'
    ,'Messages': '消息'
    ,'Model endpoint': '模型端点'
    ,'Model endpoints': '模型端点'
    ,'SSH hosts': 'SSH 主机'
    ,'Add SSH host': '添加 SSH 主机'
    ,'No SSH hosts yet': '还没有 SSH 主机'
    ,'Cloud providers': '云服务商'
    ,'Servers, clusters or job submission nodes from your SSH host lists': '来自 SSH 主机列表的服务器、集群或作业提交节点'
    ,'Serverless GPUs on your own Modal account — connect in about a minute.': '使用你自己的 Modal 账户运行无服务器 GPU——大约一分钟即可连接。'
    ,'Scientific models Claude can reach at a local or remote URL': 'Claude 可通过本地或远程 URL 访问的科学模型'
    ,'Run heavy analysis jobs on your own servers and clusters, or on serverless GPUs using your cloud account. Model endpoints let Claude call scientific models like protein structure predictors.': '在你自己的服务器和集群上运行重型分析任务，也可使用你的云账户调用无服务器 GPU。模型端点可让 Claude 调用蛋白质结构预测等科学模型。'
    ,'BioNeMo model services — local NIM docker containers, or externally hosted NIM APIs. Each registration asks you individually; disabling stops and removes them all.': 'BioNeMo 模型服务——可使用本地 NIM Docker 容器或外部托管的 NIM API。每次注册都会单独征求你的同意；停用后会停止并移除全部服务。'
    ,'Model unavailable': '模型不可用'
    ,'More models': '更多模型'
    ,'Move session to project': '将会话移至项目'
    ,'New category': '新建分类'
    ,'New skill': '新建技能'
    ,'New specialist': '新建专家'
    ,'No allowed domains yet': '还没有已允许的域名'
    ,'No compute running in this session': '此会话中没有运行中的计算任务'
    ,'No folders yet.': '还没有文件夹。'
    ,'No issues found': '未发现问题'
    ,'No models': '没有可用模型'
    ,'No search results': '没有搜索结果'
    ,'No session open. Start one from the left rail.': '尚未打开会话，请从左侧栏开始。'
    ,'No subfolders.': '没有子文件夹。'
    ,'No text output': '没有文本输出'
    ,'Open Claude.ai': '打开 Claude.ai'
    ,'Open above': '在上方打开'
    ,'Open below': '在下方打开'
    ,'Open fullscreen': '全屏打开'
    ,'Open in Artifact Viewer': '在产物查看器中打开'
    ,'Open in Files': '在文件面板中打开'
    ,'Open in split view': '在分屏中打开'
    ,'Open in viewer': '在查看器中打开'
    ,'Open network settings': '打开网络设置'
    ,'Open plan in panel': '在面板中打开计划'
    ,'Open subagent transcript': '打开子智能体记录'
    ,'Open tabs': '打开的标签页'
    ,'Open to the side': '在侧边打开'
    ,'Other artifacts': '其他产物'
    ,'Other project': '其他项目'
    ,'Other projects': '其他项目'
    ,'Permission details': '权限详情'
    ,'Project:': '项目：'
    ,'Publish skill': '发布技能'
    ,'Remote files': '远程文件'
    ,'Rename artifact': '重命名产物'
    ,'Research': '科研'
    ,'Research preview': '科研预览'
    ,'Retry builds': '重试构建'
    ,'Retrying': '正在重试'
    ,'Reviewer model': '审查模型'
    ,'Run Python code?': '运行 Python 代码？'
    ,'Run R code?': '运行 R 代码？'
    ,'Run a shell command?': '运行 Shell 命令？'
    ,'Running a tool': '正在运行工具'
    ,'Running in background': '正在后台运行'
    ,'Same as main model': '与主模型相同'
    ,'Save and continue': '保存并继续'
    ,'Save anyway': '仍然保存'
    ,'Save as skill': '保存为技能'
    ,'Save image': '保存图片'
    ,'Save key': '保存密钥'
    ,'Search specialists': '搜索专家'
    ,'Search tools': '搜索工具'
    ,'Select model': '选择模型'
    ,'Send a message to interrupt': '发送消息以中断'
    ,'Send feedback': '发送反馈'
    ,'Sending message': '正在发送消息'
    ,'Session actions': '会话操作'
    ,'Session deleted': '会话已删除'
    ,'Session failed': '会话失败'
    ,'Session on hold': '会话已暂停'
    ,'Session options': '会话选项'
    ,'Session preview': '会话预览'
    ,'Session:': '会话：'
    ,'Side chat': '侧边聊天'
    ,'Sign in again to continue.': '请重新登录以继续。'
    ,'Sign in with Claude.ai': '使用 Claude.ai 登录'
    ,'Sign in with a different account': '使用其他账户登录'
    ,'Skill suggestions': '技能建议'
    ,'Skills you added from GitHub': '从 GitHub 添加的技能'
    ,'Stop & restart': '停止并重启'
    ,'Stop cell': '停止单元格'
    ,'Stop dictation': '停止听写'
    ,'Stopped by you': '已由你停止'
    ,'Subagent model': '子智能体模型'
    ,'This project': '此项目'
    ,'This session': '此会话'
    ,'This session\'s model': '此会话的模型'
    ,'Unknown connector': '未知连接器'
    ,'Capabilities': '功能'
    ,'Specialists': '专家'
    ,'Memory': '记忆'
    ,'Network': '网络'
    ,'Workspace': '工作区'
    ,'Credentials': '凭据'
    ,'Storage': '存储'
    ,'Usage': '用量'
    ,'Organization': '组织'
    ,'Organization data': '组织数据'
    ,'Share this ID with Anthropic support when reporting an issue.': '报告问题时，请将此 ID 提供给 Anthropic 支持团队。'
    ,'Copy projects and skills from another organization you belong to.': '从你所属的其他组织复制项目和技能。'
    ,'Manage billing': '管理订阅'
    ,'plan': '套餐'
    ,'Applied as your default for new sessions.': '应用为新会话的默认模型。'
    ,'Reasoning effort': '推理强度'
    ,'How long Claude thinks before responding. Higher effort is more thorough but slower and uses more of your limits. Applies to Opus models.': '控制 Claude 回答前的思考时长。强度越高，推理越充分，但速度更慢且会消耗更多额度。适用于 Opus 模型。'
    ,'Low': '低'
    ,'Medium': '中'
    ,'High': '高'
    ,'Subagent model': '子智能体模型'
    ,'Model used by subagents when Delegation is on.': '启用任务委派后，子智能体使用的模型。'
    ,'Reviewer model': '审查模型'
    ,'Model the Reviewer uses for background review when work completes. Applies to all sessions; a session\'s own Reviewer model setting overrides it.': '工作完成后，审查器在后台检查时使用的模型。此设置应用于所有会话；会话自己的审查模型设置会覆盖它。'
    ,'Automatically switch models when a message is flagged': '消息被标记时自动切换模型'
    ,'When a safety filter pauses a session, retry it right away on the suggested fallback model instead of waiting for you. Applies to every project and session on this Claude Science install.': '当安全过滤器暂停会话时，立即使用建议的备用模型重试，无需等待你操作。此设置应用于本机 Claude Science 的所有项目和会话。'
    ,'Licensing': '许可'
    ,'Use intent': '使用目的'
    ,'Selects which license notice you see for skills that restrict non-commercial use.': '选择遇到限制非商业用途的技能时显示的许可提示。'
    ,'Commercial use (default)': '商业用途（默认）'
    ,'Resources restricted to non-commercial use will ask you to confirm a commercial license before loading.': '加载仅限非商业用途的资源前，会要求你确认拥有商业许可。'
    ,'Non-commercial use': '非商业用途'
    ,'Declare that your use is non-commercial (academic, personal, or other non-commercial purposes).': '声明你的用途为非商业用途（学术、个人或其他非商业目的）。'
    ,'Couldn\'t load the current use intent.': '无法加载当前使用目的。'
    ,'Appearance': '外观'
    ,'Response font': '回答字体'
    ,'Serif': '衬线体'
    ,'Sans serif': '无衬线体'
    ,'Build:': '构建版本：'
    ,'Channel:': '更新通道：'
    ,'Last checked': '上次检查'
    ,'Version and update channel': '版本和更新通道'
    ,'Automatic updates are off': '自动更新已关闭'
    ,'Automatic updates are on': '自动更新已开启'
    ,'Updates are applied by the VM automatically': '更新由虚拟机自动应用'
    ,'Check for updates': '检查更新'
    ,'Checking…': '正在检查…'
    ,'Update available': '有可用更新'
    ,'Applying…': '正在应用…'
    ,'Restart to update': '重启并更新'
    ,'Update now': '立即更新'
    ,'You\'re up to date.': '当前已是最新版本。'
    ,'Third-Party Licenses': '第三方许可'
    ,'Directory connectors unavailable': '目录连接器不可用'
    ,'Showing your last-known connectors': '正在显示上次已知的连接器'
    ,'Your claude.ai session has expired. Sign in again to restore your directory connectors.': '你的 claude.ai 会话已过期。请重新登录以恢复目录连接器。'
    ,'Your claude.ai session has expired — the list below may be out of date. Sign in again to refresh it.': '你的 claude.ai 会话已过期，下面的列表可能不是最新的。请重新登录以刷新。'
    ,'You\'re not signed in to claude.ai — the list below is from a cached copy and may be out of date. Run `claude-science login` to refresh it.': '你尚未登录 claude.ai，下面显示的是缓存副本，可能不是最新的。请运行 `claude-science login` 刷新。'
    ,'Directory connector access is being set up automatically. Check back shortly, or sign in again to set it up now.': '正在自动配置目录连接器访问权限。请稍后再试，或立即重新登录以完成配置。'
    ,'Directory connector access is being set up automatically — the list below may be out of date until then. Sign in again to refresh it now.': '正在自动配置目录连接器访问权限，完成前下面的列表可能不是最新的。你也可以立即重新登录进行刷新。'
    ,'Can\'t reach claude.ai': '无法连接 claude.ai'
    ,'Check your network connection. If you\'re on a corporate network, verify your SSO/VPN session is active. Directory connectors will reappear once claude.ai is reachable.': '请检查网络连接。如果你使用企业网络，请确认 SSO/VPN 会话仍然有效。恢复连接 claude.ai 后，目录连接器会重新出现。'
    ,'claude.ai is responding slowly': 'claude.ai 响应缓慢'
    ,'claude.ai is responding slowly — directory connectors will appear shortly. No action needed on your end.': 'claude.ai 响应缓慢，目录连接器稍后会出现，无需你进行操作。'
    ,'Default': '默认'
    ,'Forward': '前进'
    ,'Maximize': '最大化'
    ,'Restore size': '恢复大小'
    ,'Package mirror': '软件包镜像'
    ,'Copied': '已复制'
    ,'Import…': '导入…'
    ,'Skip to main content': '跳到主要内容'
    ,'Recent sessions': '最近会话'
    ,'sessions': '个会话'
    ,'Project actions': '项目操作'
    ,'Not signed in, or your session has expired. Please sign out and sign in again.': '尚未登录或会话已过期。请退出登录后重新登录。'
    ,'Clear selection': '清除选择'
    ,'Contact email': '联系邮箱'
    ,'Not set': '未设置'
    ,'When allowed, shared with research data services that ask for a contact email (such as those run by NCBI, EBI, and OurResearch) on requests made on your behalf.': '获得允许后，当研究数据服务（例如 NCBI、EBI 和 OurResearch 提供的服务）要求联系邮箱时，会在代表你发出的请求中提供该邮箱。'
    ,'Set': '设置'
    ,'Diagnostics': '诊断'
    ,'Bundles system logs for sharing with support. File paths and host names are redacted. Conversations and credentials aren\'t included. Review the bundle before sharing.': '打包系统日志以便提供给支持团队。文件路径和主机名会被隐藏，不包含对话和凭据。分享前请先检查压缩包内容。'
    ,'Filter connectors': '筛选连接器'
    ,'Search connectors…': '搜索连接器…'
    ,'All': '全部'
    ,'Featured': '精选'
    ,'Research connectors from Anthropic': 'Anthropic 提供的科研连接器'
    ,'Directory': '目录'
    ,'Syncs with the Claude Connectors Directory': '与 Claude 连接器目录同步'
    ,'Custom': '自定义'
    ,'Connectors you added': '你添加的连接器'
    ,'Add a custom connector to connect your own server': '添加自定义连接器以连接你自己的服务器'
    ,'Browse Connectors Directory': '浏览连接器目录'
    ,'Remote URL': '远程 URL'
    ,'Connect a web MCP server': '连接 Web MCP 服务器'
    ,'Local command': '本地命令'
    ,'Run a local MCP server on this machine': '在此电脑上运行本地 MCP 服务器'
  }));
  for (const [key, value] of Object.entries(__417SWITCH_ZH_CATALOG__)) exact.set(key, value);

  const skip = new Set(['SCRIPT', 'STYLE', 'CODE', 'PRE', 'TEXTAREA', 'KBD', 'SAMP']);
  const relativeTime = [
    [/^(\d+)m ago$/, match => `${match[1]} 分钟前`],
    [/^(\d+)h ago$/, match => `${match[1]} 小时前`],
    [/^(\d+)d ago$/, match => `${match[1]} 天前`]
  ];
  const translate = value => {
    const translated = exact.get(value);
    if (translated) return translated;
    if (value === 'just now') return '刚刚';
    for (const [pattern, replacement] of relativeTime) {
      const match = value.match(pattern);
      if (match) return replacement(match);
    }
    let match = value.match(/^All \((\d+)\)$/);
    if (match) return `全部（${match[1]}）`;
    match = value.match(/^active (\d+)([mhd]) ago$/);
    if (match) {
      const unit = {m: '分钟', h: '小时', d: '天'}[match[2]];
      return `${match[1]} ${unit}前活跃`;
    }
    match = value.match(/^(\d+) minutes? ago$/);
    if (match) return `${match[1]} 分钟前`;
    match = value.match(/^added (\d+)([mhd]) ago$/);
    if (match) {
      const unit = {m: '分钟前', h: '小时前', d: '天前'}[match[2]];
      return `${match[1]} ${unit}添加`;
    }
    match = value.match(/^Resets in (\d+) min$/);
    if (match) return `${match[1]} 分钟后重置`;
    match = value.match(/^Resets in (\d+) hr(?: (\d+) min)?$/);
    if (match) return `${match[1]} 小时${match[2] ? ` ${match[2]} 分钟` : ''}后重置`;
    match = value.match(/^Resets in (\d+) days?$/);
    if (match) return `${match[1]} 天后重置`;
    match = value.match(/^Nothing matches "(.+)"\.$/);
    if (match) return `没有匹配“${match[1]}”的结果。`;
    match = value.match(/^ID: (.+)$/);
    if (match) return `ID：${match[1]}`;
    match = value.match(/^(\d+) of (\d+) categories used$/);
    if (match) return `已使用 ${match[1]} / ${match[2]} 个分类`;
    match = value.match(/^Category limit reached \((\d+) of (\d+)\)\./);
    if (match) return value.replace(match[0], `已达到分类上限（${match[1]} / ${match[2]}）。`);
    match = value.match(/^Updated (.+) ago$/);
    if (match) return `${match[1]}前更新`;
    match = value.match(/^Browse files on (.+?)( \(unavailable\))?$/);
    if (match) return `浏览 ${match[1]} 上的文件${match[2] ? '（不可用）' : ''}`;
    match = value.match(/^Files on (.+)$/);
    if (match) return `${match[1]} 上的文件`;
    match = value.match(/^Revoke all (.+) grants\?$/);
    if (match) return `撤销全部${match[1]}授权？`;
    match = value.match(/^Attached to (\d+) agents?$/);
    if (match) return `已附加到 ${match[1]} 个专家助手`;
    for (const [prefix, translatedPrefix] of [
      ['Account menu — ', '账户菜单 — '],
      ['Open project ', '打开项目 '],
      ['Open conversation ', '打开会话 '],
      ['Open artifact ', '打开产物 '],
      ['View ', '查看 '],
      ['Edit ', '编辑 '],
      ['Remove ', '移除 '],
      ['Stop ', '停止 '],
      ['Back to ', '返回 '],
      ['Actions for ', '操作：'],
      ['Permission for ', '权限：'],
      ['Disable ', '停用 '],
      ['Enable ', '启用 '],
      ['Copy organization ID ', '复制组织 ID ']
    ]) {
      if (value.startsWith(prefix)) return translatedPrefix + value.slice(prefix.length);
    }
    return value;
  };
  const translateText = node => {
    const parent = node.parentElement;
    if (!parent || skip.has(parent.tagName) || parent.closest('[contenteditable="true"]')) return;
    const value = node.nodeValue || '';
    const match = value.match(/^(\s*)(.*?)(\s*)$/s);
    if (!match || !match[2]) return;
    const translated = translate(match[2]);
    if (translated !== match[2]) node.nodeValue = match[1] + translated + match[3];
  };
  const translateAttributes = element => {
    for (const attr of ['placeholder', 'title', 'aria-label', 'data-tooltip-content']) {
      if (element.hasAttribute(attr)) {
        const value = element.getAttribute(attr);
        const translated = translate(value);
        if (translated !== value) element.setAttribute(attr, translated);
      }
    }
  };
  const translateElement = element => {
    if (!(element instanceof Element) || skip.has(element.tagName)) return;
    translateAttributes(element);
    for (const child of element.querySelectorAll('[placeholder], [title], [aria-label], [data-tooltip-content]')) {
      translateAttributes(child);
    }
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) translateText(node);
  };
  translateElement(document.body);
  new MutationObserver(records => {
    for (const record of records) {
      if (record.type === 'characterData') translateText(record.target);
      for (const node of record.addedNodes) {
        if (node.nodeType === Node.TEXT_NODE) translateText(node);
        else translateElement(node);
      }
      if (record.type === 'attributes') translateElement(record.target);
    }
  }).observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ['placeholder', 'title', 'aria-label', 'data-tooltip-content']
  });
})();
"#;
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

fn chinese_patch_enabled() -> bool {
    crate::settings::get_settings().science_chinese_patch_enabled
}

fn expected_launch_mode(chinese_patch: bool) -> &'static str {
    if chinese_patch {
        SCIENCE_LAUNCH_MODE_ZH
    } else {
        SCIENCE_LAUNCH_MODE_ORIGINAL
    }
}

fn launch_mode_is_current() -> bool {
    let expected = expected_launch_mode(chinese_patch_enabled());
    std::fs::read_to_string(launch_mode_path())
        .map(|value| value.trim() == expected)
        .unwrap_or(false)
}

fn save_launch_mode(chinese_patch: bool) -> Result<(), String> {
    safe_write(
        &launch_mode_path(),
        format!("{}\n", expected_launch_mode(chinese_patch)).as_bytes(),
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

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or("Science runtime 结构越界")?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or("Science runtime 结构越界")?;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}

fn macho_name_matches(bytes: &[u8], offset: usize, expected: &[u8]) -> bool {
    bytes
        .get(offset..offset + 16)
        .and_then(|name| name.split(|byte| *byte == 0).next())
        == Some(expected)
}

fn bun_payload_from_macho(bytes: &[u8]) -> Result<&[u8], String> {
    if read_u32_le(bytes, 0)? != 0xfeed_facf {
        return Err("Claude Science runtime 不是受支持的 64 位 Mach-O".into());
    }
    let command_count = read_u32_le(bytes, 16)? as usize;
    let commands_size = read_u32_le(bytes, 20)? as usize;
    let commands_end = 32usize
        .checked_add(commands_size)
        .filter(|end| *end <= bytes.len())
        .ok_or("Claude Science Mach-O load commands 越界")?;
    let mut command_offset = 32usize;

    for _ in 0..command_count {
        let command = read_u32_le(bytes, command_offset)?;
        let command_size = read_u32_le(bytes, command_offset + 4)? as usize;
        let command_end = command_offset
            .checked_add(command_size)
            .filter(|end| *end <= commands_end && command_size >= 8)
            .ok_or("Claude Science Mach-O load command 无效")?;
        if command == 0x19 && command_size >= 72 {
            let section_count = read_u32_le(bytes, command_offset + 64)? as usize;
            let sections_size = section_count
                .checked_mul(80)
                .and_then(|size| 72usize.checked_add(size))
                .filter(|size| *size <= command_size)
                .ok_or("Claude Science Mach-O section 表无效")?;
            let _ = sections_size;
            if macho_name_matches(bytes, command_offset + 8, b"__BUN") {
                for index in 0..section_count {
                    let section = command_offset + 72 + index * 80;
                    if macho_name_matches(bytes, section, b"__bun")
                        && macho_name_matches(bytes, section + 16, b"__BUN")
                    {
                        let section_size = usize::try_from(read_u64_le(bytes, section + 40)?)
                            .map_err(|_| "Claude Science __bun section 过大")?;
                        let section_offset = read_u32_le(bytes, section + 48)? as usize;
                        let section_bytes = bytes
                            .get(section_offset..section_offset.saturating_add(section_size))
                            .ok_or("Claude Science __bun section 越界")?;
                        let payload_size = usize::try_from(read_u64_le(section_bytes, 0)?)
                            .map_err(|_| "Claude Science Bun payload 过大")?;
                        return section_bytes
                            .get(8..8usize.saturating_add(payload_size))
                            .ok_or_else(|| "Claude Science Bun payload 越界".into());
                    }
                }
            }
        }
        command_offset = command_end;
    }
    Err("Claude Science runtime 不包含 __BUN/__bun 资源".into())
}

fn bun_string<'a>(payload: &'a [u8], offset: u32, length: u32) -> Result<&'a [u8], String> {
    let start = offset as usize;
    let end = start
        .checked_add(length as usize)
        .filter(|end| *end <= payload.len())
        .ok_or("Claude Science Bun 字符串指针越界")?;
    Ok(&payload[start..end])
}

fn science_assets_archive(payload: &[u8]) -> Result<&[u8], String> {
    const OFFSETS_SIZE: usize = 32;
    const MODULE_SIZE: usize = 52;
    if payload.len() < OFFSETS_SIZE + BUN_TRAILER.len() || !payload.ends_with(BUN_TRAILER) {
        return Err("Claude Science Bun payload trailer 无效".into());
    }
    let offsets_start = payload.len() - OFFSETS_SIZE - BUN_TRAILER.len();
    let byte_count = usize::try_from(read_u64_le(payload, offsets_start)?)
        .map_err(|_| "Claude Science Bun payload byte count 过大")?;
    if byte_count > offsets_start {
        return Err("Claude Science Bun payload byte count 越界".into());
    }
    let modules_offset = read_u32_le(payload, offsets_start + 8)? as usize;
    let modules_length = read_u32_le(payload, offsets_start + 12)? as usize;
    if modules_length == 0 || modules_length % MODULE_SIZE != 0 {
        return Err("Claude Science Bun module 表长度无效".into());
    }
    let modules = payload
        .get(modules_offset..modules_offset.saturating_add(modules_length))
        .filter(|_| modules_offset.saturating_add(modules_length) <= byte_count)
        .ok_or("Claude Science Bun module 表越界")?;
    let mut archive = None;
    for module in modules.chunks_exact(MODULE_SIZE) {
        let name = bun_string(payload, read_u32_le(module, 0)?, read_u32_le(module, 4)?)?;
        if name.starts_with(b"/$bunfs/root/assets.tar-") && name.ends_with(b".gz") {
            if archive.is_some() {
                return Err("Claude Science runtime 包含多个 assets archive".into());
            }
            let contents = bun_string(payload, read_u32_le(module, 8)?, read_u32_le(module, 12)?)?;
            if !contents.starts_with(&[0x1f, 0x8b, 0x08]) {
                return Err("Claude Science assets archive 不是 gzip".into());
            }
            archive = Some(contents);
        }
    }
    archive.ok_or_else(|| "Claude Science runtime 不包含 assets.tar-*.gz".into())
}

fn safe_archive_path(path: &Path) -> Result<PathBuf, String> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => relative.push(value),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("拒绝解包不安全路径：{}", path.display()));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err("拒绝解包空路径".into());
    }
    Ok(relative)
}

fn validate_archive_symlink_target(link_path: &Path, target: &Path) -> Result<(), String> {
    let mut resolved = link_path
        .parent()
        .map(|path| {
            path.components()
                .filter_map(|component| match component {
                    Component::Normal(value) => Some(value.to_os_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => resolved.push(value.to_os_string()),
            Component::ParentDir => {
                if resolved.pop().is_none() {
                    return Err(format!(
                        "拒绝解包逃逸资源根的符号链接：{} -> {}",
                        link_path.display(),
                        target.display()
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "拒绝解包绝对符号链接：{} -> {}",
                    link_path.display(),
                    target.display()
                ));
            }
        }
    }
    Ok(())
}

fn unpack_science_assets(archive: &[u8], destination: &Path) -> Result<(), String> {
    let decoder = GzDecoder::new(Cursor::new(archive));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|e| format!("读取 Claude Science assets archive 失败：{e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("读取 Claude Science asset 失败：{e}"))?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .map_err(|e| format!("读取 Claude Science asset 路径失败：{e}"))?;
        if entry_type.is_dir()
            && entry_path
                .components()
                .all(|item| item == Component::CurDir)
        {
            continue;
        }
        let relative = safe_archive_path(&entry_path)?;
        let target = destination.join(&relative);
        if entry_type.is_dir() {
            ensure_private_dir(&target)?;
            continue;
        }
        if entry_type.is_symlink() {
            let link_name = entry
                .link_name()
                .map_err(|e| format!("读取 Science asset 符号链接失败：{e}"))?
                .ok_or("Science asset 符号链接缺少目标")?;
            validate_archive_symlink_target(&relative, &link_name)?;
            let parent = target.parent().ok_or("Science asset 符号链接缺少父目录")?;
            ensure_private_dir(parent)?;
            if target.exists() || std::fs::symlink_metadata(&target).is_ok() {
                return Err(format!("Science asset 路径重复：{}", target.display()));
            }
            std::os::unix::fs::symlink(&link_name, &target)
                .map_err(|e| format!("创建 Science asset 符号链接失败：{e}"))?;
            continue;
        }
        if !entry_type.is_file() {
            return Err(format!(
                "拒绝解包非普通 Science asset：{}",
                target.display()
            ));
        }
        let parent = target.parent().ok_or("Science asset 缺少父目录")?;
        ensure_private_dir(parent)?;
        if target.exists() {
            return Err(format!("Science asset 路径重复：{}", target.display()));
        }
        let executable = entry.header().mode().unwrap_or(0) & 0o111 != 0;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if executable { 0o700 } else { 0o600 })
            .open(&target)
            .map_err(|e| format!("创建 Science asset 失败：{e}"))?;
        std::io::copy(&mut entry, &mut output)
            .map_err(|e| format!("写入 Science asset 失败：{e}"))?;
        output
            .sync_all()
            .map_err(|e| format!("持久化 Science asset 失败：{e}"))?;
    }
    Ok(())
}

fn inject_science_zh_patch(html: &str) -> Result<String, String> {
    if html.contains(SCIENCE_ZH_PATCH_SENTINEL) {
        return Ok(html.to_string());
    }
    let head = html
        .rfind("</head>")
        .ok_or("Claude Science Web UI 缺少 </head>")?;
    if !html.contains("</body>") {
        return Err("Claude Science Web UI 缺少 </body>".into());
    }
    let mut output = String::with_capacity(html.len() + SCIENCE_ZH_PATCH_TAG.len() + 1);
    output.push_str(&html[..head]);
    output.push_str(SCIENCE_ZH_PATCH_TAG);
    output.push('\n');
    output.push_str(&html[head..]);
    Ok(output)
}

fn science_zh_catalog() -> Result<BTreeMap<String, String>, String> {
    serde_json::from_str(SCIENCE_ZH_CATALOG)
        .map_err(|e| format!("解析 Claude Science 中文翻译目录失败：{e}"))
}

fn science_zh_patch_script() -> Result<String, String> {
    let catalog = science_zh_catalog()?;
    let catalog = serde_json::to_string(&catalog)
        .map_err(|e| format!("编码 Claude Science 中文翻译目录失败：{e}"))?;
    Ok(SCIENCE_ZH_PATCH_SCRIPT.replace("__417SWITCH_ZH_CATALOG__", &catalog))
}

fn patch_science_javascript_literals(root: &Path) -> Result<usize, String> {
    let catalog = science_zh_catalog()?;
    let encoded = catalog
        .iter()
        .map(|(english, chinese)| {
            Ok((
                serde_json::to_string(english)
                    .map_err(|e| format!("编码 Claude Science 英文文案失败：{e}"))?,
                serde_json::to_string(chinese)
                    .map_err(|e| format!("编码 Claude Science 中文文案失败：{e}"))?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let matcher = AhoCorasick::new(encoded.iter().map(|(source, _)| source))
        .map_err(|e| format!("构建 Claude Science 翻译匹配器失败：{e}"))?;
    let assets_dir = root.join("web-dist/assets");
    let entries = std::fs::read_dir(&assets_dir)
        .map_err(|e| format!("读取 Claude Science assets 目录失败：{e}"))?;
    let mut replacements = 0usize;

    for entry in entries {
        let entry = entry.map_err(|e| format!("读取 Claude Science asset 条目失败：{e}"))?;
        let path = entry.path();
        if entry
            .file_type()
            .map_err(|e| format!("读取 Claude Science asset 类型失败：{e}"))?
            .is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("js")
        {
            let original = std::fs::read_to_string(&path)
                .map_err(|e| format!("读取 Claude Science JavaScript asset 失败：{e}"))?;
            let mut patched = original.clone();
            let mut matched = matcher
                .find_iter(&original)
                .map(|value| value.pattern().as_usize())
                .collect::<Vec<_>>();
            matched.sort_unstable();
            matched.dedup();
            for index in matched {
                let (source, target) = &encoded[index];
                if patched.contains(source) {
                    let count = patched.matches(source.as_str()).count();
                    patched = patched.replace(source, target);
                    replacements += count;
                }
            }
            if patched != original {
                safe_write(&path, patched.as_bytes(), 0o600)?;
            }
        }
    }
    Ok(replacements)
}

fn patched_assets_marker(runtime: &RuntimeRecord) -> String {
    format!(
        "patch={SCIENCE_ZH_PATCH_VERSION}\nruntime_sha256={}\nruntime_version={}\n",
        runtime.sha256, runtime.version
    )
}

fn validate_patched_assets(path: &Path, marker: &str) -> bool {
    if path_contains_symlink(path) {
        return false;
    }
    std::fs::read_to_string(path.join(".417switch-patch")).is_ok_and(|value| value == marker)
        && std::fs::read_to_string(path.join("web-dist/index.html"))
            .is_ok_and(|value| value.contains(SCIENCE_ZH_PATCH_SENTINEL))
        && std::fs::read_to_string(path.join(SCIENCE_ZH_PATCH_ASSET))
            .is_ok_and(|value| value.contains(SCIENCE_ZH_PATCH_SENTINEL))
}

fn prepare_patched_science_assets(
    runtime: &RuntimeRecord,
    cache_root: &Path,
) -> Result<PathBuf, String> {
    if !runtime_is_current(runtime) {
        return Err("Science runtime 在提取中文资源前发生变化".into());
    }
    ensure_private_dir(cache_root)?;
    let destination = cache_root.join(format!("{}-{SCIENCE_ZH_PATCH_VERSION}", runtime.sha256));
    let marker = patched_assets_marker(runtime);
    if validate_patched_assets(&destination, &marker) {
        return Ok(destination);
    }
    if destination.exists() {
        return Err("Claude Science 中文资源缓存已存在但校验失败；请删除后重试".into());
    }

    let runtime_bytes = validate_executable(
        &runtime.path,
        !matches!(runtime.source, RuntimeSource::InstalledApp),
    )?;
    if sha256(&runtime_bytes) != runtime.sha256 {
        return Err("Science runtime 在读取中文资源时发生变化".into());
    }
    let payload = bun_payload_from_macho(&runtime_bytes)?;
    let archive = science_assets_archive(payload)?;
    let temp = tempfile::Builder::new()
        .prefix(".science-assets-")
        .tempdir_in(&cache_root)
        .map_err(|e| format!("创建 Science assets 临时目录失败：{e}"))?;
    unpack_science_assets(archive, temp.path())?;
    let static_replacements = patch_science_javascript_literals(temp.path())?;
    if static_replacements == 0 {
        return Err("Claude Science 中文资源未命中任何静态文案，拒绝提交空补丁".into());
    }
    let index_path = temp.path().join("web-dist/index.html");
    let index = std::fs::read_to_string(&index_path)
        .map_err(|e| format!("读取 Claude Science Web UI 失败：{e}"))?;
    let patched = inject_science_zh_patch(&index)?;
    safe_write(&index_path, patched.as_bytes(), 0o600)?;
    let patch_script = science_zh_patch_script()?;
    safe_write(
        &temp.path().join(SCIENCE_ZH_PATCH_ASSET),
        patch_script.as_bytes(),
        0o600,
    )?;
    safe_write(
        &temp.path().join(".417switch-patch"),
        marker.as_bytes(),
        0o600,
    )?;
    let temp_path = temp.keep();
    std::fs::rename(&temp_path, &destination)
        .map_err(|e| format!("提交 Claude Science 中文资源失败：{e}"))?;
    if !validate_patched_assets(&destination, &marker) {
        return Err("Claude Science 中文资源提交后校验失败".into());
    }
    Ok(destination)
}

fn patched_science_assets_root(runtime: &RuntimeRecord) -> Result<PathBuf, String> {
    prepare_patched_science_assets(runtime, &science_root().join("runtime-assets"))
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

fn validate_science_browser_url(url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|e| format!("Science 登录地址无效：{e}"))?;
    let allowed_host = matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    );
    if !allowed_host || parsed.port_or_known_default() != Some(SCIENCE_PORT) {
        return Err("Science 登录地址不是 417Switch 隔离 loopback 端口".into());
    }
    Ok(parsed)
}

fn open_science_surface(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
    let parsed = validate_science_browser_url(url)?;
    app.opener()
        .open_url(parsed.as_str(), None::<String>)
        .map_err(|e| format!("使用系统浏览器打开 Claude Science 失败：{e}"))
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

fn apply_science_serve_args(command: &mut Command, assets_root: Option<&Path>) {
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
        .arg(SCIENCE_PREVIEW_PORT.to_string());
    if let Some(assets_root) = assets_root {
        command.arg("--assets-root").arg(assets_root);
    }
    command.arg("--no-browser").arg("--detached");
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
    let chinese_patch = chinese_patch_enabled();
    let assets_root = if chinese_patch {
        Some(patched_science_assets_root(&runtime)?)
    } else {
        None
    };
    let host_home = real_home_dir()?;
    ensure_virtual_login()?;
    ensure_private_dir(&sandbox_data_dir())?;
    remove_temporary_host_browse_grants()?;

    let mut command = Command::new(&runtime.path);
    apply_science_serve_args(&mut command, assets_root.as_deref());
    command
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
    save_launch_mode(chinese_patch)?;
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

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn test_assets_archive() -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut archive = tar::Builder::new(encoder);
        let html =
            b"<!doctype html><html><head></head><body><button>Settings</button></body></html>";
        let mut header = tar::Header::new_gnu();
        header.set_size(html.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "web-dist/index.html", &html[..])
            .unwrap();
        let javascript = br#"const labels=["Settings","Add specialist","Browse Connectors Directory","No skills yet","Compute providers","Allowed domains","No credentials configured.","Data location","Clear all memories?","Your usage limits","Default model"];"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(javascript.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                "web-dist/assets/index-test.js",
                &javascript[..],
            )
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn test_bun_payload(assets: &[u8]) -> Vec<u8> {
        let name = b"/$bunfs/root/assets.tar-test.gz";
        let mut payload = Vec::new();
        let name_offset = payload.len() as u32;
        payload.extend_from_slice(name);
        let contents_offset = payload.len() as u32;
        payload.extend_from_slice(assets);
        let modules_offset = payload.len() as u32;
        let mut module = [0u8; 52];
        put_u32(&mut module, 0, name_offset);
        put_u32(&mut module, 4, name.len() as u32);
        put_u32(&mut module, 8, contents_offset);
        put_u32(&mut module, 12, assets.len() as u32);
        payload.extend_from_slice(&module);
        let byte_count = payload.len() as u64;
        let mut offsets = [0u8; 32];
        put_u64(&mut offsets, 0, byte_count);
        put_u32(&mut offsets, 8, modules_offset);
        put_u32(&mut offsets, 12, module.len() as u32);
        payload.extend_from_slice(&offsets);
        payload.extend_from_slice(BUN_TRAILER);
        payload
    }

    fn test_macho(payload: &[u8]) -> Vec<u8> {
        let section_offset = 32 + 72 + 80;
        let section_size = 8 + payload.len();
        let mut bytes = vec![0u8; section_offset + section_size];
        put_u32(&mut bytes, 0, 0xfeed_facf);
        put_u32(&mut bytes, 16, 1);
        put_u32(&mut bytes, 20, 152);
        put_u32(&mut bytes, 32, 0x19);
        put_u32(&mut bytes, 36, 152);
        bytes[40..45].copy_from_slice(b"__BUN");
        put_u32(&mut bytes, 96, 1);
        bytes[104..109].copy_from_slice(b"__bun");
        bytes[120..125].copy_from_slice(b"__BUN");
        put_u64(&mut bytes, 144, section_size as u64);
        put_u32(&mut bytes, 152, section_offset as u32);
        put_u64(&mut bytes, section_offset, payload.len() as u64);
        bytes[section_offset + 8..].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn extracts_first_http_url() {
        assert_eq!(
            first_http_url("note\nopen https://127.0.0.1:15890/path next"),
            Some("https://127.0.0.1:15890/path".into())
        );
    }

    #[test]
    fn extracts_assets_archive_from_bun_macho_section() {
        let assets = test_assets_archive();
        let macho = test_macho(&test_bun_payload(&assets));
        let payload = bun_payload_from_macho(&macho).unwrap();
        assert_eq!(science_assets_archive(payload).unwrap(), assets);
    }

    #[test]
    fn rejects_corrupt_bun_payload() {
        let mut payload = test_bun_payload(&[0x1f, 0x8b, 0x08, 0]);
        payload.pop();
        assert!(science_assets_archive(&payload).is_err());
        assert!(bun_payload_from_macho(b"not a macho").is_err());
    }

    #[test]
    fn rejects_archive_path_traversal() {
        for path in ["../escape", "/absolute", "folder/../../escape"] {
            assert!(safe_archive_path(Path::new(path)).is_err(), "{path}");
        }
        assert_eq!(
            safe_archive_path(Path::new("./web-dist/index.html")).unwrap(),
            PathBuf::from("web-dist/index.html")
        );
        assert!(validate_archive_symlink_target(
            Path::new("agents/operon/.claude/skills/example"),
            Path::new("../../../../skills/example")
        )
        .is_ok());
        assert!(validate_archive_symlink_target(
            Path::new("agents/link"),
            Path::new("../../outside")
        )
        .is_err());
        assert!(
            validate_archive_symlink_target(Path::new("agents/link"), Path::new("/tmp/out"))
                .is_err()
        );
    }

    #[test]
    fn chinese_html_patch_is_idempotent_and_requires_complete_document() {
        let html = "<html><head></head><body>Settings</body></html>";
        let once = inject_science_zh_patch(html).unwrap();
        let twice = inject_science_zh_patch(&once).unwrap();
        assert_eq!(once, twice);
        assert_eq!(once.matches(SCIENCE_ZH_PATCH_SENTINEL).count(), 1);
        assert!(once.find(SCIENCE_ZH_PATCH_SENTINEL).unwrap() < once.find("</head>").unwrap());
        assert!(inject_science_zh_patch("<html><body></body></html>").is_err());
        assert!(inject_science_zh_patch("<html><head></head></html>").is_err());
        assert!(SCIENCE_ZH_PATCH_SCRIPT.contains("Directory connectors unavailable"));
        assert!(SCIENCE_ZH_PATCH_SCRIPT.contains("Applied as your default for new sessions."));
        assert!(SCIENCE_ZH_PATCH_SCRIPT.contains("Automatic updates are off"));
        let generated = science_zh_patch_script().unwrap();
        assert!(!generated.contains("__417SWITCH_ZH_CATALOG__"));
        assert!(generated.contains("No credentials configured."));
        assert!(generated.contains("尚未配置凭据。"));
    }

    #[test]
    fn science_chinese_catalog_covers_every_settings_page_and_nested_flow() {
        let catalog = science_zh_catalog().unwrap();
        for key in [
            // Capabilities pages and nested editors.
            "Add specialist",
            "Browse Connectors Directory",
            "No skills yet",
            "Compute providers",
            "Allowed domains",
            "No credentials configured.",
            "Data location",
            "Clear all memories?",
            // Workspace pages and their detail views.
            "Revoke this license acknowledgment?",
            "Delete cloud credential?",
            "Your usage limits",
            "Default model",
            "Package mirror",
            // Common nested dialogs.
            "Discard unsaved details?",
            "Remove model endpoint",
            "Enable Modal compute?",
        ] {
            assert!(
                catalog.contains_key(key),
                "missing Science translation: {key}"
            );
        }
        assert!(catalog.len() >= 650);
    }

    #[test]
    fn patched_assets_cache_hits_and_runtime_hash_changes_rebuild() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let runtime_path = temp.path().join("claude-science");
        let assets = test_assets_archive();
        let first_bytes = test_macho(&test_bun_payload(&assets));
        std::fs::write(&runtime_path, &first_bytes).unwrap();
        std::fs::set_permissions(&runtime_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut runtime = RuntimeRecord {
            path: runtime_path.clone(),
            source: RuntimeSource::Explicit,
            version: "test".into(),
            sha256: sha256(&first_bytes),
        };
        let cache = temp.path().join("cache");
        let first = prepare_patched_science_assets(&runtime, &cache).unwrap();
        let second = prepare_patched_science_assets(&runtime, &cache).unwrap();
        assert_eq!(first, second);
        assert!(std::fs::read_to_string(first.join("web-dist/index.html"))
            .unwrap()
            .contains(SCIENCE_ZH_PATCH_SENTINEL));
        assert!(std::fs::read_to_string(first.join(SCIENCE_ZH_PATCH_ASSET))
            .unwrap()
            .contains(SCIENCE_ZH_PATCH_SENTINEL));
        let javascript =
            std::fs::read_to_string(first.join("web-dist/assets/index-test.js")).unwrap();
        for (english, chinese) in [
            ("Settings", "设置"),
            ("Add specialist", "添加专家助手"),
            ("Browse Connectors Directory", "浏览连接器目录"),
            ("No skills yet", "还没有技能"),
            ("Compute providers", "计算服务商"),
            ("Allowed domains", "允许的域名"),
            ("No credentials configured.", "尚未配置凭据。"),
            ("Data location", "数据位置"),
            ("Clear all memories?", "清除全部记忆？"),
            ("Your usage limits", "你的用量限制"),
            ("Default model", "默认模型"),
        ] {
            assert!(
                javascript.contains(chinese),
                "missing replacement for {english}"
            );
            assert!(
                !javascript.contains(&serde_json::to_string(english).unwrap()),
                "English literal survived: {english}"
            );
        }

        let mut second_assets = test_assets_archive();
        second_assets.push(0);
        let second_bytes = test_macho(&test_bun_payload(&second_assets));
        std::fs::write(&runtime_path, &second_bytes).unwrap();
        runtime.sha256 = sha256(&second_bytes);
        let rebuilt = prepare_patched_science_assets(&runtime, &cache).unwrap();
        assert_ne!(first, rebuilt);
    }

    #[test]
    fn science_serve_command_uses_patched_assets_root_and_allows_auto_updates() {
        let assets = Path::new("/tmp/417switch-science-assets-test");
        let mut command = Command::new("claude-science");
        apply_science_serve_args(&mut command, Some(assets));
        let args = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let position = args
            .iter()
            .position(|value| value == "--assets-root")
            .unwrap();
        assert_eq!(args.get(position + 1).map(String::as_str), assets.to_str());
        assert!(!args.iter().any(|value| value == "--no-auto-update"));
    }

    #[test]
    fn science_serve_command_can_use_original_embedded_assets() {
        let mut command = Command::new("claude-science");
        apply_science_serve_args(&mut command, None);
        let args = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!args.iter().any(|value| value == "--assets-root"));
        assert!(!args.iter().any(|value| value == "--no-auto-update"));
    }

    #[test]
    fn science_launch_mode_tracks_chinese_patch_setting() {
        assert_ne!(expected_launch_mode(true), expected_launch_mode(false));
        assert!(expected_launch_mode(true).contains("zh-cn"));
        assert!(expected_launch_mode(false).contains("original"));
    }

    #[test]
    #[ignore = "requires locally installed Claude Science"]
    fn extracts_and_patches_installed_science_assets() {
        let path = PathBuf::from(OFFICIAL_APP_BIN);
        let bytes = validate_executable(&path, false).unwrap();
        let runtime = RuntimeRecord {
            path,
            source: RuntimeSource::InstalledApp,
            version: "local-integration-test".into(),
            sha256: sha256(&bytes),
        };
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let patched = prepare_patched_science_assets(&runtime, temp.path()).unwrap();
        let html = std::fs::read_to_string(patched.join("web-dist/index.html")).unwrap();
        assert!(html.contains(SCIENCE_ZH_PATCH_SENTINEL));
        assert!(patched.join(SCIENCE_ZH_PATCH_ASSET).is_file());
        assert!(patched.join("drizzle/sqlite/meta/_journal.json").is_file());
        assert!(patched
            .join("agents/operon/.claude/skills/customize")
            .is_symlink());
        let mut application_javascript = String::new();
        for entry in std::fs::read_dir(patched.join("web-dist/assets")).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("js")
                && path.file_name().and_then(|value| value.to_str())
                    != Some(
                        Path::new(SCIENCE_ZH_PATCH_ASSET)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap(),
                    )
            {
                application_javascript.push_str(&std::fs::read_to_string(path).unwrap());
            }
        }
        let catalog = science_zh_catalog().unwrap();
        for english in [
            "Add specialist",
            "Browse Connectors Directory",
            "No skills yet",
            "Compute providers",
            "Allowed domains",
            "No credentials configured.",
            "Data location",
            "Clear all memories?",
            "Your usage limits",
            "Default model",
        ] {
            let chinese = catalog.get(english).unwrap();
            assert!(
                application_javascript.contains(chinese),
                "real Science assets missed: {english}"
            );
            assert!(
                !application_javascript.contains(&serde_json::to_string(english).unwrap()),
                "real Science English literal survived: {english}"
            );
        }
        if std::env::var_os("CC_SWITCH_KEEP_SCIENCE_TEST_ASSETS").is_some() {
            eprintln!("SCIENCE_TEST_ASSETS={}", patched.display());
            let _ = temp.keep();
        }
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
    fn science_browser_url_accepts_only_the_managed_loopback_port() {
        for url in [
            "http://localhost:15890/?nonce=test",
            "http://127.0.0.1:15890/?nonce=test",
            "http://[::1]:15890/?nonce=test",
        ] {
            assert!(validate_science_browser_url(url).is_ok(), "{url}");
        }

        for url in [
            "https://claude.ai/",
            "http://127.0.0.1:8765/?nonce=test",
            "http://127.0.0.1:15891/?nonce=test",
        ] {
            assert!(validate_science_browser_url(url).is_err(), "{url}");
        }
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
