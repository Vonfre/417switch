# 417Switch 独立项目

此目录保存 417Switch 的完整可维护源码和已构建的 macOS 应用，与原始
`cc-switch`、`CSSwitch` 仓库分开。

## 官方网站

- 网站源码：`website/`
- 官方域名：[417switch.io](https://417switch.io/)
- GitHub Pages：推送到 `main` 后由 `.github/workflows/pages.yml` 自动部署

417Switch 基于 [CC Switch](https://github.com/farion1231/cc-switch) 与
[CSSwitch](https://github.com/SuperJJ007/CSSwitch) 实现：没有 Claude Science
需求时可直接使用 CC Switch；只想使用 Claude Science 时可选择 CSSwitch；
需要两种能力的融合体验时选择 417Switch。

## 目录结构

- `source/`：417Switch 源码、前端资源、Rust/Tauri 后端和依赖锁文件。
- `artifacts/macos/417Switch.app`：当前验证可用的 macOS 应用。
- `scripts/build_macos.sh`：从 `source/` 重新构建并更新 macOS 成品。
- `website/`：417switch.io 的静态网站源码。

源码副本未包含以下可重新生成内容：

- `.git/`
- `node_modules/`
- `src-tauri/target/`
- `dist/`

## 重新构建

确保系统已经安装 Node.js、pnpm 和 Rust，然后执行：

```bash
./scripts/build_macos.sh
```

脚本会安装锁定依赖、构建 release App、执行本机 ad-hoc 签名，并将结果更新到：

```text
artifacts/macos/417Switch.app
```

Claude Science 的登录状态、供应商配置和目录授权不在本项目目录中，仍保存在
`~/.417switch/`，因此重新构建源码不会清空用户数据。

## 发布与自动更新

推送与 `source/package.json`、`source/src-tauri/tauri.conf.json` 版本一致的
`v*` 标签后，GitHub Actions 会自动构建 universal macOS DMG、创建 GitHub
Release，并上传 Tauri updater 所需的签名包和 `latest.json`。

应用从以下地址检查更新：

```text
https://github.com/Vonfre/417switch/releases/latest/download/latest.json
```

首次启用该更新通道的版本需要手动安装 DMG；之后的新版本可在应用内下载、安装
并自动重启。
