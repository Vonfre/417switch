# 417Switch 独立项目

此目录保存 417Switch 的完整可维护源码和已构建的 macOS 应用，与原始
`cc-switch`、`CSSwitch` 仓库分开。

## 目录结构

- `source/`：417Switch 源码、前端资源、Rust/Tauri 后端和依赖锁文件。
- `artifacts/macos/417Switch.app`：当前验证可用的 macOS 应用。
- `scripts/build_macos.sh`：从 `source/` 重新构建并更新 macOS 成品。

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

