#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="$project_dir/source"
built_app="$source_dir/src-tauri/target/release/bundle/macos/417Switch.app"
saved_app="$project_dir/artifacts/macos/417Switch.app"

cd "$source_dir"
pnpm install --frozen-lockfile
pnpm tauri build --bundles app
codesign --force --deep --sign - "$built_app"
codesign --verify --deep --strict "$built_app"
mkdir -p "$project_dir/artifacts/macos"
ditto "$built_app" "$saved_app"

echo "417Switch 已构建并保存到：$saved_app"
