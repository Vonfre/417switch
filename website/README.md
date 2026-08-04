# 417Switch Website

`website/` 是 [417switch.io](https://417switch.io/) 的纯静态 GitHub Pages 站点，
不依赖 Node.js 构建步骤。

## 本地预览

```bash
python3 -m http.server 4170 --directory website
```

打开 <http://127.0.0.1:4170/>。

## 发布

推送到 `main` 后，`.github/workflows/pages.yml` 会把此目录部署到 GitHub Pages。
仓库设置中的 Pages Source 需要选择 **GitHub Actions**。

## 417switch.io DNS

在域名服务商中配置：

- 根域名 `417switch.io` 添加 GitHub Pages 的四条 `A` 记录：
  `185.199.108.153`、`185.199.109.153`、`185.199.110.153`、`185.199.111.153`
- `www` 添加 `CNAME`，指向 `vonfre.github.io`

DNS 生效后，在仓库 **Settings → Pages** 中确认自定义域名为 `417switch.io`，
并启用 **Enforce HTTPS**。
