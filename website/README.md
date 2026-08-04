# 417Switch Website

`website/` 是 [vonfre.github.io/417switch](https://vonfre.github.io/417switch/)
的纯静态 GitHub Pages 站点，不依赖 Node.js 构建步骤。

## 本地预览

```bash
python3 -m http.server 4170 --directory website
```

打开 <http://127.0.0.1:4170/>。

## 发布

推送到 `main` 后，`.github/workflows/pages.yml` 会把此目录部署到 GitHub Pages。
仓库设置中的 Pages Source 需要选择 **GitHub Actions**。

网站使用 GitHub 提供的免费 `github.io` 地址，无需购买域名或配置 DNS。
