# LocalTunnel

基于 Rust 的自托管内网穿透软件，参考花生壳的使用方式。通过公网中转服务器，将本地 Windows 电脑上的网站和 API 映射到自有域名，无需本地公网 IP。

## 开发文档

- [技术设计与开发路线 V1.0](docs/architecture-and-roadmap.md)
- [GitHub Actions 免费云端 Runner 部署测试规范](docs/github-actions-ci-cd.md)
- [Runner 环境测试工作流](https://github.com/trade3403/localtunnel/actions/workflows/runner-smoke.yml)

## 技术栈

Rust · Tokio · Rathole · Axum · Rustls · Tauri 2 · Vue 3 · SQLite · Nginx

## 开发进度

当前处于规划阶段，尚未实现或测试核心功能。

| 版本 | 目标 | 状态 |
|---|---|---|
| V0.1 | 核心隧道与真实公网访问验证 | 待开发 |
| V0.2 | 域名映射、HTTPS、WebSocket | 待开发 |
| V0.3 | Windows 客户端及安装包 | 待开发 |
| V0.4 | Web 管理后台 | 待开发 |
| V0.5 | 安全、稳定性与负载测试 | 待开发 |
| V0.6–V1.0 | 跨平台、扩展、商业化、多节点及发行 | 待开发 |

首个里程碑：Windows agent + Linux relay + 自定义域名，真实公网端到端访问本地 HTTP 服务。验收标准见开发文档。

不要提交真实设备密钥、密码、服务器凭据或生产配置。
