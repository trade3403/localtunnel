# LocalTunnel

基于 Rust 的自托管内网穿透软件，参考花生壳的使用方式。通过公网中转服务器，将本地 Windows 电脑上的网站和 API 映射到自有域名，无需本地公网 IP。

## 开发文档

- [技术设计与开发路线 V1.0](docs/architecture-and-roadmap.md)
- [GitHub Actions 免费云端 Runner 部署测试规范](docs/github-actions-ci-cd.md)
- [Runner 环境测试工作流](https://github.com/trade3403/localtunnel/actions/workflows/runner-smoke.yml)

- [V0.1 候选版运行和测试说明](docs/v0.1.md)
- [V0.2 域名网关候选版](docs/v0.2.md)
- [V0.3 Windows 客户端开发预览](docs/v0.3.md)
- [V0.4 管理服务开发预览](docs/v0.4.md)

## 技术栈

Rust · Tokio · Rathole · Axum · Rustls · Tauri 2 · Vue 3 · SQLite · Nginx

## 开发进度

V0.1 免费 Linux/Windows Runner 同机加密隧道测试已通过。V0.2 静态域名网关已通过 Linux/Windows CI #17；动态 HTTP/HTTPS 路由及证书轮换已通过 CI #44。V0.3 Windows 客户端阶段 CI #98/#99 已通过，V0.4 管理 API 首个增量待验收。公网部署和真实域名绑定暂缓。

| 版本 | 目标 | 状态 |
|---|---|---|
| V0.1 | Rust 配置工具、加密隧道、同机 E2E；公网验收延后 | 同机 CI 通过，公网待验收 |
| V0.2 | 域名映射、HTTPS、WebSocket | 静态及动态网关 CI 通过；ACME、动态隧道待开发 |
| V0.3 | Windows 客户端及安装包 | 桌面、托盘、Windows Service、安装卸载与真实回环转发 CI 通过；未签名，实机和公网待验收 |
| V0.4 | Web 管理后台 | Axum/SQLite 骨架开发中，待 CI |
| V0.5 | 安全、稳定性与负载测试 | 待开发 |
| V0.6–V1.0 | 跨平台、扩展、商业化、多节点及发行 | 待开发 |

首个里程碑：Windows agent + Linux relay + 自定义域名，真实公网端到端访问本地 HTTP 服务。验收标准见开发文档。

不要提交真实设备密钥、密码、服务器凭据或生产配置。
