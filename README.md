# LocalTunnel

基于 Rust 的自托管内网穿透软件，参考花生壳的使用方式。通过公网中转服务器，将本地 Windows 电脑上的网站和 API 映射到自有域名，无需本地公网 IP。

## 开发文档

- [技术设计与开发路线 V1.0](docs/architecture-and-roadmap.md)
- [GitHub Actions 免费云端 Runner 部署测试规范](docs/github-actions-ci-cd.md)
- [Runner 环境测试工作流](https://github.com/trade3403/localtunnel/actions/workflows/runner-smoke.yml)

- [V0.1 候选版运行和测试说明](docs/v0.1.md)
- [V0.2 域名网关候选版](docs/v0.2.md)
- [V0.3 Windows 客户端开发预览](docs/v0.3.md)
- [V0.4 管理服务开发预览与历史](docs/v0.4.md)
- [V0.4 最终验收记录、运行入口及未完成边界](docs/v0.4-acceptance.md)
- [V0.5 安全与稳定性开发记录](docs/v0.5.md)
- [V0.5 最终验收、实测数据与未完成边界](docs/v0.5-acceptance.md)
- [V0.6 跨平台客户端开发记录](docs/v0.6.md)
- [V0.6 开发预览验收与实际安装包](docs/v0.6-acceptance.md)
- [V0.7 UDP / QUIC 开发记录](docs/v0.7.md)
- [V0.7 QUIC 技术选型及真实测试证据](docs/v0.7-quic-decision.md)
- [自主开发与 CI 记录](docs/autonomous-development.md)

## 技术栈

Rust · Tokio · Rathole · Axum · Rustls · Tauri 2 · Vue 3 · SQLite · Nginx

## 开发进度

V0.1–V0.4 已通过免费 GitHub Hosted Runner 的同机开发预览回归。V0.4 实测基线为 `d21c0443aeae221172eb5a1e6eb5ef5dcd1050ab`（Management #57/#58、Windows #128、Gateway #122、Runner #253/#254 全绿）；最终证据门禁提交 `d6440ab87c7f9b782ef32a3689d32719935124d0`（Management #59/#60、Windows #129、Gateway #123、Runner #255/#256）也已全绿。包括 Axum/SQLite、中文 Web 后台、Windows 管理配对/原生心跳、HTTP/HTTPS 真实加密隧道启停、常驻故障恢复、流量观测和审计。不是生产版或公网验收；当前管理入口仅回环，不能自动把远程 Windows 设备配置应用至真实公网中转。

| 版本 | 目标 | 状态 |
|---|---|---|
| V0.1 | Rust 配置工具、加密隧道、同机 E2E；公网验收延后 | 同机 CI 通过，公网待验收 |
| V0.2 | 域名映射、HTTPS、WebSocket | 静态及动态网关 CI 通过；ACME、动态隧道待开发 |
| V0.3 | Windows 客户端及安装包 | 桌面、托盘、Windows Service、安装卸载与真实回环转发 CI 通过；未签名，实机和公网待验收 |
| V0.4 | Web 管理后台、管理设备、受控预览运行 | 同机功能及最终证据门禁验收通过；生产边界未完成 |
| V0.5 | 安全、稳定性与负载测试 | 同机开发预览功能基线 CI 全绿（90项管理+88项桌面）；生产门禁未完成 |
| V0.6 | Linux/macOS/ARM64 agent | 开发预览及收尾 CI 全部通过 |
| V0.7 | UDP / QUIC 协议扩展 | Windows UDP 桌面运行、独立 QUIC 反向流实验已通过；完整依赖锁已通过；Noise/TCP 与 QUIC 配对实验已通过；隔离网络损伤实验已通过；应用资源上限及断流恢复已通过；QUIC 暂缓正式集成，保留 Noise/TCP，Windows SCM UDP/混合后台运行已通过；可复用 UDP 计量核心已通过；Windows 混合计量与历史已通过；可配置 UDP 字节限速待 CI |
| V0.8–V1.0 | 商业化、多节点及发行 | 待开发 |

首个里程碑：Windows agent + Linux relay + 自定义域名，真实公网端到端访问本地 HTTP 服务。验收标准见开发文档。

不要提交真实设备密钥、密码、服务器凭据或生产配置。
