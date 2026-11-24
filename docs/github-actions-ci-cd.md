# GitHub Actions 云端部署测试规范

## 决策
全部 CI 默认采用 GitHub 官方标准 GitHub-hosted runners，不使用 self-hosted，不要求用户电脑或已有自托管 Runner 在线。当前仓库为 public，标准 runner 计算时间免费，仍遵守 GitHub 使用限制、存储及保留政策；不使用付费 larger runners。若仓库转私有须重新评估免费额度。参考 https://docs.github.com/en/actions/concepts/billing-and-usage 。

## Runner 矩阵
- ubuntu-latest：Rust server/agent 编译、clippy、单元测试、Linux 临时部署、集成测试。
- windows-latest：Rust MSVC agent、Windows Service 测试、Tauri EXE/MSI 构建、安装/卸载和可行的自动化 UI 测试。
- macos-latest：V0.6 起构建、原生测试及 DMG；签名/公证须另行配置。
- Android：后续在标准 Ubuntu runner 安装 SDK/NDK；模拟器能力按实际环境验证。
- 初期 Linux/Windows 为必过项；macOS/ARM64 等仅在对应版本纳入。锁定 toolchain 与 Cargo.lock。

## 工作流规划
| 文件 | 触发 | 职责 |
| --- | --- | --- |
| .github/workflows/runner-smoke.yml | push、PR、手动 | 官方云端 Linux/Windows 环境验证 |
| .github/workflows/ci.yml | push、PR | fmt、clippy、test、audit、前端 lint/typecheck |
| .github/workflows/e2e.yml | push、PR、手动 | 同一 runner 临时启动 server、agent、测试 HTTP fixture，验证真实 TCP/TLS/HTTP 数据路径，测试结束清理 |
| .github/workflows/public-e2e.yml | 受信 main 手动或受保护环境 | 通过已授权可达的公网测试 relay，Windows agent 与独立探测端验证真实域名/TLS/响应正文、拒绝未授权、重连 |
| .github/workflows/release.yml | 版本 tag | 全量测试通过后构建并发布二进制/安装包、SHA-256、版本记录 |
| .github/workflows/deploy.yml | 受保护环境、手动批准 | 可选部署至用户授权的正式 Linux 主机；健康检查、失败回滚 |

## E2E 分级和验收
1. 单机集成：在每个 Linux/Windows runner 独立启动临时 relay、agent 和 fixture，检查实际穿透响应、随机 nonce、并行映射、重连与权限拒绝。运行完成后停止进程、删除临时凭据。
2. 跨机器/公网 E2E：不同 job 的 runner 网络不保证互通，也不能假定存在可入站公网地址。需要独立的、授权的可达测试 relay 或适合 CI 的临时测试网络接入；真实域名、TLS、独立探测器及请求证据齐全才算公网 E2E 通过。入口未提供时明确 BLOCKED，不以 localhost 结果替代，不伪造绿灯。
3. 长稳测试：单 job 有时限，不使用连续重启 runner 规避时限；30 天常驻验证须另行使用获授权的持久环境。GitHub Runner 不是正式生产主机。
4. 测试失败时保存脱敏日志、JUnit/JSON 测试报告、必要截图、二进制大小及 SHA-256。报告必须对应 commit SHA、runner OS、工具链版本。只有实际通过的版本才标记完成。
5. CI 自动触发；修复由开发者或获授权的开发代理依据真实日志提交并触发新运行，不能假设 Actions 会自行修复源码。

## 安全与成本
公开 PR 仅执行不含秘密的测试；不使用 pull_request_target 执行不可信源码。默认 GITHUB_TOKEN contents: read，发布单独授予 contents: write。生产部署仅允许受信分支/tag，使用受保护 Environment、最小权限凭据、显式批准。Secrets 不写入仓库及日志；第三方 Actions 发布前固定可信提交 SHA。控制并发、超时、缓存和 artifact 保留期，避免额外存储费用。不修改现有生产 Nginx，未授权不部署。

## 当前状态
Rust 源码尚未实现。第一步仅建立 runner-smoke 工作流；环境测试通过不代表产品功能通过。后续随 V0.1 源码实现 ci/e2e 工作流。正式公网入口、部署凭据和真实域名尚未提供。
