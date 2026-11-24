# LocalTunnel
Rust 内网穿透软件

技术设计与开发路线  ·  2026-11-24  ·  草案 V1.0

### 01 / 产品定位

面向个人开发者及团队的自托管内网穿透平台，参考花生壳的使用方式。公网服务器仅承载入口、转发和管理；网站、API、数据库保留在本地。Windows 客户端主动建立出站隧道，无需家庭公网 IP 或路由器端口映射。不是递归 DNS 服务器，也不是通用上网代理。

### 首版使用场景

| 外网域名（示例） | 本地服务 | 访问方式 |
| --- | --- | --- |
| web.example.com | 127.0.0.1:5173 | HTTPS / Vue |
| api.example.com | 127.0.0.1:8080 | HTTPS / Go API |
| admin.example.com | 127.0.0.1:8000 | HTTPS / Laravel |

### 范围与约束

首版：Windows 10/11 x64 客户端 + Linux x64 服务端，支持 HTTP、HTTPS、WebSocket、TCP、设备授权、基本日志。后续增加 Linux/macOS/ARM 客户端、UDP、多节点和 QUIC；移动端后台限制独立评估。

用户需拥有可达的公网 Linux 主机和自己控制的域名；本地电脑保持开机、联网。默认只允许映射本机回环地址，局域网目标须显式授权。不默认开放数据库、远程桌面及开发调试接口。

### 关键决策

统一 Rust 核心，前端 Vue 3；先复用 Rathole，不预先重写隧道协议。先跑通公网闭环，再建设 GUI 和商业化平台。所有体积、吞吐、并发数字均为待验证验收目标。

## 02 / 技术架构与模块

| 层级 | 选型与职责 |
| --- | --- |
| 公网入口 | Nginx：80/443、TLS 终止、Host 路由及 WebSocket；ACME 自动签发 |
| 控制平面 | Axum + SQLx/SQLite：账号、设备、映射、权限、状态、审计 |
| 数据平面 | Rathole + Tokio：TCP 隧道；TLS 经兼容性验证后固定配置 |
| 本地后台 | Rust agent：配置同步、运行监督、心跳、日志、Windows Service |
| 桌面界面 | Tauri 2 + Vue 3 + TypeScript：操作本地 agent，不直接持有隧道 |
| 后台界面 | Vue 3 + Ant Design Vue：用户、设备、域名、节点、流量 |
| 可观测性 | tracing 结构化日志、指标、健康检查；后期 Prometheus |
| 构建与扩展 | Cargo workspace；GitHub Actions；后续评估 Quinn、PostgreSQL |

### 数据路径

浏览器 → DNS A/AAAA（公网 IP）→ Nginx :443 → 127.0.0.1:内部映射端口 → Rathole 服务端 → 加密隧道 → Rathole 客户端 → 本地 127.0.0.1:8080。响应沿原连接返回。公网 TLS 在 Nginx 终止；中转与 agent 之间另行加密。

### 控制路径与失败处理

客户端通过 HTTPS API 注册设备并获得短期凭据；服务端保存映射期望状态，生成隧道和网关配置。agent 拉取带版本的配置并返回应用结果。配置通过校验、原子替换、受控重载与探活后才标记在线；失败回滚至上一有效版本。

Rathole 先采用独立进程封装，固定上游提交、验证 TLS、配置更新及连接影响。若重载会中断其他映射，V0.1 接受维护窗口，V0.2 前解决隔离/平滑更新；必要时 fork 或更换数据平面。保留 Apache 2.0 许可与归属声明。

## 03 / 工程结构与接口

### 仓库：trade3403/localtunnel

| 目录 | 职责 |
| --- | --- |
| crates/core/ | 共享类型、错误、配置、重试与限流 |
| crates/agent/ | 本地后台、设备凭据、进程监督、IPC |
| crates/server/ | Axum API、鉴权、域名与映射状态 |
| crates/tunnel/ | Rathole 适配、配置生成、运行状态 |
| crates/gateway/ | Nginx 配置生成、验证、ACME 协调 |
| apps/desktop/ | Tauri + Vue，系统托盘、映射管理 |
| apps/admin/ | Web 管理后台 |
| deploy/ · tests/ · docs/ | 安装脚本、集成/E2E、设计与运维说明 |

### 管理 API（拟定，统一 /api/v1 前缀）

| 接口 | 说明 |
| --- | --- |
| POST /auth/login | 用户登录；管理员角色单独授权 |
| POST /devices/enroll | 一次性配对码绑定设备 |
| GET /devices/{id}/config | 授权设备获取期望配置及 revision |
| POST /devices/{id}/status | 心跳、配置版本、连接状态、流量 |
| GET/POST /mappings | 列表及创建映射；按所属用户隔离 |
| PATCH/DELETE /mappings/{id} | 更新、暂停、删除；校验所有权 |
| POST /domains/verify | 域名控制权验证（DNS TXT） |

### 数据模型

users、devices、domains、mappings、nodes、usage_daily、audit_logs。映射包含 id、owner_id、device_id、protocol、domain、local_host、local_port、bind_port、enabled、revision、status；域名全局唯一，节点内部端口唯一。状态：待验证、待配置、连接中、在线、离线、错误、停用。秘密字段不回传 UI。

## 04 / 版本路线与交付门槛

| 版本 | 范围 / 必须通过的验收 |
| --- | --- |
| V0.1 | 核心闭环：锁定 Rathole、TLS、TCP、手动配置；真实公网访问本地 HTTP 服务，校验响应内容。 |
| V0.2 | 域名、HTTPS、多映射、WebSocket；域名冲突拒绝，证书验证通过，映射互不干扰。 |
| V0.3 | Windows GUI、托盘、后台服务与安装包；关闭窗口后访问仍可用，重启自动恢复。 |
| V0.4 | 管理后台、用户/设备/域名/映射/日志；API 操作实际生效，状态可追踪。 |
| V0.5 | 限流、设备吊销、访问控制、故障恢复、负载测试；公网发布前完成安全门槛。 |
| V0.6 | Linux/macOS/ARM64 agent；各目标原生构建并通过同一公网 E2E。 |
| V0.7 | UDP、QUIC 可行性实验、连接效率；仅在基准显示收益时引入。 |
| V0.8 | 套餐、配额、带宽及租户隔离；配额和权限测试通过。 |
| V0.9 | 多节点、调度、监控告警、故障切换；演练节点下线及恢复。 |
| V1.0 | 正式安装包、签名、自动更新、回滚、备份恢复、安全审计与长稳测试。 |

### 首个里程碑执行顺序

1. 建立 Cargo workspace、固定 Rust stable toolchain、Cargo.lock 与第三方许可清单。
2. 在 Linux 公网主机部署测试 relay；Windows agent 接入 TLS。
3. 启动返回固定标识的本地测试 HTTP 服务，配置 Nginx 路由和真实域名。
4. 从独立公网机器发起访问，校验 HTTP 状态、正文、日志，并验证未授权连接拒绝。
5. 保存 CI 证据和部署说明，才允许进入 V0.2。

V0.1 是受控测试，不开放匿名注册或任意 TCP 公网端口；所有公开映射均需授权。未通过测试的功能不得标记为已完成。

## 05 / 安全、部署与运维

### 安全要求（从 V0.1 开始实施）

设备采用一次性配对码、独立凭据、可撤销与轮换机制；TLS 校验服务端身份，禁止关闭证书校验。控制 API 强制鉴权与对象归属检查；管理界面不向公网匿名开放。域名经 DNS TXT 验证后方可绑定，防止 Host 抢占。

限制客户端目标为已授权地址；服务端映射端口仅监听回环，公共 TCP 映射另行明确授权。限制连接数、请求体、超时、带宽及并发；使用有界缓冲和背压。可信代理重写转发头，防止伪造。日志脱敏，不记录令牌、密码及请求正文。

凭据存入系统受保护存储或权限受限文件；本地 IPC 使用 ACL 限制访问。更新包验证签名，依赖运行 cargo audit，检查许可证；备份配置与数据库并定期演练恢复。

### 公网服务器端口（建议）

| 端口 | 用途 / 约束 |
| --- | --- |
| 80 / 443 TCP | Nginx 公网入口，复用现有宝塔站点 |
| 2333 TCP | Rathole 隧道入口，TLS 和认证；端口可调整 |
| 127.0.0.1:9000 | Axum API，网关代理访问 |
| 127.0.0.1:20000–29999 | 内部映射池，不直接开放公网 |

### 部署流程

Linux：准备 DNS 和防火墙 → 安装独立 systemd 服务或 Docker → 生成初始管理员和设备配对码 → 配置 Nginx 与 ACME → 探活。若已有宝塔/Nginx，新增独立站点配置，先 nginx -t 后重载，不覆盖既有站点。

Windows：安装签名客户端 → 验证 WebView2 → 配对 → 新建映射 → 验证域名和本地端口 → 启动 → 外网测试。后台服务与 UI 分离，卸载清理服务但允许用户保留配置。公网断网或本机休眠时标记离线。

## 06 / 测试、性能与参考资料

### 自动化验收矩阵

| 测试 | 验收内容 |
| --- | --- |
| 单元 / 静态检查 | cargo fmt、clippy、test、audit；前端 lint、构建、类型检查 |
| 集成 / 公网 E2E | Linux relay + Windows agent；真实域名、TLS、正文、WebSocket、断线重连；测试日志及报告留档 |
| 安全回归 | 未授权设备、过期凭据、域名冲突、跨租户访问、错误证书、超限、删除映射后不可访问 |
| 发布构建 | Windows MSVC / Linux GNU 原生 runner；后续 macOS、ARM64；保存 SHA-256、版本及安装包 |

### 性能目标（非实测，先固定测试环境）

| 指标 | 目标及口径 |
| --- | --- |
| 核心 / 安装包 | agent ≤5 MB；Windows 安装包 ≤15 MB（不含 WebView2 离线运行库） |
| 后台资源 | 空闲 agent RSS ≤20 MB；CPU ≤1%，采样 10 分钟，不含 UI |
| 吞吐 / 并发 | 目标 1 Gbps、10,000 并发；独立千兆以上网络，记录 CPU、RSS、p95 与错误率，非最低配置保证 |
| 恢复 / 长稳 | 网络恢复后 p95 重连 ≤5 秒；168 小时初验，V1.0 争取 30 天长稳 |

### 参考资料与待确认事项

Rathole：https://github.com/rathole-org/rathole

Tauri 安装：https://v2.tauri.app/distribute/windows-installer/

Axum：https://docs.rs/axum/latest/axum/

Tokio：https://tokio.rs/　Rustls：https://github.com/rustls/rustls

待确认：实际域名、公网主机系统及带宽、是否已有宝塔、Rathole 固定版本与安全审计、是否采用商业授权模式。本文仅为设计与验收基线，仓库已创建，尚未部署或实测。
