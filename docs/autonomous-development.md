# LocalTunnel 自主开发与验收接续记录

## 授权范围与执行规则（2026-11-24）
唯一写入目标：trade3403/localtunnel 当前开发分支 feat/v0.3-client-reliability（PR #5），完成后可从已核验开发 HEAD 创建下一阶段 feat/v0.x-* 分支并记录继承关系。不得修改 main、稳定版本、生产服务器、密钥、真实 DNS 或正式发布，不得强推。仅使用 GitHub 官方标准免费 hosted runner。额外费用、权限、生产变更、真实设备或重大冲突由用户授权。其他项目不受本任务影响。

每轮先核对 PR/head/base、当前文档、最新 commit CI 状态和日志；以实际 head 为准，不覆盖并发修改。优先修复失败 CI，真实日志定位、保持全部回归门禁、新增针对性测试，核验结果及 artifacts。运行中/排队中不重复触发、不提交无关改动以免取消 CI。尽可能一次提交一组改动；提交前重新核对 HEAD，优先 CAS 非强制更新或基于当前 blob SHA 更新；检测冲突立即停止本轮。每次只推进一个有界增量。相同根因最多连续三次有证据修复，之后记录阻塞并通知一次，等待新证据或人工处理，不无限重跑。无实质变化不通知，不为状态轮询提交文件。阶段满足门禁即继续下阶段，无需用户重复“下一步”。

## 当前真实证据
- V0.1 #13: https://github.com/trade3403/localtunnel/actions/runs/45403587846 ，Windows/Linux 6/6 单测及 7/7 同机 E2E。
- V0.2 #44: https://github.com/trade3403/localtunnel/actions/runs/45408193697 ，两平台 9/9 单测、Linux 14/14 E2E、Windows 7/7 E2E；HTTPS 动态证书/域名更新通过。ACME、动态隧道及公网仍未完成。
- V0.3 #20: https://github.com/trade3403/localtunnel/actions/runs/45421385073 ，head 9c7a231dda23ad336d368ccb0a9d1618c4e3eb01，8/8 单测（含 DPAPI）、1/1 真实 TCP lifecycle、NSIS 打包通过。未签名预览安装包 https://github.com/trade3403/localtunnel/actions/runs/45421385073/artifacts/14935671400 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45421385073/artifacts/14935896187 ，七天保留。
- V0.3 #23: https://github.com/trade3403/localtunnel/actions/runs/45422191299 ，head 2604d07d58681b1cfb2650fa7a5c22a3b14edcdf，9/9 单测（含真实 Job Object 终止子进程）、1/1 lifecycle、NSIS 1.99 MiB 构建通过，实际静默安装、原生窗口启动成功；卸载返回后程序文件仍存在，CI 失败且安装包未上传。证据 https://github.com/trade3403/localtunnel/actions/runs/45422191299/artifacts/14934247674 。
- 修复 462322fa907546298dc34e0280fda9e395c8a14e：NSIS 可能在 TEMP 子进程继续卸载；新增最多 60 秒实际文件消失检测与时间记录，禁止测试脚本代替卸载删除文件。根因假设尚须新 CI 验证，未声称修复通过。

## 自动化协作
现有 GitHub push/pull_request 自动触发官方 runner，CI 按依赖顺序执行功能测试、安装门禁、证据归档。ChatGPT 单一 hourly 任务读取真实结果、修复及开发，保持 main 不动。GitHub workflow_run completed 监听器要求工作流存在默认分支；官方 Codex Action CI 修复方案需授权 API key。当前不引入付费 API，不写 main，不伪造事件回调；事件源查询不可用，暂以平台最高频率每小时检查补足。参考 https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows 和 https://developers.openai.com/cookbook/examples/codex/autofix-github-actions 。未来在明确授权后才接入可验证的事件入口。

## 下一任务与阶段验收门禁
1. V0.3 最新卸载修复 CI；如失败读完整日志/证据，针对根因修复。必须核验安装、窗口启动、真实卸载、引擎生命周期、DPAPI、Job Object、既有回归、预览包 SHA。补齐依赖锁、可信引擎验证及安装集成、GUI/托盘真实操作、异常终止临时文件清理、Windows Service/自启动（显式 opt-in，CI 隔离测试）、真实服务端认证/映射状态与流量计量。不得以 TCP 可达或进程运行冒充认证在线，不得把单机同机 E2E 当公网。
2. V0.4 管理后台：按 architecture-and-roadmap.md 实现 Rust Axum API、用户/设备/映射授权、SQLite 数据库、Vue 管理界面、真实 CRUD/隔离/认证回归，审查动态配置发布和失败回滚。记录未完的 V0.2 ACME、DNS 控制权验证和动态隧道管理，作为依赖补齐。 
3. V0.5 安全、性能和稳定性：真实量测并记录环境、数据与原始证据，不把目标写成实测；V0.6 跨平台，V0.7 UDP/QUIC，V0.8 商业化管理，V0.9 多节点，V1.0 签名、升级、正式发行前验收，依架构路线逐阶段推进。签名、公开正式发行、真实设备/域名/生产部署需用户授权；不阻塞其他可独立开发任务。
4. 只在有实质变化时更新本记录及相关版本文档；每次报告包含阶段、功能、head SHA、真实 CI 链接/结果、数据、产物、未完与下一项。完成所有授权范围目标后，若剩余仅人工门禁，报告并暂停开发任务；不得自行发布。

下一次执行从 PR #5 当前 HEAD 开始，不固定旧 SHA。此文档是接续入口，实际 CI 与分支最新状态优先。

## 2026-11-25：安装门禁通过，下一增量
- PR #5 head 7dc9358a28e8ecd1186c72bf1b830993bfbd8c83，Windows CI #27 https://github.com/trade3403/localtunnel/actions/runs/45424105874 全部通过；9/9 单测、1/1 真实 TCP 生命周期（0.58 秒为测试耗时，不是网络性能）。实际下载证据 ZIP 核验 installer-smoke.json：installed/window_started/uninstalled 均 true，卸载启动器 exit 0，文件消失等待 258 ms。build.txt 实际测试 merge SHA 4d350107da1dad59d22aa73685b42d01598fd990，EXE SHA256 540410316edd4f18711ecda842cdbb7bcbe462ed5c571b251069f33746483d7。安装包 1.99 MiB，未签名预览：https://github.com/trade3403/localtunnel/actions/runs/45424105874/artifacts/14936666766 ，证据：https://github.com/trade3403/localtunnel/actions/runs/45424105874/artifacts/14936093271 。V0.2 #57 与 Runner #122 均通过。
- 下一安全增量：正常停止后显式删除临时明文配置，失败时报告而不是静默成功；真实生命周期测试增加配置文件和目录不存在的断言。新提交待 CI。强杀桌面后的孤立配置清理仍未实现；后续继续可信引擎、依赖锁、独立服务及自启等门禁。


## 2026-11-25：正常停止清理验收、引擎完整性增量
- PR #5 head 3e9b39b80f5447a51d333b3cfa13b14d03c18c12：Windows CI #29 https://github.com/trade3403/localtunnel/actions/runs/45426246888 全部通过，9/9 Rust 单测、1/1 真实 TCP 生命周期（0.78 秒为测试耗时），正常停止后临时明文配置及目录不存在断言通过。EXE 2.00 MiB；安装、启动、卸载门禁通过。未签名预览包 https://github.com/trade3403/localtunnel/actions/runs/45426246888/artifacts/14938545505 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45426246888/artifacts/14936868707 。预览包 ZIP 的 SHA256 0364a5a7727bee672845e5a4ef8f59b12dbb1bb6cf9ee21dfa8c6526509674a9（不是 EXE 的 SHA）。V0.2 #58、Runner #124 通过。
- 新增 engine_integrity.rs，Windows CI 在编译前从现有固定 SHA256 的 Rathole v0.5.0 Windows x64 官方归档提取引擎，通过 Get-FileHash 得到二进制 SHA256，并以构建时 LOCALTUNNEL_ENGINE_SHA256 嵌入客户端。运行时不信任环境变量或用户自报哈希；未配置构建指纹、非法指纹、超限或文件摘要不匹配均拒绝启动。最多读取 64 MiB，将通过校验的确切字节写入独立临时目录，执行该副本而非原始路径；此机制不抵御已控制同一用户账户或临时目录的攻击者。引擎与临时配置随正常停止清理，强杀后孤立目录清理仍待实现。
- 新增两项校验单测，真实生命周期测试先篡改真实官方 EXE 的一个字节并验证拒绝启动，然后使用正确引擎走真实 TCP 转发及清理门禁。提交 d91fada3598b11038621d5ef21cd047c33e59199、0714625ab45eb7651cc1cc4a7293d29819894558、0570ea8ddaaa9fefb4ddc6a4a8074c50c74c905a、6350f5c2cc97776a0d51e9f4858b9773dfa66ed8、d91c4adc00904db4f1cecddd6004216f5a5841ea。新 CI 待核验。
- 下一步：先验收此次增量；之后审查并锁定 Cargo.lock 与 package-lock.json、改用 locked/npm ci，并考虑将已验证的引擎纳入安装包（许可声明、完整性复核）；目前仍需要用户提供对应官方 EXE 路径。Windows Service、自启、认证状态、流量计量、真实 GUI/托盘及异常退出专项仍未完成。只在安全开发分支工作，不发布 main。

## 2026-11-25：可信引擎验收与依赖锁接续
- HEAD 7052e693769aed4af57b89f689c0a2455f695d22，Windows CI #41 https://github.com/trade3403/localtunnel/actions/runs/45428041713 ，11/11 单测及 1/1 真实 TCP 生命周期通过（含真实篡改拒绝、停止清理）；官方归档提取的引擎 SHA256 a91717eb37b3dc25c9d2391aca6a1b1f8edde9a3de626264718811ff8113e55b。原始报告已解压核验：安装、原生窗口、卸载均 true，卸载等待 257 ms，EXE SHA256 719C0B2F149DE0372987FFF74A027BAEB5E2402CDA92F838326637CCFE48A59E。预览包 https://github.com/trade3403/localtunnel/actions/runs/45428041713/artifacts/14937931826 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45428041713/artifacts/14938136827 。核心 #64、Runner #136 状态 success。
- 依赖锁 ZIP 已实际获取，Cargo.lock 114832 字节、package-lock.json 52974 字节。当前文件下载与 Git 写入工具之间缺少直接字节传递接口；新增临时 CI 步骤，仅输出两个非秘密依赖锁的 Base64 分块、长度和 SHA256，供下一轮在同一 GitHub 工具调用内重组并提交。保留全部现有门禁，不赋予 CI 写权限。下一轮从最新成功 job 日志解析 LOCK-BEGIN/CHUNK/END，检查连续偏移、长度及 SHA256（或 Git blob 校验），审查依赖来源；以 base64 创建两个 blob，原子提交锁文件及 npm ci/cargo --locked 门禁，并移除临时导出步骤。不得将本轮视为依赖锁定完成。若导出无法取得，记录限制并推进独立功能，不重复无效下载。


## 2026-11-25：依赖锁定增量
- CI #43 https://github.com/trade3403/localtunnel/actions/runs/45495224323 三个工作流通过；桌面 11/11 单测、真实隧道及安装门禁通过。产物：https://github.com/trade3403/localtunnel/actions/runs/45495224323/artifacts/14969265290 。
- 重组真实日志 110 个 Base64 分块，逐块核验偏移、文件字节数和 SHA256，Cargo.lock 114832 字节 bf267572bd5eb29f4cdc6c150a60a6072e4ccd6df8dae60c2a6876d12386f339；package-lock.json 52974 字节 26116400ee3aedc2f0e2e60605a58fb09fe6abba4d520abddb1b4b4e299b1e7a。检查 Cargo registry 仅 crates.io，npm resolved 仅 npm 官方 registry 且有 integrity。提交原始字节；启用 npm ci、cargo test --locked、Tauri cargo build --locked 和构建后锁文件不变门禁，删除临时日志导出。锁定构建仍待新 CI 验收；下一项为可信引擎安装包集成、许可证及真实安装验证。未修改 main、未发布。


## 2026-11-25：依赖锁验收、内置引擎增量
- HEAD 00f644d2dcefb6e1067236f98f666964bb18f844 的 CI #45 https://github.com/trade3403/localtunnel/actions/runs/45512870320 全部步骤通过，锁定 npm/Cargo 构建及锁文件未变检查通过，真实隧道、安装启动卸载通过；预览包 https://github.com/trade3403/localtunnel/actions/runs/45512870320/artifacts/14976902272 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45512870320/artifacts/14976178448 。核心 #66、Runner #140 通过。
- 新增 Tauri bundle.resources：将固定 SHA256 的 v0.5.0 官方 Windows x64 EXE 与上游 Apache-2.0 LICENSE（原始 blob d9a10c0d8e868ebf8da0b3dc95bb0be634c34bfe）和来源说明打包到 engine/。CI 先验证原始 archive，再校验二进制固定 SHA256，再复制至资源目录；未提交 EXE 源文件。默认空引擎路径由 Rust 解析安装资源，保留原有外部绝对路径及相同运行时校验；普通/DPAPI 配置支持保存空路径。新增资源定位测试、默认配置测试；安装验收新增实际安装引擎 SHA、--version 运行、许可证存在、卸载后资源移除门禁。仍须新 CI 验收；未完成所有依赖的许可证/安全审计，不声称正式发布。
- 本地构建须先执行 tests/e2e.py 的 engine 下载函数，将校验后的 EXE 复制至 apps/desktop/src-tauri/resources/engine/rathole.exe 并设置 LOCALTUNNEL_ENGINE_SHA256；参考 Windows CI。下一阶段：Windows Service/显式自启、真实状态与流量、异常清理及 GUI/托盘操作验收。main 未修改，仍使用免费 runner。


## 2026-11-25：内置引擎验收、Windows SCM 服务入口
- HEAD 3009ea807fbd2a354364c4f1835224552686ec17，CI #47 https://github.com/trade3403/localtunnel/actions/runs/45514680220 全通过；12/12 Rust 单测及 1/1 真隧道测试（1.00s 测试耗时，不是吞吐性能），内置引擎摘要/实际执行、锁定构建、安装启动卸载门禁通过；EXE 3.14 MiB。产物 https://github.com/trade3403/localtunnel/actions/runs/45514680220/artifacts/14975789769 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45514680220/artifacts/14975774682 。核心 #67、Runner #142 通过。
- 本增量以现有 windows-sys 0.59 增加 Services feature，不增加新 crate；实现明确 --service-host LocalTunnelPreview-<32hex> SCM 入口，实际 RegisterServiceCtrlHandlerExW/SetServiceStatus/StartServiceCtrlDispatcherW、STOP/SHUTDOWN、无 GUI 运行。新增名称及控制单测、隔离免费 Windows Runner 以 LocalService/Manual 注册、启动、查询 PID、停止、删除及证据门禁。正常桌面/安装程序不注册服务，不设自启，不接触生产。
- 本次只实现 SCM 生命周期，不提供服务模式穿透、不跨账户解密桌面用户 DPAPI、不把 SCM Running 当隧道在线。后续必须实现服务身份独立安全凭据配置、最小权限/ACL、受控 IPC、防止桌面与服务同时争用映射、真实服务隧道回归、显式安装和卸载、自启及恢复；先验证本次新 CI。当前所有服务新功能均待验收，仍未正式发布。


## 2026-11-25：SCM 生命周期通过，真实服务隧道增量
- HEAD 8550b392514ce30aa8ef5b76e1459a0f430e320d，CI #49 https://github.com/trade3403/localtunnel/actions/runs/45519226087 全通过；14/14 Rust 单测、1/1 真 TCP 生命周期（1.15s 测试耗时）、SCM LocalService 注册/启动/PID/停止/删除、锁定构建、NSIS 安装/卸载通过。EXE 3.14 MiB。预览包 https://github.com/trade3403/localtunnel/actions/runs/45519226087/artifacts/14979463637 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45519226087/artifacts/14979812026 。核心 #68、Runner #144 通过。
- 新增明确 --service-tunnel 模式，复用 Supervisor、固定内置引擎 SHA256、Job Object、核心 Noise 配置；独立 service-profile.bin，DPAPI LocalMachine 封装由 CI 管理员提供，服务读取解密并验证映射，禁止外部引擎路径；临时明文配置位于部署目录 runtime/。隔离部署只支持 ProgramData/LocalTunnelPreview-<32hex>，SCM LocalService + 每服务 SID，管理员/系统完全控制、服务读执行、仅 runtime 子目录可写，需管理员先建立 ACL。机器级 DPAPI 本身不提供账户隔离，不能脱离 ACL；当前生产部署 ACL 自检、正式凭据配置工具、GUI 服务控制和防冲突仍未完成，不得用于真实生产。
- 新增真实 SCM HTTP 加密转发测试：随机本地 fixture、独立 relay、临时 token、密封配置、每服务 SID、启动后真实业务响应、停止后无转发、临时目录清理及 SCM 删除，仍保留此前全部回归。新代码待 CI，不把运行状态当作认证在线；不涉及真实公网或生产服务。下一步验收，补齐安全 provisioning/自启/恢复与真实状态流量。


## 2026-11-25：真实服务隧道验收、Rust 凭据配置入口
- HEAD ac9cb8dd6f7041d716a61183f22167d094402552，CI #51 https://github.com/trade3403/localtunnel/actions/runs/45525710159 三个工作流通过；14/14 单测、1/1 桌面真实生命周期（0.89s 测试耗时）、独立 SCM LocalService Noise HTTP 隧道/停止后断开/运行时清理/删除、锁定构建及安装卸载通过，EXE 3.15 MiB。预览包 https://github.com/trade3403/localtunnel/actions/runs/45525710159/artifacts/14982322952 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45525710159/artifacts/14983360432 。
- 新增 Rust --service-seal-profile <preview-name> 入口，仅在约定 ProgramData 部署目录从 stdin 读取有界 JSON，复用核心验证、禁止外部引擎、DPAPI LocalMachine、原子无覆盖写入 service-profile.bin；桌面 DPAPI 仍为 CurrentUser。部署根目录拒绝重解析点；仍依赖管理员预先配置严格 ACL，不是完整 ACL 自检或生产安装工具。无明文文件/命令行 token，不自动注册服务，不启用自启。配置轮换需后续单独实现。
- CI 改用实际 Rust 配置入口代替 Python 测试专用 DPAPI 加密；加入错误配置拒绝、已存在密文不覆盖、实际服务解密转发门禁，新增 Rust 单测；全部待新 CI 验收。下一步完成安全部署 ACL 验证、显式服务管理、自启、异常恢复及状态/流量；未修改 main，未涉及生产或付费 runner。


## 2026-11-25：Rust 凭据配置验收、服务 ACL 自检
- HEAD 6a652f4ce0cfc1080c21f832afbc0599ff11b71c，CI #53 https://github.com/trade3403/localtunnel/actions/runs/45528325145 全部通过，15/15 单测及 1/1 真实桌面隧道（0.87s 测试耗时）、Rust 服务密封配置、错误引擎拒绝、无覆盖及 SCM 真 HTTP 隧道、锁定构建、安装卸载通过。EXE 3.15 MiB；预览包 https://github.com/trade3403/localtunnel/actions/runs/45528325145/artifacts/14982944647 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45528325145/artifacts/14983623040 。核心 #70、Runner #148 通过。
- 新增 Windows native service_acl.rs，以 GetNamedSecurityInfoW/GetAce/LookupAccountNameW 校验部署根目录、宿主 EXE、engine 目录/EXE、runtime 目录及启动时密文配置。仅允许管理员/SYSTEM 持有所有者和完全权限、对应服务 SID 仅 RX（runtime 允许 Modify），拒绝未知 ACE、额外身份、过度授权、缺失 ACL、重解析点；密封前及实际启动前均自检。CI 设置所有者为 Administrators，注入 Everyone RX，验证密封拒绝以及不安全密文文件导致启动失败，恢复严格 ACL 后验证真实转发。新代码待 CI。此检查是严格预览目录门禁，尚非完整 Windows 安全审计；不覆盖父目录/管理员篡改、并发 ACL 变更或所有异常残留路径。未自动注册/自启任何用户设备。下一步验收、正式显式服务部署管理及开机自启、恢复与状态流量。


## 2026-11-25：服务 ACL 验收、显式 SCM 控制及自启配置
- HEAD 4df1a40aaf3409b28e9367df513771ec3e21194f，Windows CI #55 https://github.com/trade3403/localtunnel/actions/runs/45532163893 全部通过；15/15 单测、1/1 桌面真实生命周期、非法 Everyone ACL 拒绝、服务真实 HTTP 转发及清理、安装卸载通过，EXE 3.15 MiB。预览包 https://github.com/trade3403/localtunnel/actions/runs/45532163893/artifacts/14984394326 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45532163893/artifacts/14984124944 。核心 #71、Runner #150 通过。
- 新增 service_control.rs 和显式 --service-control <preview-name> check|start|stop|autostart-on|autostart-off；原生 SCM 访问权限最小化、校验已部署服务的完整 ImagePath、LocalService 身份及 own-process 类型，开始/启用前复核 ACL、密封配置和引擎指纹，停止/关闭自启保留故障恢复路径；有界等待启动停止，修改自启后读回验证。默认手动，不创建服务、不自动提权、不修改用户计算机。新增真实 SCM 测试：不安全自启拒绝、手动默认、自启开启与关闭的 SCM 实际配置、通过产品 Rust 控制入口启动停止并验证真实隧道。仅配置级自启测试，不是重启后启动验收。全部新代码待 CI。后续完成显式安装删除工具、异常恢复/孤立配置清理、GUI 控制及真实状态计量。仍仅安全预览分支，未修改 main。


## 2026-11-25：CI #57 停止服务失败修复
- HEAD 05aee7228dbfad1f570bf87989a1a622d89fd770，Windows CI #57 https://github.com/trade3403/localtunnel/actions/runs/45534403274 失败：16/16 Rust 单测及桌面真实 TCP、3.15 MiB NSIS 构建、SCM 生命周期通过；service_tunnel_e2e.py 第179行 control("stop") 返回1，前序自启配置、启动及真实 HTTP 转发已执行成功；锁文件门禁、最终安装卸载及预览包上传跳过。核心 #72 和 Runner #152 成功。失败证据 https://github.com/trade3403/localtunnel/actions/runs/45534403274/artifacts/14986751483 。原控制命令吞掉错误文本，根因未直接证实。
- 代码审查发现高概率竞态：控制处理函数只设置 STOP flag，服务循环100ms后才发布 STOP_PENDING，旧 wait 遇 RUNNING 立即返回失败。本轮停止等待在25s上限内接受 RUNNING 和 STOP_PENDING，仅真实 STOPPED 返回成功；启动等待仍严格拒绝 STOPPED。补充状态转换单测、真实 SCM 停止幂等回归及命令 stderr 脱敏诊断，不降低真实停止/断开/临时目录清理门禁。新 CI 尚待核验，不宣称修复成功。保留所有旧测试，不修改 main。若仍失败，读具体错误再修复，同根因最多3次。


## 2026-11-25：停止竞态修复验收、显式服务注册删除
- HEAD 7fdc2b2adf5efaac4130e76be10071b5f3e12efc 的 CI #59 https://github.com/trade3403/localtunnel/actions/runs/45536035040 全部通过，17/17 单测、1/1 真实桌面 TCP（0.93s 测试耗时）、实际 SCM 自启配置、真实转发、停止/重复停止、运行目录清理、锁定构建及安装卸载通过。EXE 3.15 MiB；预览包 https://github.com/trade3403/localtunnel/actions/runs/45536035040/artifacts/14986614328 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45536035040/artifacts/14986409921 。核心 #73、Runner #154 通过。
- 新增显式 --service-control <preview-name> register|unregister，注册前仅 SYSTEM/Administrators 拥有安全部署文件、runtime 为空、无已有凭据、固定引擎校验；原生 CreateServiceW 以 LocalService/Manual/own-process 注册，设独立 SID，失败删除新服务，不覆盖现有服务。管理员仍需显式授权服务 SID 并密封凭据。删除仅针对确认身份且已停止的服务，先禁用自启，再 DeleteService，不删除文件/密文。CI 使用产品实际注册/删除入口取代 sc create/delete 正常路径，新增不安全注册拒绝、重复注册拒绝、运行中删除拒绝、删除保留凭据与 SCM 消失门禁，旧回归不减。新代码待 CI；尚非完整安装器或 GUI，未在真实用户设备注册服务。下一步异常恢复、残留清理及完整安装/卸载管理。未修改 main。自动任务本轮查询为关闭，未重新启用。


## 2026-11-25：服务注册删除验收、引擎异常退出恢复
- HEAD 20a5bf0563d3303aaf947dcde287d99b82d1a29b，CI #61 https://github.com/trade3403/localtunnel/actions/runs/45537179713 全部通过，17/17 单测、1/1 桌面真实 TCP（0.78s 测试耗时）、真实 SCM 注册删除及拒绝非法注册/运行中删除、真实隧道、锁定构建及安装卸载通过。EXE 3.15 MiB；预览包 https://github.com/trade3403/localtunnel/actions/runs/45537179713/artifacts/14986739741 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45537179713/artifacts/14987388757 。核心 #74、Runner #156 通过。
- 服务宿主新增引擎异常退出恢复，单次 SCM 服务生命周期最多3次，1/2/4秒递增间隔，主动停止时取消；重新读取密文凭据和校验 ACL/引擎指纹，旧进程停止且 runtime 为空才继续，失败耗尽后服务停止并报告失败。初次配置不合法仍直接拒绝启动；SCM Running 代表宿主活跃（包括恢复），不等于隧道在线。真实 CI 注入故障：按 SCM PID 精确定位其 runtime 下的 Rathole 子进程，强制结束，验证新子进程 PID、原宿主未变、旧临时目录消失、HTTP 再次真实转发。新增预算单测。全部新代码待 CI，未实现宿主自身异常退出的 SCM recovery policy 或跨宿主残留安全清理；禁止自动递归删除未知数据。未修改 main，不涉及生产设备。下一阶段按实际 CI 验收后继续宿主恢复及残留清理。


## 2026-11-25：引擎恢复验收、宿主崩溃残留清理
- HEAD 411b6e287ec36fc6872168fad5b3f15d2f960239，CI #63 https://github.com/trade3403/localtunnel/actions/runs/45538735734 全部通过，18/18 单测、1/1 桌面真实 TCP（0.93s 测试耗时）、真实 SCM 子进程强制退出后恢复转发/旧 runtime 消失、安装卸载通过。EXE 3.16 MiB；预览包 https://github.com/trade3403/localtunnel/actions/runs/45538735734/artifacts/14988158394 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45538735734/artifacts/14988238217 。核心 #75、Runner #158 通过。
- 新增初次 SCM 启动时专用 runtime 崩溃残留清理：先验证部署 ACL 及密封凭据，仅接受一个 tempfile 生成的 localtunnel-client-<6字母数字> 目录、普通 client.toml/rathole.exe 文件，逐项严格 ACL/所有者/重解析点检查、拒绝未知数据、检测独占读取、先删除旧引擎再配置、非递归删除空目录。仅 runtime 子项允许 LocalService/服务 SID 所有者；部署根/密文/引擎仍必须管理员或 SYSTEM 所有。新增真实 CI 整个 SCM 宿主强制结束、Job Object 子进程退出、未知文件阻止清理、人工移除未知测试文件后显式启动恢复 HTTP。所有新增功能待验收；尚非整个宿主自动重启，需后续 SCM 恢复策略。独占打开与删除间仍有竞态，依赖专用目录 ACL 和 SCM 单宿主约束；不是完整安全擦除，也未覆盖恶意管理员或同 LocalService 身份。未修改 main。


## 2026-11-25：宿主残留清理验收、显式 SCM 崩溃恢复
- HEAD 24ed7d8cd4278190bf33722f3b8232f4c184a588，CI #65 https://github.com/trade3403/localtunnel/actions/runs/45540249685 全部通过；19/19 单测、1/1 真实桌面 TCP（0.73s 测试耗时）、实际宿主强制结束/未知文件保留/手动重启清理后真实 HTTP、安装卸载通过，EXE 3.16 MiB。预览包 https://github.com/trade3403/localtunnel/actions/runs/45540249685/artifacts/14988883924 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45540249685/artifacts/14989625413 。核心 #76、Runner #160 通过。
- 新增显式 --service-control <preview-name> recovery-on|recovery-off，默认不配置恢复；启用前复核既有服务身份、ACL、凭据、引擎指纹。原生 ChangeServiceConfig2W 设置 SCM 崩溃恢复为3/6/12秒重启、末尾 NONE（后续不再重启），86400秒无故障重置计数，非崩溃失败不触发，禁止外部命令/重启电脑，QueryServiceConfig2W 读回核验动作及 flag。关闭恢复不依赖健康凭据；已排队的 SCM 重启可能仍执行，必要时管理员禁用服务。真实 CI 先保留既有手动崩溃清理测试，再主动启用恢复、强制结束唯一测试 SCM 宿主，验证新宿主 PID、旧 runtime 清理、HTTP 实际恢复及耗时；正常停止观察14秒不重启，关闭恢复，删除测试服务。所有新增功能待 CI；非实际重启电脑测试、不修改用户设备、不修改 main。下一步实时状态、流量计量与 GUI 服务管理。 


## 2026-11-25：SCM 恢复验收、桌面 TCP 实时观察
- HEAD 3890f3b7807d633e06f15e331f8a15ae1d5fcafe，CI #67 https://github.com/trade3403/localtunnel/actions/runs/45544426725 全部通过，20/20 单测、1/1 实际桌面 TCP（0.94s 测试耗时）、真实 SCM 宿主自动恢复和正常停止观察、安装卸载通过。EXE 3.16 MiB；预览包 https://github.com/trade3403/localtunnel/actions/runs/45544426725/artifacts/14990902587 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45544426725/artifacts/14991621009 。核心 #77、Runner #162 通过。
- 新增 transport.rs Windows GetExtendedTcpTable OWNER_PID IPv4/IPv6 只读有界快照，按实际引擎 PID、ESTABLISHED、配置 IP/端口筛选；域名仅端口候选且排除本地映射同端口回环，不执行 DNS 或主动探测。IPC transport_status 与既有 1.2s GUI 轮询整合；失败为未知，停机为未启动，无 TCP 为未观察到，明确不能证明 Noise 认证/公网在线。新增真实本地 socket 单测与实际 Rathole TCP 测试断言。仅 GUI 管理的引擎，尚未读服务模式状态，不包含流量计数、每映射认证或公网探测。Windows TCP 表调用在阻塞线程执行，不增加依赖包（windows-sys 增特性）；锁定构建及新测试待 CI。后续继续服务状态、准确应用字节计量及界面，未修改 main。


## 2026-11-25：桌面 TCP 监测验收、SCM 实时只读状态
- HEAD 7422c15662fd3232bf34b9d60fe096773d3a17e2，CI #69 https://github.com/trade3403/localtunnel/actions/runs/45546429554 全部通过，Windows 原生 TCP 表、真实引擎 TCP、SCM 恢复、安装卸载及锁定构建通过；核心 #78、Runner #164 通过。预览包 https://github.com/trade3403/localtunnel/actions/runs/45546429554/artifacts/14992440025 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45546429554/artifacts/14992011167 。
- 新增只读 SCM QueryServiceStatusEx 状态快照（校验预览服务名称、完整固定 ImagePath、LocalService/own-process、QUERY_CONFIG/QUERY_STATUS 最小权限），返回宿主状态、启动模式、有效宿主 PID、退出码；普通安装 EXE 可通过 --service-status <name> JSON 查询，不读密文或更改服务。GUI 增加手动指定服务并1.2秒轮询，停止监测、错误清空、代际检查避免旧查询覆盖新目标。CI 从非部署 EXE 真实读取注册后停止/自启/运行 PID/宿主恢复新 PID/停止/删除后的不可用状态，拒绝不相关服务。新增代码待 CI，不代表认证/公网在线，不含服务引擎 TCP 计数或流量字节统计，权限不足会明确报错；GUI 服务注册/修改仍待开发。未修改 main。下一步准确流量计量与服务管理界面。


## 2026-11-25：SCM 状态验收、桌面实际流量计量
- HEAD ba23fab81e8a09d722050a9611abaf0dd70b1ce7，CI #71 https://github.com/trade3403/localtunnel/actions/runs/45549752861 全部通过，真实 SCM 只读状态/恢复 PID/停止/删除与安装卸载通过；核心 #79、Runner #166 通过。预览包 https://github.com/trade3403/localtunnel/actions/runs/45549752861/artifacts/14992819841 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45549752861/artifacts/14994130021 。
- 新增桌面模式专用 IPv4 loopback 计量转发层，固定每映射目标，临时端口不与目标或中转端口相同；单线程 Tokio runtime、全局128并发上限、3秒本地连接超时、双向流式转发与半关闭、停止时取消所有任务；统计成功写入应用字节（含 HTTP 头，不含加密与 TCP 开销），按实际单调时间差计算速度，界面1.2秒刷新；未测/停止显示空而非虚构0。仅本次桌面会话，停止后不可见，不持久化，不计费；本机其他进程可直接访问回环计量端口，因此非认证流量证明，不能用于安全/结算。SCM 仍直接转发，不受该计量层影响。新增真实32768/65536字节/半关闭/停止单测及实际 Rathole 转发计量断言；使用已有锁定 Tokio 1.54.1，更新根依赖锁定项，全部新代码待 CI；性能及高并发未测。下一步服务计量/管理 UI，未改 main。


## 2026-11-25：桌面流量验收、SCM 实际流量快照
- HEAD 267dab3402dbc5921af242c4dc059a7722bde8c7，CI #73 https://github.com/trade3403/localtunnel/actions/runs/45553836046 全部通过，24/24 单测（包含32768/65536真实字节及半关闭）、1/1 实际桌面 TCP（0.73s 测试耗时）、真实 SCM 和锁定构建/安装卸载通过，EXE 3.26 MiB。核心 #80、Runner #168 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45553836046/artifacts/14995121156 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45553836046/artifacts/14994926553 。
- SCM 复用桌面真实字节计量层，128 并发、固定本地目标；每秒写入引擎临时目录内固定 traffic.json（只有数值、宿主/引擎 PID、采样时间，无凭据/载荷）。SCM 查询验证路径、ACL、单一 runtime、4KiB 上限、宿主 PID 和5秒新鲜度；未知或无权限返回空，不影响隧道。崩溃清理白名单增加 traffic.json，正常停止关闭文件句柄再删除目录。GUI 展示独立服务上传/下载速度和累计字节。CI 真实 HTTP 后验证服务计数、自动宿主恢复后新 PID 的实际计数及停止无流量快照。所有新增待 CI；当前计量为单次引擎会话，非历史累计/计费，普通非管理员若无法访问 ACL 保护目录仍只显示 SCM 状态；不放宽权限。固定文件非原子写入，读取遇半截 JSON 返回空，下次采样恢复；同 LocalService 身份和本地回环访问不构成防篡改计费证明。未修改 main。下一步安全历史累计与 GUI 服务管理。


## 2026-11-25：SCM 流量 CI #75 编译修复
- HEAD 3aaacc5d6722e94a0fd9cea6ffb3652cacdfd194，CI #75 https://github.com/trade3403/localtunnel/actions/runs/45555726060 在 Rust desktop unit tests 编译阶段失败。实际日志 job 139007181452：src/main.rs:207-208 E0308，publish_service_traffic 返回 Result<(), String>，尾表达式 map_err 返回 &str。核心 #81、Runner #170 通过；后续真实服务测试/安装包均未执行，失败证据 https://github.com/trade3403/localtunnel/actions/runs/45555726060/artifacts/14995353279 。
- 本次仅将尾表达式错误转换为 String，保留全部测试、安全校验和计量行为，不跳过验收。重新触发 CI，待真实后台计量通过后再做历史累计。未改 main 分支。


## 2026-11-25：后台流量验收、桌面历史流量持久化
- HEAD 34debd43b55eca358565f3ffd4a74d054cb8bbf0，CI #77 https://github.com/trade3403/localtunnel/actions/runs/45560354544 全部通过；24/24 单测、1/1 实际桌面 TCP（0.93s 测试耗时）、真实 SCM 流量/恢复/停止、锁定构建、安装卸载成功，EXE 3.27 MiB。核心 #82、Runner #172 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45560354544/artifacts/14998141224 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45560354544/artifacts/14998041614 。
- 本轮新增桌面本机用户目录 traffic-history.json 与 OS 排他文件锁，历史存储只含上传/下载数值和保存时间，限制4KiB、拒绝异常路径/损坏数据；基于启动时基线+当前实际会话计数，避免周期保存重复累加。独立线程每5秒检查并原子替换已同步文件，停止时先结束转发再最终保存；失败可显示，启动遇损坏历史不覆盖，其他桌面实例不能并发写同一历史。GUI 分开显示会话实时数据和已保存跨重启累计。新增重开/重复保存/并发锁/损坏保留测试及真实32768/65536字节转发停止保存、重开不重复。使用已验收 CI Rust 1.100 支持的 std File::try_lock；未新增依赖。新代码待 CI，后台服务历史另做，文件为用户本地非计费证据、信任用户目录、断电/强退可能丢失未保存增量及遗留临时文件，尚未测实际断电/性能。未改 main。


## 2026-11-25：桌面历史验收、SCM 历史持久化
- HEAD be0df515b7005b80b257daf008b43418c4d1ba62，CI #79 https://github.com/trade3403/localtunnel/actions/runs/45569925600 全部通过，真实桌面流量与持久化、防重复、排他锁、损坏保护、SCM 回归与安装卸载通过；核心 #83、Runner #174 通过。预览包 https://github.com/trade3403/localtunnel/actions/runs/45569925600/artifacts/15001529468 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45569925600/artifacts/15001828433 。
- SCM 可选历史目录：管理员在专属 ProgramData/LocalTunnelPreview-<32hex>/history 建目录（runtime 的同级，不参与临时清理），拥有者 Administrators/SYSTEM，继承仅 Administrators/SYSTEM Full，给此服务 SID (OI)(CI)M，根目录仍 RX。不自动创建或放宽 ACL；旧部署缺 history 保留会话计量，存在但 ACL/重解析点不安全则拒绝启动/自启。复用桌面5秒持久化、排他锁、原子替换、结束最终保存，宿主与引擎恢复按已持久化基线累加；SCM 状态返回独立历史（停止时也可读），未配置/无权限/无数据返回空。CI 增加真实服务流量历史检查、拒绝 Everyone 授权、强杀宿主前确认检查点、恢复后新增真实计量、停止及注销保留历史。新功能待 CI；异常退出可能丢失未保存增量，记录不是计费凭据；历史目录配置仍需管理员，未做自动升级/GUI 权限提升，不修改 main。


## 2026-11-25：SCM 历史验收、可视化已注册服务管理
- HEAD 1e0e5ed77fdad83a5a3d3bb928cc78981f0c1d6e，CI #81 https://github.com/trade3403/localtunnel/actions/runs/45571661939 全部通过，26/26 单测、1/1 真实桌面 TCP（0.92s 测试耗时）、SCM 真实历史/宿主恢复/停止/注销保留、锁定构建和安装卸载通过，EXE 3.29 MiB。核心 #84、Runner #176 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45571661939/artifacts/15002392263 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45571661939/artifacts/15003027233 。
- 新增 manage_existing 与 manage_service IPC：普通桌面 EXE 使用明确服务名、固定 ProgramData 部署路径，验证 SCM ImagePath/LocalService/own-process，复用现有 ACL、凭据、引擎摘要检查和 SCM 状态机；动作白名单 check/start/stop/autostart-on/off/recovery-on/off，不支持注册、注销、路径输入、任意 shell 或自动提权。IPC 进程内互斥、后台阻塞线程，Vue 操作中锁定目标，结果回读 SCM，错误不伪造成功，故障恢复仅在精确策略匹配时显示启用/关闭。CLI --service-manage 与 IPC 共用函数供真实 SCM E2E；测试从普通构建 EXE 执行安全拒绝、检查、自启、启动、恢复、停止和恢复策略读回，保留原有注册/注销测试。新增功能待 CI；实际图形点击、普通权限拒绝与管理员桌面验收尚未测试，初始部署/凭据配置仍由管理员完成。未修改 main。下一步可视化服务部署/配置及最终 GUI 托盘验收。


## 2026-11-25：已注册服务控制验收、一键服务部署
- HEAD 05e19f1d6800a12663c24584aee9877318698207，CI #83 https://github.com/trade3403/localtunnel/actions/runs/45572613901 全部通过；核心 #85、Runner #178 通过；实际 SCM 管理后端、历史、安装卸载通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45572613901/artifacts/15002757611 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45572613901/artifacts/15003037299 。
- 新增 Windows provision_service 与 --service-provision（stdin JSON，CLI 固定 EXE 同级 engine），显式管理员操作：校验配置、SCM 创建权限、Windows ProgramData known folder、拒绝祖先 reparse；BCrypt 随机生成32hex 名；CreateDirectoryW 带受保护 SDDL 原子创建新根，拒绝复用；复制当前桌面 EXE、校验内置 engine、受保护子目录、原生注册后分配每服务 SID RX/M、DPAPI machine sealed profile、验证权限及配置。默认停止、手动启动，未启用 recovery；不自动提权或覆盖；失败尝试注销本次确知注册，保留目录供检查，未做自动升级/修改/删除。GUI 勾选明确授权后用当前表单创建并监测新服务。CI 增加第二个全新一次性服务，真实注册/启动/HTTP/停止/历史持久化/注销，沿用旧完整测试。使用同一 windows-sys 0.59 已锁定包新增功能标志，无新版本；新代码待 CI。当前预览 EXE 未签名，需信任管理员运行的安装包及本机 ProgramData，不用于不可信二进制或生产部署；GUI 实际点击/普通用户权限与服务配置更新仍待验收。未改 main。


## 2026-11-25：一键部署验收、已注册服务配置更新和注销
- HEAD 3ff22c77b28c137c646122d9cc3e1a65552b5bda，CI #85 https://github.com/trade3403/localtunnel/actions/runs/45574650077 全部通过；26/26 单测、1/1 真实桌面 TCP（0.99s 测试耗时）、实际第二服务一键部署/HTTP/历史/停止、安装卸载成功，EXE 3.31 MiB。核心 #86、Runner #180 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45574650077/artifacts/15005005031 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45574650077/artifacts/15004441952 。
- 新增独立 update_service_profile / unregister_service IPC、--service-update 和 --service-unregister（明确名称重复确认，配置 JSON stdin），统一 GUI mutation mutex；普通动作白名单仍不含注销。仅精确已注册 LocalService/own-process/固定 ProgramData known folder、停止状态的服务可维护。配置预检原有 ACL、密封凭据、引擎摘要、新配置有效性；先禁用启动再替换，候选 machine-DPAPI 加密、sync、ACL、原子 persist、解密回读比较，不读出旧 Token 到 UI；更新后保持禁用，须显式设手动/自动。失败若已禁用不自动恢复；原子替换前失败保留旧文件，替换后回读失败须管理员检查。注销使用原有禁用/停止确认/DeleteService，保留目录和数据，不递归删除。GUI 精确输入服务名确认，表单整套更新和注销注册。CI 扩展真实第二服务：运行时拒绝更新/注销、错误确认/配置拒绝、旧密文保留、合法新本地端口更新后仍禁用、重新手动启动并验证不同 HTTP 响应、历史累计保存、注销保留密文/历史并确认 SCM 删除。尚待 CI；可信管理员之间的外部并发修改不是事务锁，排队恢复可能在重新启用后发生；暂未做在线更新、自动提权、数据擦除、GUI 点击验收。未改 main。


## 2026-11-25：配置修改/注销验收、真实已安装 GUI 验收
- HEAD 65bc238604a6597cb234de1a02b79f1afbf07fd1，CI #87 https://github.com/trade3403/localtunnel/actions/runs/45577365966 全部通过；26/26 单测、1/1 真实桌面 TCP（0.93s 测试耗时）、真实 SCM 更新映射后的不同 HTTP 响应/注销保留历史、安装卸载成功，EXE 3.33 MiB。核心 #87、Runner #182 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45577365966/artifacts/15005755465 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45577365966/artifacts/15005392811 。
- 新增 installed_gui_e2e.mjs，Node 22 原生 WebSocket，无额外依赖；在 NSIS 安装后实际启动安装版 WebView2，独立临时 WebView 数据目录、仅 CI 子进程启用本地调试端口，真实 DOM 控件 input/change/click（不是直接 invoke 或 mock），添加删除映射、端口探测、启动实际 Rathole Noise HTTP、显示实际字节、对验证属于本应用 PID 的 HWND 发送 WM_CLOSE 并检查隐藏及持续真实转发、原生 ShowWindowAsync 恢复、停止后真实转发断开、历史显示。保留原安装/原生窗口/卸载门禁，新增 JSON 证据，临时随机 token/密钥不打印。此门禁尚未运行；CDP 依赖 Windows hosted runner WebView2 调试可用性。没有物理鼠标点击或托盘菜单点击验收，原生恢复不是托盘恢复；服务控制仍为真实 SCM 后端 E2E，尚需 GUI 服务操作验收。测试临时调试设置不写入发布配置，不部署公网，不改 main。


## 2026-11-25：真实安装版 GUI CI #89 连接修复
- HEAD b38ed5169351c462851e2574c4f181b23f847fab，CI #89 https://github.com/trade3403/localtunnel/actions/runs/45578918748 仅已安装 GUI E2E 失败；job 139083710495 日志 Error: GUI gate timed out: WebView2 debug target，未执行 UI 测试。Rust、真实 TCP、SCM 生命周期、加密转发及构建均通过；核心 #88、Runner #184 通过。失败证据 https://github.com/trade3403/localtunnel/actions/runs/45578918748/artifacts/15006496243 。
- 与上游 https://github.com/tauri-apps/wry/issues/1782 高度吻合：WebView2 Runtime 150+ 管理员进程忽略环境变量调试参数，Windows hosted runner 受影响；本次日志尚未证实 runtime 版本。参考按 EXE 名称的 HKLM AdditionalBrowserArguments 策略 https://github.com/RVYNP/hold-my-brief/commit/7f3b93f88073be1f7274fe4612a39b93284cf5cf 。仅允许 GitHub-hosted Windows CI 脚本设置 localtunnel-desktop.exe 的随机本地调试端口，不覆盖已有 app/wildcard 策略，不修改发行配置、运行权限或安全开关，退出测试进程后 finally 校验并删除本次创建的策略值；保留空父键，不碰其他注册表值。新增 CDP HTTP 可达/目标类型/策略设置与清理证据，识别 page/webview，连接时限 60 秒；修正 Windows PowerShell 5.1 不支持的 0u 字面量。临时 runner 上仍仅使用随机测试密钥/令牌；不用于真实用户电脑。新 CI 待验收，保留全部 GUI 门禁。未改 main。


## 2026-11-25：安装版 GUI 验收通过、服务 GUI 全生命周期验收
- HEAD ade61d31676ec31cdafe141b907cf72fc159bd27，CI #91 https://github.com/trade3403/localtunnel/actions/runs/45581311380 全部通过；临时 CDP 策略修复通过实际安装版 GUI 门禁，真实桌面映射、端口检测、启动/HTTP/流量、原生关闭隐藏后转发、恢复/停止/历史、安装卸载通过。核心 #89、Runner #186 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45581311380/artifacts/15007680224 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45581311380/artifacts/15007396009 。
- 扩展同一个安装版 WebView2 DOM E2E：桌面已停止后，真实勾选并点击一键部署，验证随机新服务名、SCM 手动且停止、密文无测试 token；实际点击开机自启/手动、恢复策略开关、启动/停止，真实 HTTP 及可见字节、持久化记录；第二独立 HTTP fixture 修改本地端口，点击更新后保持禁用，再手动启用并验证不同响应和历史累加；通过输入确切服务名点击注销，验证 SCM 不存在及密文和历史保持。失败清理仅本轮新建的随机服务，CI 专用临时调试策略仍清理；不添加依赖或修改产品安全配置，不改 main。新增服务 GUI 测试待 CI，物理托盘菜单点击尚未验证，公网、非管理员权限、签名安装包仍未完成。


## 2026-11-25：后台服务 GUI 验收通过、系统托盘原生菜单验收
- HEAD d814611e00fda6b408baf0dbc8f2a9ffedf52ae7，CI #93 https://github.com/trade3403/localtunnel/actions/runs/45582618151 全部通过，安装版 WebView2 的真实 SCM 部署、启动方式、恢复策略、启动/HTTP/流量/停止、修改映射后实际不同响应、注销保留历史与凭据、安装卸载通过。核心 #90、Runner #188 通过。安装包 https://github.com/trade3403/localtunnel/actions/runs/45582618151/artifacts/15007237451 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45582618151/artifacts/15007282270 。
- 新增 native_tray_e2e.ps1，严格限制 disposable GitHub-hosted Windows runner、精确安装 EXE/PID、唯一 tray_icon_app HWND、Shell_NotifyIconGetRect 证明真实 shell 注册，依据锁定 tray-icon 0.25.1 源码 https://github.com/tauri-apps/tray-icon/blob/tray-icon-v0.25.1/src/platform_impl/windows/mod.rs 的 6002/WM_RBUTTONUP 通知打开真正原生弹出菜单；核对菜单所属线程、三个实际标签、GetMenuItemRect 与 WindowFromPoint 后对正确菜单项发送真实鼠标输入，不调用 WM_COMMAND、IPC、Rust 菜单处理函数或生产测试钩子。安装版 E2E 新增运行隧道时隐藏→托盘显示→HTTP 保持→托盘停止→HTTP 断开→重启→托盘退出→正常退出码及 HTTP 断开。暂未执行 CI；通知区图标打开使用合成 shell 回调（不是物理右键），菜单项是真实原生鼠标输入；runner 交互桌面/Explorer、菜单可见性仍需实际验证。若不可用保留失败证据，不伪造通过。无新依赖、不改生产配置或 main。下一步通过后收尾 V0.3、V0.4 管理后台。


## 2026-11-25：托盘 CI #95 失败诊断及交接收尾
- HEAD 067823081801e0429b3a00fd885a9b3436b8a964，CI #95 https://github.com/trade3403/localtunnel/actions/runs/45586320102 失败；job 139108726820 的真实错误为 GUI gate timed out: window hidden for tray restore（installed_gui_e2e.mjs:417）。26/26 单测、1/1 真实桌面 TCP（0.78s 测试耗时）、SCM 生命周期及真实加密隧道、依赖锁、3.32 MiB 安装包构建通过；核心 #91、Runner #190 通过。此前桌面/服务 GUI 步骤已执行至托盘段，托盘显示/停止/退出尚未通过，未上传本次安装包。失败证据 https://github.com/trade3403/localtunnel/actions/runs/45586320102/artifacts/15010065689 。最新全绿仍为 d814611e00fda6b408baf0dbc8f2a9ffedf52ae7 / CI #93 https://github.com/trade3403/localtunnel/actions/runs/45582618151 ，安装包 https://github.com/trade3403/localtunnel/actions/runs/45582618151/artifacts/15007237451 。
- 本次收尾修复：第二次关闭不再重新选择 Get-Process.MainWindowHandle，而是复用第一次 WM_CLOSE 隐藏并 ShowWindowAsync 恢复已经验证的同一 HWND（每次仍校验 owner PID），在关闭前要求可见，记录当前枚举句柄是否一致、原始窗口可见/隐藏，仍发送实际 WM_CLOSE 而非强制隐藏。句柄选择错误是待验证假设，不是已证实根因；不跳过托盘原生菜单或真实 HTTP 验收，不修改正式代码、不改 main。新 CI 待验收。按用户要求完成本次收尾后交接，下一窗口必须先查新 HEAD 三个 CI；若失败读实际日志和证据，修复至全绿再进入 V0.4，禁止伪造通过。V0.4 优先本地管理 API/数据模型/auth，后续 Vue3+Ant Design Vue；不部署公网、不要求域名/VPS、不合并 main、不发布正式版。自动开发定时任务保持关闭，未经明确同意不重启。交接由上下文不足风险触发，或用户主动要求；无法精确查询剩余上下文容量，提前提醒并提供完整交接 Prompt。

## 2026-11-25：托盘 CI #96/#97 重复关闭失败，框架状态同步修复
- HEAD ec9d1e95c154f667b2c1c655c88307379356fd93 的 Windows CI #96 https://github.com/trade3403/localtunnel/actions/runs/45588192665 与 #97 https://github.com/trade3403/localtunnel/actions/runs/45588204891 均失败，真实 job 139115125778/139115171744 均为 GUI gate timed out: original main window hidden for tray restore（installed_gui_e2e.mjs:423）。原 HWND 复用未解决。26/26 单测、真实桌面 TCP、NSIS 构建、前序后台服务和 GUI 流程已通过至该门禁；核心 #92、Runner #191/#192 通过。失败证据 https://github.com/trade3403/localtunnel/actions/runs/45588204891/artifacts/15009193994 和 https://github.com/trade3403/localtunnel/actions/runs/45588192665/artifacts/15010186986 。未上传新安装包。
- 查阅锁定 Tao 0.37.3 上游源码（https://github.com/tauri-apps/tao/blob/tao-v0.37.3/src/platform_impl/windows/window.rs 及 window_state.rs）：set_visible 维护 WindowFlags::VISIBLE，apply_diff 对无变化直接返回。首次测试使用外部 ShowWindowAsync 恢复可能让 OS 已显示但框架仍认为隐藏，第二次 hide 无差分。这是有源码支持的假设，尚未被新 CI 验证。本次移除测试中的外部强制显示，首次及第二次均由真实原生托盘菜单恢复，保留相同 HWND 所属 PID/WM_CLOSE/Win32 可见性、两轮隐藏及恢复的实际 HTTP、桌面按钮停止、SCM GUI 全生命周期、托盘停止/重启/退出等门禁；增加 helper 失败动作及有限诊断。未降低门禁或修改正式程序，不使用模拟成功。Shell 打开通知仍为合成回调，实际菜单项为鼠标输入。新 CI 待验收。未修改 main、未部署、未启用定时任务；V0.4 仍等待 V0.3 全绿。最新已验收安装包仍是 CI #93。

## 2026-11-25：V0.3 托盘最终 CI 验收通过，进入 V0.4
- HEAD d9284a806fcbc91fb055e01f1df57a82ec703e2c 的全部 5 个 CI 通过：Windows #98 https://github.com/trade3403/localtunnel/actions/runs/45595455814 、#99 https://github.com/trade3403/localtunnel/actions/runs/45595467322 、核心 #93、Runner #193/#194。#99 的实际 job 139140252979 所有步骤成功，包括真实已安装 GUI、原生 WM_CLOSE 两次、真实托盘菜单恢复/停止/退出、实际 HTTP、后台服务 GUI、锁定构建、安装卸载及上传。安装包 https://github.com/trade3403/localtunnel/actions/runs/45595467322/artifacts/15013697013 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45595467322/artifacts/15014310458 。Shell 打开通知为合成回调而非物理右键；菜单项为实际鼠标输入。此前框架内部可见性不同步的假设得到修复后全绿的支持，不等于独立复现实验。V0.3 阶段 CI 门禁完成；真实公网、普通用户权限、实机重启、性能、长期稳定性、签名与安全审计仍未验收。
- 从该已验收提交新建堆叠分支 feat/v0.4-management-api，新增 crates/server 独立 Axum 0.8.6 / SQLx 0.8.6 / Tokio 1.48.0 crate；仅 IPv4 回环监听，真实 SQLite 迁移及 healthz/readyz，不提供匿名数据操作。初始 users/devices/nodes/domains/mappings 数据模型与归属/端口约束，默认禁用映射；无真实管理员凭据、无默认密码、不操作现有网关。新增真实 Linux HTTP 进程/数据库重启、约束、就绪失败、不安全路径测试及免费 hosted runner 工作流。首轮锁文件因本地环境无法解析依赖，必须由 CI 生成回收并提交，之后严格锁定复验，不算已验收。下一步 CI 全绿且 lock 固定后做管理员认证。未改 main、未部署公网、未启用定时任务。

## 2026-11-25：V0.4 首个管理服务 CI 通过、锁定构建复验
- HEAD 1a02e3c0823d1a07f296c5d0fe1111ce053efaef 全部 6 个 CI 成功：Management #1 https://github.com/trade3403/localtunnel/actions/runs/45597475434 、#2 https://github.com/trade3403/localtunnel/actions/runs/45597497087 、Windows #100、Gateway #94、Runner #196/#197。两个管理服务 job 139147263653/139147335947 均实际通过 Rust 构建、真实回环 HTTP、SQLite 迁移/持久化/约束、就绪状态与不安全路径拒绝，报告 https://github.com/trade3403/localtunnel/actions/runs/45597497087/artifacts/15012909468 。
- 从两份独立成功 CI 的 BEGIN/END 标记回收完整 Cargo.lock（1840 行），逐字比较一致，保留 registry checksum，无手工拼装依赖。提交 crates/server/Cargo.lock；删除每轮 cargo generate-lockfile 步骤，继续 cargo test/build --locked，并增加 git diff 门禁，保留真实 E2E 与证据上传。下一轮严格锁定构建仍需验收，未开发登录或对外开放服务。全绿后进入管理员认证；未改 main、未部署公网、未启用自动任务。

## 2026-11-25：锁定管理服务验收、管理员认证增量
- HEAD 17744e96e2cb03994628cdca98c11acfcc825110 六个 CI 全绿：Management #3 https://github.com/trade3403/localtunnel/actions/runs/45599226639 、#4 https://github.com/trade3403/localtunnel/actions/runs/45599234675 、Windows #101、Gateway #95、Runner #198/#199。严格锁定构建、真实 HTTP/SQLite、git diff 锁文件不变通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45599234675/artifacts/15013974712 。
- 新增 stdin 初始化管理员（空 users 表原子插入）、Argon2id 随机盐、随机32字节 Bearer token 仅存 SHA256 摘要、1小时单会话、登录轮换/注销/降权/禁用/密码变更撤销、4KiB body 上限、全局12次/60秒预算及2个并行哈希任务。真实 CLI/HTTP/SQLite 测试，保留旧测试，迁移计数更新为2。仅回环预览；MFA、密码恢复、普通用户认证、生产 HTTPS 未实现。预算重启清空，可能共享阻塞。新增 Argon2 依赖一次性 cargo metadata 解析，输出锁供回收；构建 --locked 并核对解析后无变化。全部新增功能待 CI，之后回收锁严格复验再进入设备注册。未改 main、未部署、未启动定时任务。

## 2026-11-25：管理员认证功能 CI 全绿、依赖锁固定
- HEAD 6c55714b59363b8079325f3fa36ca19138e1e159 六个 CI 全部成功：Management #5 https://github.com/trade3403/localtunnel/actions/runs/45601461525 、#6 https://github.com/trade3403/localtunnel/actions/runs/45601472905 、Windows #102 https://github.com/trade3403/localtunnel/actions/runs/45601472876 、Gateway #96、Runner #200/#201。两个管理 job 139161190208/139161155178 均通过 Rust 单测、原管理 HTTP/SQLite 测试、新增真实管理员 CLI/HTTP 生命周期、解析后锁文件不变门禁。认证证据 https://github.com/trade3403/localtunnel/actions/runs/45601472905/artifacts/15015866229 。Windows 安装包 https://github.com/trade3403/localtunnel/actions/runs/45601472876/artifacts/15015429121 ，证据 https://github.com/trade3403/localtunnel/actions/runs/45601472876/artifacts/15015359427 。
- 两份独立 CI 日志回收的 Cargo.lock 完全一致，191 个包、1878 行；保留上游 checksum，提交锁文件，移除一次性 cargo metadata 解析步骤，恢复 cargo test/build --locked 及 git diff 门禁，保留认证及原有 E2E。严格锁定复验待通过，之后开发设备注册与认证（管理员授权的一次性配对码、独立设备凭据、禁止匿名管理）。不改 main、不部署生产、不启用自动定时任务。

## 2026-11-25：管理员认证严格锁定验收、设备配对增量
- HEAD bd64c3bdb6cb26763ba0f87811b13b6a69191465 六个 CI 全绿：Management #7 https://github.com/trade3403/localtunnel/actions/runs/45604710827 、#8 https://github.com/trade3403/localtunnel/actions/runs/45604718942 、Windows #103、Gateway #97、Runner #202/#203。#8 job 139172512889 的构建、基础管理 E2E、管理员认证 E2E、锁文件不变均成功，证据 https://github.com/trade3403/localtunnel/actions/runs/45604718942/artifacts/15017865344 。
- 新增第三迁移 device_pairings，管理员签发10分钟256位随机一次性配对码（每管理员一个、重签轮换），角色/密码/禁用变更清除待用码；注册事务先 DELETE RETURNING 再插入设备，一次消费且失败回滚，随机独立设备凭据仅存类型区分 SHA256，管理员和设备凭据互不通用。设备身份检查绑定id、所属管理员与设备状态。管理员列表按所属隔离、游标分页100条；吊销原子检查授权及归属、禁用并轮换凭据摘要、递增revision。吊销不代表数据平面已停止；设备长效凭据及配对码独立于会话，需客户端保护；所有者重新启用后未吊销设备可恢复。真实 CLI+HTTP+SQLite 测试含并发单次兑换、过期、重启、跨归属拒绝、吊销；旧测试保留。注册单进程60次/分钟预算、4KiB上限。无新依赖，严格锁文件门禁不变。新功能待CI。下一步设备配置拉取和状态上报，不合并 main、不部署公网、不启用定时任务。

## 2026-11-25：设备注册验收、配置快照与心跳增量
- HEAD a6ab9b776e8cc0a5cd9078e17819bd7b5bae2eef 六个 CI 全绿：Management #9 https://github.com/trade3403/localtunnel/actions/runs/45606663963 、#10 https://github.com/trade3403/localtunnel/actions/runs/45606671899 、Windows #104、Gateway #98、Runner #204/#205。#10 job 139179209350 真实设备注册与授权生命周期、此前认证/基础测试、严格锁文件检查成功。证据 https://github.com/trade3403/localtunnel/actions/runs/45606671899/artifacts/15018880530 。
- 新增第四迁移 device_status、映射增删改触发设备 revision 更新、账号/设备授权状态变化清除旧心跳。GET devices/{id}/config 同一事务授权及读取期望元数据快照（最多64条，超限拒绝），POST devices/{id}/status 原子授权写入服务器时间及设备自报状态，拒绝未来 revision；GET 同路径仅所属管理员读取。30秒建议心跳、90秒管理在线窗口，configuration_current 仅代表自报版本一致，不等于真实应用成功；按接收顺序记录，不保证消息排序。未下发隧道密钥、未执行映射，不伪造数据平面状态。新增真实 HTTP/SQLite E2E（映射测试夹具经数据库注入，过期时间注入，非真实等待），覆盖归属、版本、过期、重启及吊销。无新增依赖，锁文件不变。新功能待 CI；下一步管理员映射 CRUD、节点及域名验证。未改 main、未部署公网、未启用定时任务。

## 2026-11-25：设备配置及心跳验收、管理员映射 CRUD 增量
- HEAD 19e651522cd8c9fe699305009bb9037b6bda2c48 六个 CI 全绿：Management #11 https://github.com/trade3403/localtunnel/actions/runs/45608475915 、#12 https://github.com/trade3403/localtunnel/actions/runs/45608486198 、Windows #105、Gateway #99、Runner #206/#207。#12 job 139185500790 严格锁定构建、此前回归及真实设备配置/心跳测试成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45608486198/artifacts/15018613360 。
- 新增管理员映射列表/创建/详情/PATCH/DELETE，归属检查及写入时实时会话授权，原子检查启用设备/节点、域名归属、单设备64条上限，复用端口/域名唯一约束和设备 revision 触发器。内部端口20000–29999，本地回环端口1–65535。创建仅禁用草稿，拒绝启用，未验证域名不得用于实际转发；PATCH 支持本地/中转端口及停用，设备/节点/协议/域名不可变，已启用记录仅可单独停用，禁用后才可删除。PATCH/DELETE 强制 expected_revision 防止覆盖并发变更。新增真实HTTP/SQLite CRUD、安全隔离、冲突、重启与上限测试，节点/域名/遗留启用状态采用数据库夹具，不代表实际应用。无新依赖或迁移，保留既有回归与锁门禁。新功能待CI。下一步节点管理和域名所有权验证，再做数据平面配置应用。未改 main、未部署公网、未启用定时任务。

## 2026-11-25：映射 CRUD 验收、节点及 DNS TXT 所有权增量
- HEAD 3af526d82e01dd65831fae6a13bd29a13e76e768 六个 CI 全绿：Management #13 https://github.com/trade3403/localtunnel/actions/runs/45610328368 、#14 https://github.com/trade3403/localtunnel/actions/runs/45610337158 、Windows #106、Gateway #100、Runner #208/#209。#14 job 139191893605 实际映射 CRUD/版本生命周期、所有旧回归与锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45610337158/artifacts/15019239537 。
- 新增本地操作员节点创建/启停CLI、管理员只读节点列表，拒绝有启用映射节点停用；域名所属 CRUD、严格小写 hostname、唯一及100条限制、随机256位TXT公开挑战、轮换及验证时间、引用删除保护。第五迁移新增 verification_token 并清除历史未经新机制证明的 verified_at。固定 /usr/bin/dig 真实DNS TCP查询，精确 owner/完整 TXT/NOERROR，拒绝CNAME；最多2个并发，操作员可指定回环解析器，HTTP不可控。验证后原子复查挑战与授权。CI 安装 dnsutils、启动真实本地 TCP DNS 测试服务，测试错误/正确/轮换/隔离/引用/持久化，不是公网DNS验收。系统DNS信任、历史时间不等于当前仍持有域名、未验证域名抢占/转移/持续复验、真实节点部署和激活仍待开发。无新Rust依赖，保留严格锁及全部回归。新功能待CI。下一步控制面与实际配置应用/回滚安全设计。未改 main、未部署公网、未启用定时任务。

## 2026-11-25：节点与域名验收、管理草稿实际数据平面预览
- HEAD 950d12afb65eb38a12a5eaf3d8ca6daabcea9cf6 全部6个CI成功：Management #15 https://github.com/trade3403/localtunnel/actions/runs/45612141096 、#16 https://github.com/trade3403/localtunnel/actions/runs/45612148583 、Windows #107、Gateway #101、Runner #210/#211。#16 job 139198150205 真实本地DNS TCP TXT验证、节点生命周期及所有旧回归通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45612148583/artifacts/15020029194 。
- 本轮新增 Linux 本地操作员 --export-preview 与 --preview-gateway：仅当前版本、启用所有者/设备/节点、近5分钟TXT证明的禁用HTTP草稿；新建0700目录、复用已有 core CLI 生成0600 Rathole server/client 配置、独立随机token，非秘密manifest，禁止覆盖、路径遍历，子进程仅传相关密钥且输出抑制。操作员负责在管理API停止时执行、保护配置和管理实际进程；无并发一致性保证。独立Nginx空配置初始化、实际apply与clear复用现有核心校验/探测/恢复，不修改系统Nginx，不修改数据库enabled或虚报在线。新增实际API+本地DNS+Noise Rathole+Nginx正文/Host/清空测试，备份存在导致应用前拒绝时验证旧配置和流量保持；不宣称加载后失败的回滚专项已验收。CI复用上游固定Rathole v0.5.0 Linux下载及报告机制（Linux archive SHA256仅记录，非预置比对），无新Rust依赖。新功能待CI。下一步受控应用状态、故障回滚与自动撤销联动；HTTPS及公网、生产进程监督仍未完成。未改 main、未部署公网、未开启定时任务。

## 2026-11-25：管理草稿真实转发验收、业务探测回滚与操作历史
- HEAD 98b41a7d3b6d5a28416e11632eb9beceff22f0a6 六个CI全绿：Management #17 https://github.com/trade3403/localtunnel/actions/runs/45614061399 、#18 https://github.com/trade3403/localtunnel/actions/runs/45614069000 、Windows #108、Gateway #102、Runner #212/#213。#18 job 139204802200 真实管理草稿到 Noise 隧道与 Nginx 流量、基础回归及锁检查全部通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45614069000/artifacts/15020463959 。
- 新增核心 gateway-apply-checked 及管理 CLI apply-checked：真实候选 revision 加载后固定回环 GET /，精确200及预期正文才保留配置，失败走原真实恢复/reload/旧 revision 探测。预期正文来自可信操作员私有普通文件（1–65536字节），curl 不跟随重定向、禁用代理及用户配置、时间/大小限制。新增第六迁移 preview_attempts，前置校验后先记 pending、结束记 succeeded 或 failed_or_unknown，保留异常中断的未知状态，不写敏感凭据或正文。CI 新增故意错误正文触发实际候选请求经 Noise 隧道到达服务后回滚，验证旧文件与旧空网关真实421，再验证正确正文生效；撤销后新应用拒绝、显式清除允许，历史记录核验。仍是停管理API后的本地操作员单HTTP回环预览，未自动撤销旧隧道、未实现历史API/进程监督/并发一致性/HTTPS或公网；不宣称失败状态等于已回滚。无新Rust依赖。新功能待CI；下一步安全控制面联动和自动清理。未改 main、未部署公网、未启用定时任务。

## 2026-11-25：真实业务探测回滚验收、前台监督器撤销清理增量
- HEAD d104ee4583327c5cd857ae890d5b76769bfacf72 六个CI全绿：Management #19 https://github.com/trade3403/localtunnel/actions/runs/45615689727 、#20 https://github.com/trade3403/localtunnel/actions/runs/45615704267 、Windows #109 https://github.com/trade3403/localtunnel/actions/runs/45615704218 、Gateway #103、Runner #214/#215。#20 job 139210410392 真实业务探测错误正文触发reload后回滚、正确正文应用、全部旧测试及锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45615704267/artifacts/15023075019 。Windows 安装版及托盘测试和证据上传通过。
- 新增本地显式 --supervise-preview，专用已运行独立HTTP网关先清空、生成私有bundle、可信绝对引擎启动自身拥有的两个子进程，真实 relay 正文探测再受检网关应用。每500ms查询当前映射版本、设备/账号/节点、历史TXT新鲜度，数据库错误或子进程退出停止，先终止并等待自身relay/client再尝试清空网关；不通过任意PID或HTTP执行命令。同前缀监督锁，其他CLI仍需操作员协调。真实CI追加API撤销、真实流量关闭、网关421和relay不可达、竞争锁测试。仍仅单机单HTTP前台操作员预览；未做异常强杀/实机重启孤儿收割、HTTPS、远程启用及生产一致性，未保证连续DNS或所有旧连接。无新Rust依赖，新功能待CI。未改 main、未部署公网、未开启定时任务。

## 2026-11-25：隧道监督验收、HTTPS配置联动增量
- HEAD 26b49f4609e444cb1f4ed212d42222d1c5e69cba 六个CI全绿：Management #21 https://github.com/trade3403/localtunnel/actions/runs/45617345774 、#22 https://github.com/trade3403/localtunnel/actions/runs/45617356421 、Windows #110 https://github.com/trade3403/localtunnel/actions/runs/45617356317 、Gateway #104、Runner #216/#217。#22 job 139216101664 真实监督器API撤销、隧道停止、网关清除及旧回归全部通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45617356421/artifacts/15022194927 。Windows预览包 https://github.com/trade3403/localtunnel/actions/runs/45617356317/artifacts/15022603961 。
- 新增HTTPS草稿私有隧道导出与本地 --preview-tls-gateway，HTTP路径仍只接受HTTP。专用回环TLS空配置拒绝所有握手；非空仅apply-checked，可信版本化0700证书目录、私有普通文件、至少1天有效性及链/私钥/hostname校验，真实TLS revision与业务正文200检查，失败走已有真实回滚。新增transport历史列（旧记录http），真实本地DNS+Noise+Nginx测试含错误证书、SNI/Host、证书轮换、故障后旧信任和旧流量恢复、撤销后拒绝新应用与显式清空。空配置允许过期证书但仍依赖现存可加载的证书/密钥。仅本地操作员预览，不代表公网CA或自动ACME，HTTPS自动监督/撤销和后台启停仍待开发；无新增Rust依赖。新功能待CI。未改 main、未部署公网、未开启定时任务。

## 2026-11-25：HTTPS 联动验收、HTTPS 监督自动撤销增量
- HEAD 476d02e9e792c0e5dca31e060b6e8e6b89eee5c5 全部6个CI成功：Management #23 https://github.com/trade3403/localtunnel/actions/runs/45620639254 、#24 https://github.com/trade3403/localtunnel/actions/runs/45620649922 、Windows #111、Gateway #105、Runner #218/#219。#24 job 139227562984 的真实 HTTPS 证书轮换及业务失败回滚、所有旧回归、严格锁门禁通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45620649922/artifacts/15025330547 。
- 新增 --supervise-tls-preview，HTTP/HTTPS 共用监督器及严格协议授权；HTTPS 特有端口与目录冲突检查、可信证书/实际 TLS 及正文受检发布、撤销后先停止拥有的 relay/client 再清空专用 TLS 网关（失败不虚报已关闭）。真实 E2E 加入 HTTPS 监督启动、错误协议及端口、竞争锁、实际 API 吊销后握手拒绝且 relay 不可达、网关仍存活及历史记录。无新增 Rust 依赖。仍是单机前台预览，依赖操作员提供的专用网关/不可变证书；未实现异常强杀孤儿回收、自动续期、持续DNS或后台远程启停。新功能待CI，下一步建立本地受控启动/停止请求及状态接口，再开发 Vue 管理后台。未改 main、未部署公网、未启用定时任务。

## 2026-11-25：HTTPS 监督验收、管理启停请求及受控 worker 增量
- HEAD a107d38389d61fe9bd83b69b949449421023e4a9 全部6个CI成功：Management #25 https://github.com/trade3403/localtunnel/actions/runs/45622196911 、#26 https://github.com/trade3403/localtunnel/actions/runs/45622208543 、Windows #112、Gateway #106、Runner #220/#221。#26 job 139233032343 真实 HTTPS 监督撤销、握手拒绝及全部回归/锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45622208543/artifacts/15024558507 。
- 新增第八迁移 runtime_requests、管理员所属 start/stop/runtime API，原子授权及版本/近期TXT门禁，202 queued 不等于已运行，取消及旧请求ID保护，未停止/未知请求阻止编辑删除，过期未领取可替换。可信本地固定参数 one-shot worker（HTTP/HTTPS）等待60秒领取一次、真实监督器受检应用后 running、每500ms检查停止和授权、确认自身子进程停止与网关清除才 stopped，失败或不明保持 failed_or_unknown。无任意命令、路径或密钥经HTTP传入。真实HTTP worker E2E覆盖队列、取消、权限、启动正文、状态与停止后端口不可达。HTTPS worker复用代码，专项测试尚待；非常驻服务、未知状态/孤儿恢复、生产多节点和公网均未完成。无新依赖，新功能待CI。下一步管理后台与状态/操作入口。未改 main、未部署公网、未开启定时任务。

## 2026-11-25：启停 API 验收、Web 管理后台第一批
- HEAD 770cb7d7637ac7fd87719653862fcb96a9ee5aad 六个CI全绿：Management #27 https://github.com/trade3403/localtunnel/actions/runs/45623996311 、#28 https://github.com/trade3403/localtunnel/actions/runs/45624006753 、Windows #113、Gateway #107、Runner #222/#223。#28 job 139239305423 真实HTTP API/worker启停、所有旧回归及锁门禁通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45624006753/artifacts/15027577230 。
- 新增 apps/admin 独立 Vue3/Ant Design Vue/TS/Vite 中文管理台，内存会话、回环同源代理、登录退出、当前页仪表盘、设备配对/状态/吊销、节点只读、域名创建/TXT/轮换、映射创建及运行请求详情和启停。真实 Chromium E2E 新增错误/正确登录、配对设备、节点、域名、映射及未验证启动拒绝。首轮 npm 依赖锁引导：直接依赖精确版本，CI输出实际完整 package-lock 并 npm ci/cmp、构建与测试；下一轮从实际成功CI获取完整锁并提交，再恢复严格锁门禁。不手写伪锁。仍仅回环预览、首100条数据及手动刷新，编辑删除、全量分页、真实浏览器worker启停、流量日志、生产部署待完成。未新增Rust依赖，未改 main、未部署公网、未启用定时任务。新功能待CI。

## 2026-11-25：Web 管理后台 CI 环境修复及真实依赖锁固化
- HEAD 05e4ee4967d8a62d5463646f58bdbcbcad2d3542：Management #29 https://github.com/trade3403/localtunnel/actions/runs/45625768748 、#30 https://github.com/trade3403/localtunnel/actions/runs/45625780978 失败；Windows #114、Gateway #108、Runner #224/#225 均已通过，确认无在途CI后修复。两管理 job 139245418516/139245457671 实际 Rust构建及全部既有HTTP/HTTPS生命周期成功，npm ci/cmp及Vue生产构建成功；Chromium安装失败原文 ERROR: Playwright does not support chromium on ubuntu26.04-x64，真实浏览器用例未执行。
- 管理 CI 固定 ubuntu-24.04 免费托管 runner，保留原 Playwright 1.56.1 与所有实际浏览器/旧回归门禁。从上述两次实际日志取完整 BEGIN_ADMIN_PACKAGE_LOCK 至 END_ADMIN_PACKAGE_LOCK 内容，逐字一致（56950字符、1704行含尾部空行、118个packages条目含根），提交 apps/admin/package-lock.json（含真实registry integrity）；删除临时生成步骤，恢复 npm ci 及锁文件差异检查。无新依赖、未改业务功能，不宣称浏览器已通过。修复待新CI；全绿后继续后台编辑、删除、分页及实际启停。未改main、未部署公网、未开启定时任务。

## 2026-11-25：Chromium 环境修复成功、浏览器按钮定位修复
- HEAD 7a42c9597ec051fee61732874c9e50ed6a84cd1f 管理 #31 https://github.com/trade3403/localtunnel/actions/runs/45627326098 、#32 https://github.com/trade3403/localtunnel/actions/runs/45627336659 失败；Windows #115、Gateway #109、Runner #226/#227 成功，均已结束。实际 job 139250881722/139250924736 的旧回归、锁安装、Vue 构建和 Chromium 安装均成功；浏览器首次点击 getByRole('button',{name:'登录',exact:true}) 在 browser.mjs:46 等待30秒超时。推断 Ant Design Vue 双字自动间隔导致可访问名称变化，未取得旧DOM直接证明。
- 增加登录按钮明确 aria-label，保留真实点击/认证断言；对下拉控件使用稳定组件标识及实际可见弹层，对状态文本等待明确元素，登录后等待刷新结束；失败阶段诊断不输出DOM/凭据。无依赖变化、没有跳过测试或改业务认证。新CI待验收；未进入后台功能增量，未改main、未部署公网、未开启定时任务。

## 2026-11-25：Web 管理后台第一批验收、编辑删除及游标分页
- HEAD b8b4a6de99f6277563404792f835aefa6d1817cd 六个CI全绿：Management #33 https://github.com/trade3403/localtunnel/actions/runs/45629013762 、#34 https://github.com/trade3403/localtunnel/actions/runs/45629024157 、Windows #116、Gateway #110、Runner #228/#229。#34 job 139256895633 实际 Chromium 浏览器第一批功能及全部旧回归、npm/Rust严格锁门禁通过，报告/构建 https://github.com/trade3403/localtunnel/actions/runs/45629024157/artifacts/15030670448 。
- 新增四类列表真实after游标加载更多、当前已加载数（非全局），刷新及变更重置首批；映射端口编辑保留打开时版本、映射版本删除及域名引用删除保护，确认操作。新增真实Chromium测试节点102条（1 CLI + 101 SQLite夹具）跨100边界、端口修改与revision、引用拒绝及实际删除。保留旧测试和严格锁，无新增依赖/后端修改。仍仅回环预览、非全量一致性快照、未完成浏览器真实worker启停、HTTPS worker专项、流量/审计/常驻执行器。新功能待CI。未改main、未部署公网、未开启定时任务。

## 2026-11-25：管理后台第二批验收、浏览器与真实隧道联动增量
- HEAD 61e6a8c9fe0e4e2939c26adfdc68d68a3a6cde43 六个CI全绿：Management #35 https://github.com/trade3403/localtunnel/actions/runs/45630809953 、#36 https://github.com/trade3403/localtunnel/actions/runs/45630819862 、Windows #117、Gateway #111、Runner #230/#231。#36 job 139263202250 实际 Chromium 游标分页、映射修改及删除、域名引用保护与全部旧回归、双锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45630819862/artifacts/15030651745 。
- 新增实际浏览器 UI DNS挑战/验证、映射创建、启动请求与真实本地 worker、Noise/Nginx 正文、运行状态刷新、停止请求/退出/网关421/relay不可达；复用固定上游引擎下载及真实TCP DNS夹具，不伪造API、DNS验证或业务。HTTPS专项追加实际 API/worker start/stop、可信TLS正文/状态及拒绝握手。无新依赖、无产品业务代码修改。新验收待CI；仍仅单机回环、需本地操作员预配执行器，生产常驻、流量审计、Windows联合、公网未完成。下一步常驻执行器及安全恢复。未改main、未部署公网、未开启定时任务。

## 2026-11-25：浏览器真实隧道验收、常驻前台执行器增量
- HEAD 73bc7fb3c4dacbba2b5524aecc6fae7fa3c5b771 六个CI全绿：Management #37 https://github.com/trade3403/localtunnel/actions/runs/45632626458 、#38 https://github.com/trade3403/localtunnel/actions/runs/45632637702 、Windows #118、Gateway #112、Runner #232/#233。#38 job 139269631231 实际浏览器请求启停/Noise/Nginx正文、HTTPS worker专项与全部旧回归及双锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45632637702/artifacts/15031652472 。
- 新增固定映射版本 HTTP/HTTPS 常驻前台 worker，重复领取独立授权请求、独立私有bundle和随机token、成功后清理本轮bundle、共享worker锁、本地停止标记、空闲授权检查及未知状态拒绝重试。真实HTTP E2E 两轮API启停、竞争锁、活动期停止标记及实际子进程异常退出/清理/失败记录/重启拒绝；TLS常驻专项尚待。未做systemd/强杀主进程孤儿收割、未知状态自动恢复、生产多节点、公网；无新增依赖，新功能待CI。下一步安全异常恢复及流量/审计。未改main、未部署公网、未开启定时任务。

## 2026-11-25：常驻执行器验收、Linux 主进程死亡保护和本地恢复
- HEAD 22c7cf853ba8ce47f272a2ba01b226a166941294 全部6个CI成功：Management #39 https://github.com/trade3403/localtunnel/actions/runs/45634491008 、#40 https://github.com/trade3403/localtunnel/actions/runs/45634504701 、Windows #119 https://github.com/trade3403/localtunnel/actions/runs/45634504851 、Gateway #113、Runner #234/#235。#40 job 139276227425 真实常驻多轮启停、故障清理、旧回归、浏览器及双锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45634504701/artifacts/15033320998 。Windows未签名包 https://github.com/trade3403/localtunnel/actions/runs/45634504851/artifacts/15033106582 。
- 新增 Linux 直接引擎子进程 PDEATHSIG/SIGKILL 与父PID竞态检查、永久内核flock guard + stale证据标记、每个runtime请求非秘密私有持久化恢复记录。显式本地 --recover-runtime 持双锁、核对精确请求/映射版本/协议/端口、监听拒绝、实际网关清除及再次端口检查，条件恢复stopped，保留bundle/记录，不杀任意PID、不自动重启。真实HTTP测试增加活跃恢复拒绝、主进程SIGKILL、监听关闭、显式恢复与重复拒绝。libc已存在于锁（0.2.191），新增直接引用及根锁引用，不更改版本或registry校验。仍需人工处理早期无记录/中断网关/备份/无证书、任意派生子进程、systemd/reboot、TLS常驻恢复专项及生产多节点；无公网。新功能待CI。下一步流量统计与审计，保留安全边界。未改main、未部署公网、未开启定时任务。

## 2026-11-25：异常恢复验收、真实网关流量观测
- HEAD 869a037f445fdd2b84c6dfb13da18d46ae537b5c 全部6个CI通过：Management #41 https://github.com/trade3403/localtunnel/actions/runs/45636601598 、#42 https://github.com/trade3403/localtunnel/actions/runs/45636615751 、Windows #120、Gateway #114、Runner #236/#237。#42 job 139283676297 真实主进程SIGKILL/显式恢复、全部旧回归及双锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45636615751/artifacts/15033087787 。
- 受检单路由Nginx按revision写数字-only HTTP请求长度/响应发送字节/状态；运行worker有界增量读取、按request_id持久化（迁移9），所属管理员最近50次观测API及后台详情，真实HTTP请求/隔离/终止快照、Chromium流量展示测试。不是加密链路字节或计费；含业务探测、异常仅保留上次采样、停止partial，文件4MiB采样上限非磁盘上限，无轮转保留期、跨主机/TCP/UDP或完整报表。无新依赖，待CI；下一步审计/日志及流量保留策略。未改main、未部署公网、未开启定时任务。

## 2026-11-25：流量观测验收、操作审计与历史维护
- HEAD 48992420bc099325fbabd7a75ed8438340a3aa81 六个CI全绿：Management #43 https://github.com/trade3403/localtunnel/actions/runs/45638825561 、#44 https://github.com/trade3403/localtunnel/actions/runs/45638840885 、Windows #121、Gateway #115、Runner #238/#239。#44 job 139291533460 实际HTTP流量/权限隔离、Chromium展示、全部旧回归及双锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45638840885/artifacts/15034348146 。
- 新增迁移10同事务资源状态审计触发器、所属管理员递减游标API、中文后台操作审计、可信本地显式90日历史清理（保留当前请求流量），实际CRUD/隔离/保留/游标及浏览器运行状态转换用例。非完整请求/操作者/失败登录审计，无敏感凭据、无自动调度/防篡改/文件轮转。新功能待CI，无新依赖。下一步Windows客户端管理联动及未完成TLS专项/最终验收。未改main、未部署公网、未开启定时任务。

## 2026-11-25：操作审计验收、Windows 管理设备联动第一批
- HEAD b92d2a13261f84436dc4496b3c8dc7103a716d3a 六个CI全绿：Management #45 https://github.com/trade3403/localtunnel/actions/runs/45640945788 、#46 https://github.com/trade3403/localtunnel/actions/runs/45640959700 、Windows #122、Gateway #116、Runner #240/#241。#46 job 139299149527 实际审计/权限/历史清理/Chromium及所有旧回归和双锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45640959700/artifacts/15034989184 。
- Windows 客户端新增实际本机管理配对、独立当前用户DPAPI设备token、身份/配置元数据/手动心跳同步、吊销拒绝及本地移除；token不回WebView、固定回环高位端口、禁代理跳转、响应限制。不自动应用远程草稿或影响原隧道。reqwest 0.13.5 已锁定，新增直接引用及根锁引用，不新引入TLS。Windows CI 增加同commit真实控制面构建及安装版GUI配对/实际后台心跳/吊销/DPAPI验证。新功能待CI，仍无远程TLS/自动同步/管理隧道配置下发、服务模式管理设备、真实公网/普通用户验收。未改main、未部署公网、未开启定时任务。

## 2026-11-25：Windows 管理联动 CI 修复
- HEAD bde2ea61c07795730c4d848ba5b6982483e990e1 六个CI均结束：Management #47 https://github.com/trade3403/localtunnel/actions/runs/45643414508 成功、#48 https://github.com/trade3403/localtunnel/actions/runs/45643428070 失败；Windows #123 https://github.com/trade3403/localtunnel/actions/runs/45643428262 失败；Gateway #117、Runner #242/#243 成功。
- 实际 Management job 139307897270 在 preview_e2e.py:257 报 AssertionError: candidate was not actually probed。推测Nginx新旧worker切换竞争，无旧连接归属直接证据。受检业务代理响应增加由网关注入的revision并隐藏上游同名头，curl核对同候选版本+200+精确正文；错误代际/连接失败有界重试，候选错误响应直接回滚。旧版本及TLS探测有界等待，原真实探测/回滚测试不放宽，新增解析单测。
- 实际 Windows job 139307898176 已通过Rust单测、Noise/SCM、NSIS构建、真实控制面构建与锁门禁；真实安装GUI经过新管理配对/DPAPI/同步/吊销/移除后，在 installed_gui_e2e.mjs:396 GUI gate timed out: enabled service button 一键部署新服务。代码证实新增管理checkbox在原SCM确认框前，旧首个checkbox选择错误；SCM独立aria-label与精确测试选择器修复，保留所有业务门禁。无新依赖，不进入自动心跳下一阶段，修复待CI。未改main、未部署公网、未开启定时任务。

## 2026-11-25：Windows 安装版验收通过、修复 curl 响应头提取
- HEAD bf21b5b68140c5568b6d54ffaf136f49a2c89230 六个CI已完成：Windows #124 https://github.com/trade3403/localtunnel/actions/runs/45647723194 成功，安装包 https://github.com/trade3403/localtunnel/actions/runs/45647723194/artifacts/15037889584 ，报告 https://github.com/trade3403/localtunnel/actions/runs/45647723194/artifacts/15037909401 ；Gateway #118、Runner #244/#245 成功。Management #49 https://github.com/trade3403/localtunnel/actions/runs/45647711783 、#50 https://github.com/trade3403/localtunnel/actions/runs/45647723083 均失败，job 139323118964/139323158331 在 preview_e2e.py:265 正确正文受检应用返回非零。
- 本地实际 curl 8.10.1 + HTTP fixture 复现：%{header:x-localtunnel-revision} 产生未知变量stderr、退出0且版本为空；%header{x-localtunnel-revision} 正确输出 real\nbody\n200 10-20。修正HTTP/HTTPS共享write-out格式，成功退出但stderr非空拒绝；增加真实本地TCP/curl格式测试。保留严格版本/正文/状态与旧回滚断言，原#48时序原因未直接证实。无新依赖，待六CI全绿，不进入下一阶段自动心跳。未改main、未部署公网、未开启定时任务。

## 2026-11-26：网关修复全绿、Windows 原生自动心跳
- HEAD 282c22fbcb01ac21fa7fa720e122e2a650eb50fc 六个CI成功：Management #51 https://github.com/trade3403/localtunnel/actions/runs/45649362929 、#52 https://github.com/trade3403/localtunnel/actions/runs/45649369889 、Windows #125 https://github.com/trade3403/localtunnel/actions/runs/45649370044 、Gateway #119、Runner #246/#247。#52 job 139329322354 所有真实管理/Noise/HTTP/TLS/回滚/Chromium及锁门禁成功，报告 https://github.com/trade3403/localtunnel/actions/runs/45649369889/artifacts/15038144395 。Windows未签名包 https://github.com/trade3403/localtunnel/actions/runs/45649370044/artifacts/15039753534 。
- Rust原生后台任务约30秒同步identity/config/status，托盘隐藏仍运行；共享串行锁、手动重设周期、无凭据不联网、暂时错误限频重试/清除观测、401阻断后续请求直至显式移除/重配或进程重启重新验证。Vue只读无秘密快照和明确状态；真实安装GUI新增隐藏自动同步映射版本、托盘恢复、进程重启DPAPI恢复与自动心跳、自动吊销拒绝。无新增依赖，不改变手动/SCM隧道，不自动应用管理草稿；仍限本机回环，非远程TLS/生产部署，待CI。下一步HTTPS常驻恢复专项及V0.4最终验收。未改main、未部署公网、未开启ChatGPT定时任务。

## 2026-11-26：Windows 自动心跳重启测试修复
- HEAD 1f76e5f2cb0315d05262deef2bd1cbc409c4b0df 正式开发分支6个CI均结束：Management #53 https://github.com/trade3403/localtunnel/actions/runs/45654007200 、#54 https://github.com/trade3403/localtunnel/actions/runs/45654021460 成功，Gateway #120、Runner #249/#250 成功，Windows #126 https://github.com/trade3403/localtunnel/actions/runs/45654021536 失败；备份分支Runner #248成功，不计正式六CI。正式分支此前接口阻塞已解除。
- Windows job 139345752080 已通过Rust单测、真实Noise/SCM、NSIS、控制面构建、锁门禁；实际安装GUI通过配对/手动同步及隐藏窗口的自动心跳、配置版本变化、托盘恢复和元数据显示，主动退出时 installed_gui_e2e.mjs:344 被 until helper 的通用进程退出保护误判。改为独立有界退出码0门禁、旧CDP清理、测试专用新端口和profile重连、真实DPAPI身份恢复和表单就绪检查；原重启后自动心跳、吊销及所有旧回归仍必须通过。无产品代码/依赖改动，待CI全绿再做HTTPS专项。未改main、未部署公网、未开启定时任务。

## 2026-11-26：Windows 自动心跳全绿、HTTPS 常驻恢复专项
- HEAD c4985acd1a8b1c028114d19c160bab2279711c59 六CI通过：Management #55 https://github.com/trade3403/localtunnel/actions/runs/45656309371 、#56 https://github.com/trade3403/localtunnel/actions/runs/45656320256 、Windows #127 https://github.com/trade3403/localtunnel/actions/runs/45656320208 、Gateway #121、Runner #251/#252。Windows job 139353865906 真实安装GUI/隐藏自动心跳/重启DPAPI/自动吊销及既有Noise/SCM/托盘门禁全过，报告 https://github.com/trade3403/localtunnel/actions/runs/45656320208/artifacts/15043387779 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45656320208/artifacts/15044570493 ；Management证据 https://github.com/trade3403/localtunnel/actions/runs/45656320256/artifacts/15042503059 。
- HTTPS真实专项新增常驻多轮启停、自有引擎故障、活动恢复拒绝、错误请求拒绝、端口占用拒绝、主管SIGKILL/PDEATHSIG、精确TLS恢复记录、清除后的TLS握手拒绝/独立Nginx存活、恢复后新请求实际CA验证正文及本地停止。保留失败证据、成功清理、原有门禁。无产品代码/依赖变化，待CI；下一步V0.4最终验收及明确未完成生产边界。未改main、未部署公网、未开启定时任务。

## 2026-11-26：HTTPS 常驻恢复全绿、V0.4 最终验收门禁
- HEAD d21c0443aeae221172eb5a1e6eb5ef5dcd1050ab 六CI全绿：Management #57 https://github.com/trade3403/localtunnel/actions/runs/45660656427 、#58 https://github.com/trade3403/localtunnel/actions/runs/45660672583 ，Windows #128 https://github.com/trade3403/localtunnel/actions/runs/45660672597 ，Gateway #122、Runner #253/#254。#58 job 139369338718 真实HTTPS故障恢复与全部管理/浏览器回归成功，证据 https://github.com/trade3403/localtunnel/actions/runs/45660672583/artifacts/15045291519 ；Windows job 139369339289 全部真实安装GUI/SCM/Noise回归通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45660672597/artifacts/15046540966 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45660672597/artifacts/15045697127 。
- 更新README现状与入口，新增docs/v0.4-acceptance.md 记录实测SHA、可复现操作入口、明确回环与生产边界、V0.5优先项。新增 tests/verify_v04_evidence.py 及两个CI步骤，在真实测试成功后严格核对管理9份报告54个字段、桌面4份报告88个字段；拒绝缺失/非true/重复字段，并有验证器负例单测。未改变产品运行逻辑、依赖及原测试门禁。最终证据门禁待新CI；全部通过后进入V0.5资源上限与限流。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.4 最终验收全绿，V0.5 资源保护第一批
- V0.4 HEAD d6440ab87c7f9b782ef32a3689d32719935124d0 六CI全部成功：Management #59 https://github.com/trade3403/localtunnel/actions/runs/45664984037 、#60 https://github.com/trade3403/localtunnel/actions/runs/45664993154 ，Windows #129 https://github.com/trade3403/localtunnel/actions/runs/45664993096 ，Gateway #123、Runner #255/#256。管理job 139384634049 与桌面job 139384634216 的54/88项证据门禁均成功；报告 https://github.com/trade3403/localtunnel/actions/runs/45664993154/artifacts/15045534976 、https://github.com/trade3403/localtunnel/actions/runs/45664993096/artifacts/15047221649 ，未签名安装包 https://github.com/trade3403/localtunnel/actions/runs/45664993096/artifacts/15048435188 。
- 新叠加分支 feat/v0.5-security-stability，第一批 Axum 全局固定内存令牌桶120/s、突发240、32并发无队列、12秒处理期限、URI/header/声明body边界、统一安全响应头；原业务限流不变。真实慢body/并发/期限/突发429/恢复测试及确定性单测，显式启用已锁定Tokio time feature，无新版本/依赖。仅应用层，不保证连接级/全局公平/公网DoS或超时写入撤销。待CI，下一步连接级保护及配额。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 资源保护测试修复
- HEAD 80bc16c6533cb4534a0fa1cb35ee911d250b7939 正式分支 push 两项结束：Runner #257 https://github.com/trade3403/localtunnel/actions/runs/45667046953 成功，Management #61 https://github.com/trade3403/localtunnel/actions/runs/45667046956 失败。job 139391901278 实际 Rust 编译/单测和基础 HTTP/SQLite 成功；protection_e2e.py:17 TypeError HTTPConnection object does not support context manager protocol，业务断言尚未执行。
- 修复两处 HTTPConnection 生命周期为 contextlib.closing，逐个保存慢连接确保失败清理；管理证据门禁在旧54项基础上新增4项及负例测试。产品限制、依赖及原验收断言不改。恢复全量 CI，建立叠加草稿PR；新版本待CI，不提前开发连接级保护。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 应用层资源保护全绿、连接层保护
- HEAD 70572a88b201fe902f47c6065501cdd779e7bbeb 六CI全绿：Management #62 https://github.com/trade3403/localtunnel/actions/runs/45668971892 、#63 https://github.com/trade3403/localtunnel/actions/runs/45668997835 ，Windows #130 https://github.com/trade3403/localtunnel/actions/runs/45668997849 ，Gateway #124、Runner #258/#259。#63 job 139398818597 实际资源保护/期限/突发限流及58项管理证据通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45668997835/artifacts/15047694882 ；Windows报告 https://github.com/trade3403/localtunnel/actions/runs/45668997849/artifacts/15048449875 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45668997849/artifacts/15049586499 。草稿PR #7 叠加在V0.4。
- 用Hyper HTTP/1显式连接驱动保留Axum路由，64已接纳socket任务、超额立即关闭、5秒完整头期限、32KiB读缓冲、120秒连接总寿命，原业务保护不变。复用锁中hyper/hyper-util直接引用，无新版本。真实头部滴流、空闲keepalive、超额/已接纳真实HTTP/恢复专项，四项证据门禁新增至62。未单独测120秒总寿命及慢响应，非公网/内核DoS保障；待CI再做认证/设备配额。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 连接层全绿、认证与设备安全配额
- HEAD d1661874f2d6ea6e59637422a422fd26a5fa20ca 六CI全绿：Management #64 https://github.com/trade3403/localtunnel/actions/runs/45671114563 、#65 https://github.com/trade3403/localtunnel/actions/runs/45671124678 ，Windows #131 https://github.com/trade3403/localtunnel/actions/runs/45671124765 ，Gateway #125、Runner #260/#261。#65 job 139406361748 真实传输/资源/62项证据全过，报告 https://github.com/trade3403/localtunnel/actions/runs/45671124678/artifacts/15049528445 ，Windows报告 https://github.com/trade3403/localtunnel/actions/runs/45671124765/artifacts/15050308013 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45671124765/artifacts/15050248031 。
- 严格验证存储Argon2id PHC工作因子/版本/摘要长度后才校验；注册同一写事务限制每owner 64启用/256总设备含吊销，409回滚保留配对、不写成功事件，吊销释放启用额度不释放总额度。真实HTTP边界/并发/隔离/PHC异常恢复及三项证据门禁至65。无依赖/迁移变化。阈值为预览默认值，既有超额不主动删/禁用，安全归档功能未来补齐。待CI再做访问控制与密钥安全；未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 认证配额全绿、回环访问与凭据文件保护
- HEAD caaeea3e50fe55183a9f433f856b324ca7ce64a8 六CI全绿：Management #66 https://github.com/trade3403/localtunnel/actions/runs/45675256416 、#67 https://github.com/trade3403/localtunnel/actions/runs/45675268208 ，Windows #132 https://github.com/trade3403/localtunnel/actions/runs/45675268035 ，Gateway #126、Runner #262/#263。#67 job 139420992157 实际认证/注册/65项证据全过，报告 https://github.com/trade3403/localtunnel/actions/runs/45675268208/artifacts/15051851324 ，Windows报告 https://github.com/trade3403/localtunnel/actions/runs/45675268035/artifacts/15051443066 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45675268035/artifacts/15052931517 。
- 管理API本机Host/Origin/Fetch-Site及重复头门禁，固定Vite同源兼容、原Bearer与所属限制不变；Linux进程启动umask077、目录有效UID、主库及附属文件FD所有权/普通文件/单硬链接校验与0600兼容收紧。新增真实来源/合法密码跨来源无会话、SQLite权限/硬链接测试及3项证据至68。未新增依赖/迁移，仍信任私有父路径/本机原生程序边界，非生产TLS/密钥轮换/Windows ACL新增保障。待CI再做日志轮转/磁盘配额。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 访问边界全绿、日志预算与离线保留期维护
- HEAD 3b1dd35f82ea961056d38b1d07dde6e24becfae3 六CI全绿：Management #68 https://github.com/trade3403/localtunnel/actions/runs/45679320799 、#69 https://github.com/trade3403/localtunnel/actions/runs/45679329341 ，Windows #133 https://github.com/trade3403/localtunnel/actions/runs/45679329307 ，Gateway #127、Runner #264/#265。#69 job 139435330256 真实访问边界/SQLite/浏览器及68项证据全过，报告 https://github.com/trade3403/localtunnel/actions/runs/45679329341/artifacts/15051799436 ，Windows报告 https://github.com/trade3403/localtunnel/actions/runs/45679329307/artifacts/15054526203 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45679329307/artifacts/15053528169 。
- 监督器日志软预算4MiB/文件、32文件/32MiB、512目录扫描、启动预留/运行超限实际停止清空并留证；可信离线显式7日维护双guard/空配置/无pid和标记/端口关闭、仅精确同UID单链接数值日志。实际HTTP超限/故障恢复/拒绝活动维护/离线保留与符号链接拒绝专项及2项证据至70。非硬配额、非在线无损轮转、非全盘保障；未新增依赖/迁移。待CI后补总量/代际边界测试，再推进备份恢复。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 日志预算全绿、HTTPS 总量与代际边界专项
- HEAD 00da3bbcc5ad6d57556aa888a6079dcd63b77b7a 六CI全绿：Management #70 https://github.com/trade3403/localtunnel/actions/runs/45681195755 、#71 https://github.com/trade3403/localtunnel/actions/runs/45681206479 ，Windows #134 https://github.com/trade3403/localtunnel/actions/runs/45681206422 ，Gateway #128、Runner #266/#267。#71 job 139441902379 真实HTTP日志预算/离线清理/HTTPS回归及70项证据通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45681206479/artifacts/15053582821 ，Windows报告 https://github.com/trade3403/localtunnel/actions/runs/45681206422/artifacts/15055700737 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45681206422/artifacts/15055551106 。
- 新增真实HTTPS运行专项：32文件/28MiB新代际预留拒绝、仅32MiB总量超限的真实停止及显式恢复、重新启动独立日志代际和旧文件保留。测试自造稀疏库存，不伪称真实大流量；4项门禁至74，无产品/依赖改动。待CI后进入数据库备份与恢复。仍非全盘硬配额/在线无损轮转。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 日志边界与并发测试修复
- HEAD fd71ebe4090147d4ffabd6acbc160ee8d377b1df Runner #268/#269、Gateway #129、Windows #135 成功；Management #72 https://github.com/trade3403/localtunnel/actions/runs/45683124646 、#73 https://github.com/trade3403/localtunnel/actions/runs/45683140740 失败。#72 job 139448582714 在tls_preview_e2e.py:654 stop(p) AttributeError PosixPath无terminate，新增模块级循环路径覆盖API进程变量；#73 job 139448637693 在protection_e2e.py:115 未观察到32请求许可耗尽，原因未确定。两个Rust构建/单测及基础HTTP均成功。
- 更名所有新增模块级日志路径避免覆盖API进程，保留原真实HTTPS断言与清理；慢请求使用Expect:100-continue确认实际body轮询、32个真实接纳后第33个必须503、全部32个最终期限响应及恢复。未改变产品限制、依赖、74项管理证据或原有断言。待新CI全部通过再进入备份恢复。未改main、未部署公网、未开启定时任务。

## 2026-11-26：V0.5 日志与并发专项全绿、SQLite安全快照及隔离恢复
- HEAD d5c583b74a3988f0cf98fce08a47b911934f50c4 六CI全绿：Management #74 https://github.com/trade3403/localtunnel/actions/runs/45685146577 、#75 https://github.com/trade3403/localtunnel/actions/runs/45685157871 ，Windows #136 https://github.com/trade3403/localtunnel/actions/runs/45685157721 ，Gateway #130、Runner #270/#271。#75 job 139455695924 实际资源/HTTPS日志专项及74项证据通过，报告 https://github.com/trade3403/localtunnel/actions/runs/45685157871/artifacts/15055668747 ，Windows报告 https://github.com/trade3403/localtunnel/actions/runs/45685157721/artifacts/15056622589 ，未签名包 https://github.com/trade3403/localtunnel/actions/runs/45685157721/artifacts/15056817308 。
- Linux本地备份/恢复命令，VACUUM INTO一致性快照、256MiB检查、完整性/外键/精确迁移及schema、私有暂存原子不覆盖发布；恢复只到新目录，清旧会话/配对/心跳/运行、禁旧设备/轮换摘要/禁已启用映射/清DNS证明，保留历史账号密码及配置，切换需可信操作员审查并隔离旧服务。真实WAL/恢复API/异常拒绝测试及3项证据至77。无新依赖/迁移，不宣称备份加密/异地/在线覆盖或全盘硬配额。待CI后补恢复状态及磁盘边界，再负载测试。未改main、未部署公网、未开启定时任务。
