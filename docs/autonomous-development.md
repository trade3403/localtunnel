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
