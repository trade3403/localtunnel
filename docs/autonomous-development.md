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
