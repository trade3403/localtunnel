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
