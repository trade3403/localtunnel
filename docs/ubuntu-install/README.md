# Ubuntu Server 装机资料索引

2026-11-27 两台电脑实战归档。仅系统安装与运维，不涉及 LocalTunnel 软件部署。

| 文档 | 用途 |
|---|---|
| [01 第一台：标准 UEFI + GPT 安装及 SSH](01-standard-uefi-gpt.md) | 120GB SSD 系统盘、保留 500GB HDD、SSH 远程管理 |
| [02 第二台：Acer Aspire MC605 Legacy + MBR](02-acer-legacy-mbr.md) | 老 BIOS、启动失败排查、GRUB 救援、SMART、自定义分区 |

## 方案选择

一般支持 UEFI 的电脑优先 UEFI + GPT。此次老宏碁使用 Legacy + GPT 时可安装但无法从硬盘独立启动，GRUB 修复无效；最终 Legacy + MBR 自定义安装后用户报告成功。同款老机可优先参考第二份说明。

## 资料来源与边界

第一份根据上午安装对话及命令记录重建，未找到上午独立原文件；第二份依据下午实机记录及用户上传的《Ubuntu Server 装机与故障排查手册》整理。公开仓库不记录真实 IP、登录账户、密码和密钥。示例命令务必根据实际设备号调整。重建分区表或格式化会清除目标盘数据，先备份。

最终第二台 MBR 启动验收及 SSH 输出尚未单独归档，不应将建议检查写成已验证结果。
