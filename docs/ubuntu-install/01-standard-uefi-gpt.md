# 第一台电脑：Ubuntu Server 标准安装与 SSH 管理

记录日期：2026-11-27 上午。本文根据上午对话、安装界面和 SSH 登录记录重建，未取得上午独立原文件。实际验证与通用建议分开记录。本仓库公开，IP 和账号均使用示例，不保存密码或主机密钥。

## 一、实际装机结果

- 120GB FASPEED K6-120G SSD（111.8 GiB）安装 Ubuntu Server 24.04.5 LTS。
- 500GB ST3500312CS HDD（465.8 GiB），原 NTFS 分区保留，未挂载。
- UEFI + GPT，SSD 上约 1 GiB FAT32 EFI 分区挂载 /boot/efi，其余约 110.7 GiB ext4 挂载 /，未使用 LVM。
- DHCP 获取局域网地址；Windows SSH 登录已验证。第一台 CPU、内存及主板具体型号未核实。
- 本文仅归档操作系统安装与管理，不要求部署 LocalTunnel 或其他业务软件。

## 二、制作启动盘（Windows）

从 https://ubuntu.com/download/server 下载 Ubuntu Server 24.04 LTS amd64 官方 ISO。使用 https://rufus.ie/ 的 Rufus；建议普通 8GB/16GB U 盘，实际容量必须足够。写盘会清除 U 盘数据，核对目标盘。

```powershell
certutil -hashfile "D:\ISO\ubuntu-server.iso" SHA256
```

将路径改为实际 ISO，核对官方 SHA256SUMS。普通 UEFI 电脑建议 GPT、UEFI（非 CSM），文件系统按 Rufus 提供的选项，优先 ISO 模式；失败可试 DD。旧主板可用 MBR、BIOS/UEFI-CSM 兼容方案，但 U 盘分区表并不决定内部硬盘分区表。若启动菜单无 U 盘，优先后置 USB 2.0 和普通 U 盘。

## 三、BIOS 与安装流程

1. 开机进入 BIOS，开启 USB 控制器、传统 USB 支持，SATA 保持 AHCI；正常 UEFI 电脑选择 UEFI 启动。保存并打开一次性启动菜单，选择 UEFI: SanDisk（实际名称可能不同）。
2. GRUB 第一项 Try or Install Ubuntu Server。语言 English，键盘 English (US)。
3. 选择 Ubuntu Server（非 minimized）；第三方驱动先不选。
4. Network configuration 使用 DHCP，确认 IP；无代理则 Proxy 留空，Mirror 使用可访问的源。
5. Guided storage 选择 Use an entire disk，明确选中 120GB SSD，不选 500GB 数据盘；取消 LVM，不使用 LUKS（本次简化管理方案）。
6. 核对 /boot/efi（FAT32）及 /（ext4）均在 SSD 上，数据盘保留。Done → Continue。此步清除目标 SSD 数据。
7. Profile setup 设置独立主机名、用户名及强密码；Ubuntu Pro 选择 Skip for now。
8. SSH configuration 按空格勾选 Install OpenSSH server（[X]）；若暂用密码登录，保留 Allow password authentication over SSH；可选导入公钥。
9. Featured server snaps 全部不选，按需后装。Installation complete! → Reboot Now，按提示拔 U 盘并回车。

操作键：Tab 切换焦点，方向键选择，Space 勾选，Enter 确认。若出现 VFS kernel panic 或 No boot disk，参见 [第二台老宏碁故障排查](02-acer-legacy-mbr.md)。

## 四、安装后验收

```bash
cat /etc/os-release
lsblk -o NAME,SIZE,MODEL,FSTYPE,MOUNTPOINTS
df -h /
free -h
ip -br a
```

第一台实际安装布局：sda1 EFI，sda2 ext4 根分区，sdb 为保留的 NTFS 硬盘（设备名可能随启动改变，以型号和挂载点为准）。

```bash
sudo systemctl status ssh.socket
sudo ss -lntp | grep :22
```

Ubuntu 可能通过 socket 按需启动 ssh.service，显示 inactive 不必然是故障，以监听和真实连接为准。如果未安装或未启用 SSH，可执行：

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

Windows PowerShell 示例（替换成实际用户名和 IP）：

```powershell
ssh admin@192.168.1.101
```

首次连接核对主机密钥指纹后接受；密码输入时不会显示。重装后若主机密钥改变，先核对新指纹再处理旧记录。长期使用 SSH 密钥，不直接将 22 端口暴露公网。可以通过 Windows 上的 SSH 或支持 SSH 的开发工具管理服务器。

## 五、维护与下次使用

```bash
sudo apt update
sudo apt upgrade
sudo reboot
sudo poweroff
```

重启和关机分别执行最后两条之一。业务工具（Git、Docker 等）按需安装，不是本次装机验收的必要条件；没有证据表明已部署业务服务。建议验收：拔 U 盘冷启动、SSH 登录、再次重启、检查实际磁盘和 IP、完成安全更新、备份重要数据。