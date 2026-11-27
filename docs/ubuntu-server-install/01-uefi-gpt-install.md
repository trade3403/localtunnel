# 第一台电脑：Ubuntu Server 标准安装（UEFI + GPT）

2026-11-27。依据当天装机手册和对话记录重整理；上午独立原件未找到。公开仓库不保存真实用户名、局域网地址、序列号或密码。

## 实机结果
Ubuntu Server 24.04.5 LTS；FASPEED K6-120G SSD 111.8 GiB，EFI FAT32 1 GiB 挂载 /boot/efi，ext4 110.7 GiB 挂载 /。另一块 ST3500312CS 500GB 机械盘（465.8 GiB）保留原 NTFS 分区，不挂载、不格式化。Windows SSH 登录已实际成功。

## 制作安装盘
从 https://ubuntu.com/download/server 下载 amd64 官方 ISO，核对 SHA256SUMS。在 Windows 使用 https://rufus.ie/ 的 Rufus，选择普通 U 盘（容量足够），GPT + UEFI，文件系统按工具可选项，ISO 模式。失败可试 DD。写入将清除目标 U 盘，务必确认设备。移动 PSSD 曾出现不识别问题，可换普通 U 盘、后置 USB 接口。

## 安装流程
1. 开机进入启动菜单，选择 UEFI USB；GRUB 选择 Try or Install Ubuntu Server。
2. 英文语言、English (US) 键盘，普通 Ubuntu Server，暂不选第三方驱动。
3. 网络 DHCP，Proxy 无代理留空，选择可用镜像源。
4. Use an entire disk 选 120GB SSD，取消 LVM，不启用 LUKS（本次简化方案）。汇总确认 /boot/efi 和 / 都在 SSD，500GB 机械盘不格式化。
5. 仅在目标盘允许清除数据时 Done → Continue。
6. 设置主机名、用户名、强密码。Ubuntu Pro 跳过，勾选 Install OpenSSH server；如需局域网密码登录，允许 password authentication。Featured server snaps 不选。
7. 安装完成 Reboot Now，按提示拔 U 盘。Tab 切换焦点，空格勾选，Enter 确认。

## SSH 和维护
登录后检查：
~~~bash
cat /etc/os-release
lsblk -o NAME,SIZE,MODEL,FSTYPE,MOUNTPOINTS
df -h /
ip -br a
sudo systemctl status ssh.socket
sudo ss -lntp | grep :22
~~~
若未装 SSH：
~~~bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
~~~
ssh.service inactive 但 ssh.socket 正常监听可能是按需启动，并非必然故障。Windows PowerShell 执行 ssh user@192.168.1.100（替换为实际用户名和 IP），核对主机指纹后输入密码，密码无回显属正常。长期建议密钥认证，不把 22 端口直接暴露公网。
~~~bash
sudo apt update
sudo apt upgrade
sudo reboot
# 关机使用 sudo poweroff
~~~
验收：拔 U 盘冷启动、再次重启、核对根分区及第二盘未受影响、实际 SSH 登录。无需为了根目录容量重装系统，也无需部署 LocalTunnel 或其他业务。旧 BIOS 故障参见 [第二台](02-legacy-mbr-recovery.md)。
