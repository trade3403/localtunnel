# 第二台电脑：老宏碁 Legacy + MBR 安装及故障排查

2026-11-27 实机记录。Acer Aspire MC605，BIOS P11-A4L（2013），i5-3350P，4GB 内存，希捷 ST1000DM003 1TB（约 927.2 GiB）。Ubuntu Server 24.04 LTS。最终使用 Legacy + MBR + ext4，用户报告成功；最终 SSH 和重复冷启动尚未单独留证。

## 成功方案（下次直接复用）
Rufus：官方 amd64 ISO，MBR，BIOS 或 UEFI-CSM，FAT32（可选时），ISO 模式。普通 SanDisk Cruzer Edge 8GB（约 7.45 GiB），优先后置 USB 2.0。制作时核对目标 U 盘，写入会擦除它。

BIOS：Onboard SATA Controller Enabled、SATA Mode AHCI、USB Controller Enabled、Legacy USB Support Enabled、USB Storage Emulation Hard Disk、Secure Boot Disabled、Launch CSM Always、PXE/Video OPROM Legacy、Boot Menu Enabled、Quiet Boot Disabled（便于排错）。F10 保存。F12 启动菜单选择不带 UEFI 前缀的 SanDisk。

### 内置硬盘 MBR 分区（会清除目标盘数据）
仅在确认允许清除并备份必要数据后操作。进入安装器语言界面，Ctrl+Alt+F2 打开临时 Linux shell：
~~~bash
lsblk -o NAME,SIZE,MODEL,FSTYPE,MOUNTPOINTS
test -d /sys/firmware/efi && echo UEFI || echo Legacy
~~~
必须显示 Legacy；本次 /dev/sda 为希捷内置盘且未挂载，/dev/sdb 为安装 U 盘。其他机器设备号可能不同，先核对型号、容量、挂载状态，绝不能误操作 U 盘或其他盘。
~~~bash
sudo parted /dev/sda mklabel msdos
sudo parted /dev/sda mkpart primary ext4 1MiB 100%
sudo parted /dev/sda set 1 boot on
sudo parted /dev/sda print
~~~
确认 Partition Table: msdos，单一 primary 分区，boot 标记。mkpart 尚未实际格式化 ext4。

Ctrl+Alt+F1 返回安装器，选 Custom storage layout，不能选 Use an entire disk（可能重建 GPT）。整块希捷盘菜单选 Use As Boot Device；现有 partition 1 → Edit → Format ext4 → Mount / → Save。核对约 927.2 GiB 根分区，U 盘 vfat in use，无缺失 boot disk 或 / 提示；不要整盘 Reformat，不建 LVM/RAID。Done → Continue（确认清除数据）。后续普通 Ubuntu Server、DHCP、Ubuntu Pro 跳过、OpenSSH 勾选、Featured snaps 不选。完成后拔 U 盘重启。

验收：
~~~bash
sudo parted /dev/sda print
lsblk -o NAME,SIZE,MODEL,FSTYPE,MOUNTPOINTS
findmnt /
ip -br a
~~~
应为 msdos、根分区 ext4、独立启动成功。SSH 参见 [第一台](01-uefi-gpt-install.md)。

## 历史故障与修复记录
- UEFI 启动普通及 HWE 内核均曾出现 Kernel panic: VFS: Unable to mount root fs on unknown-block(0,0)，重制启动盘仍失败；改 Legacy 后进入安装器。
- Legacy + GPT 安装成功，但拔 U 盘显示 No boot disk has been detected or the disk has failed，BIOS 启动列表无内置盘。Linux 能识别硬盘与 ext4。
- 添加 pmbr_boot、重装 GRUB、更新配置均成功但独立启动失败。
- SMART 短检通过；改用 Legacy + MBR 后用户确认成功。支持固件兼容性问题的判断，但不能证明所有老 BIOS 均不支持 GPT。

### GPT 救援（历史方案，不是 MBR 安装的必要步骤）
U 盘 Legacy GRUB 菜单按 C，必须在 grub> 提示符下输入：
~~~text
insmod part_gpt
set root=(hd1,gpt2)
configfile /boot/grub/grub.cfg
~~~
设备编号先用 ls 核对，本次 hd1,gpt2 为旧 GPT 根分区。若 ls -l 卡住，重启后避免重复。进入正式 Ubuntu 后核对根分区及盘型号：
~~~bash
findmnt /
lsblk -o NAME,SIZE,MODEL,MOUNTPOINTS
sudo grub-install --target=i386-pc --recheck /dev/sda
sudo update-grub
sudo parted /dev/sda disk_set pmbr_boot on
sudo parted /dev/sda print
sudo poweroff
~~~
target 后是等号。pmbr_boot 仅针对 GPT。以上修复本次全部成功，但仍未解决硬盘独立引导，不必重复。若 Linux 也找不到硬盘，断电检查 SATA 数据线、供电、接口。

### SMART 检测
~~~bash
sudo apt install smartmontools
sudo smartctl -a /dev/sda
sudo smartctl -t short /dev/sda
sudo smartctl -l selftest /dev/sda
sudo watch -n 5 smartctl -l selftest /dev/sda
~~~
Ctrl+C 退出刷新。本次 05/197/198/199 原始值为 0，温度 38℃，通电约 20988 小时，短检 Completed without error。未做长检，不能完全排除硬件故障。长期使用可执行 smartctl -t long 并查询日志。

## 注意
同款老宏碁优先复用 Legacy + MBR，其他正常 UEFI 电脑优先 GPT。公开仓库不存真实账号、IP、密码、序列号。本次只安装系统，不部署业务。
