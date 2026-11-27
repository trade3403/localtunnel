# 第二台电脑：老宏碁 Acer Aspire MC605 安装与启动故障排查

记录日期：2026-11-27。依据实机照片、命令结果及《Ubuntu Server 装机与故障排查手册 V1.0》整理。最终用户确认成功；最终 MBR 分区命令输出与第二台 SSH 登录未单独留证。仅作系统装机说明，不部署业务软件。

## 1. 设备与结论

- Acer Aspire MC605，BIOS P11-A4L（2013 年）；CPU i5-3350P、内存 4GB（原装机手册记录）。
- 希捷 ST1000DM003-1CH162 标称 1TB，实机约 996GB/927.2 GiB。
- 安装介质：SanDisk Cruzer Edge，约 7.45 GiB，USB 2.0。
- Ubuntu Server 24.04 LTS amd64。
- UEFI 安装盘启动发生 Kernel panic；Legacy 安装成功，但 GPT 内部硬盘不能独立启动；通过 U 盘 GRUB 可启动硬盘系统。重新安装 GRUB 和设置 pmbr_boot 均未解决。最后使用 Legacy + MBR、单 ext4 主分区、自定义安装，用户报告成功。
- 结论：很可能存在老 BIOS 与 GPT 的启动兼容性问题，不能推断所有老主板不支持 GPT。短时 SMART 自检正常不等于硬盘绝对健康。

## 2. 下次直接使用的成功路线

### 制作安装盘与 BIOS

在 Windows Rufus 选择正确 U 盘、官方 Ubuntu Server 24.04 LTS amd64 ISO、MBR、BIOS 或 UEFI-CSM、FAT32（可选时），优先 ISO 写入模式。写盘会清除 U 盘数据。镜像与校验参见 [第一台标准安装](01-standard-uefi-gpt.md)。

BIOS 本次参数：

| 菜单 | 设置 |
|---|---|
| Advanced → Integrated Peripherals | SATA Controller Enabled；SATA Mode AHCI；USB Controller Enabled；Legacy USB Support Enabled；USB Storage Emulation Hard Disk（可尝试） |
| Authentication | Secure Boot Disabled（本次 Legacy 排查） |
| Boot Options | Launch CSM Always；PXE/Video OPROM Legacy；Boot Menu Enabled；Quiet Boot Disabled（便于查看报错） |

F10 → Yes → Enter 保存；F12 打开启动菜单。选择 **SanDisk（不带 UEFI 前缀）**，进入 GRUB 第一项 Try or Install Ubuntu Server。其他主板菜单与按键可能不同。

### 手动创建内部硬盘 MBR（危险：清除目标磁盘数据）

在安装器语言界面按 Ctrl+Alt+F2 进入临时 Linux shell。先执行：

```bash
lsblk -o NAME,SIZE,MODEL,MOUNTPOINTS
test -d /sys/firmware/efi && echo UEFI || echo Legacy
```

应为 Legacy。此次 /dev/sda 为 927.2G 希捷盘且分区未挂载；/dev/sdb 为 7.5G U 盘，挂载 /cdrom。若设备号、型号、挂载点不同必须停止并核对；需保留数据先备份。以下只适用于已授权清空的目标硬盘，不得写入 U 盘。**mklabel 会破坏原分区布局，之后格式化会清除原系统与数据。**

```bash
sudo parted /dev/sda mklabel msdos
sudo parted /dev/sda mkpart primary ext4 1MiB 100%
sudo parted /dev/sda set 1 boot on
sudo parted /dev/sda print
```

如有确认提示，在确认允许清盘后输入 Yes。预期 Partition Table: msdos；一个 primary 分区，从 1049kB 开始、约 996GB、Flags: boot。尚未格式化。注意 sda 不是 sad。

### 保留 MBR，自定义安装

Ctrl+Alt+F1 返回安装器。按照第一台的语言、键盘、网络配置继续；存储界面务必选择 Custom storage layout → Done，不能再次使用 Use an entire disk 或整盘 Reformat，以免生成 GPT。

1. 选整块 ST1000DM003 → Enter → Use As Boot Device。
2. 选 partition 1 existing, unused → Enter → Edit → Format: ext4 → Mount: / → Save。
3. 核对汇总：existing partition of local disk、new ext4、/、约 927.227G；安装 U 盘保持 vfat / in use；无缺少 boot disk 或根分区提示。若仍显示旧布局，返回重新探测或重新启动安装介质检查，不要继续错误配置。
4. Done → Continue（清除目标盘数据）；不创建 RAID、LVM 或 LUKS；其他步骤参见第一台手册。勾选 OpenSSH Server。
5. Installation complete! → Reboot Now，按提示拔除 U 盘。验证独立冷启动及再重启。

建议安装后执行（最终输出尚未留证）：

```bash
lsblk -o NAME,SIZE,MODEL,FSTYPE,MOUNTPOINTS
sudo parted /dev/sda print
findmnt /
ip -br a
```

预期 MBR/msdos、boot 标记、/dev/sda1 挂载 /（实际设备名须核对）。SSH 连接与安全关机见第一台手册。

## 3. 实际失败路径与恢复方法

### U 盘不识别 / Kernel panic

- Removable Device Priority 为空，不代表 USB 不支持。USB Storage Emulation 可尝试 Hard Disk，U 盘可能列在 Hard Disk Drive Priority。优先使用后置 USB 2.0、冷启动、普通 U 盘。
- 错误：VFS: Unable to mount root fs on unknown-block(0,0)。先核对 ISO 与写入；本次 UEFI 普通/HWE 内核尝试失败，Legacy 后进入安装器。无需认定 Rufus 必然有故障。

### 安装成功却显示 No boot disk has been detected or the disk has failed

不要直接判定硬盘损坏。通过安装介质进入临时系统，执行：

```bash
lsblk -o NAME,SIZE,MODEL,FSTYPE,MOUNTPOINTS
sudo parted /dev/sda print
```

旧 GPT 布局为 sda1 约 1MiB bios_grub、sda2 约 927.2GiB ext4。若 Linux 也不能识别硬盘，断电检查 SATA 数据线、电源线、接口及 BIOS 硬件检测。

### 临时引导已安装的 GPT 系统（仅旧布局）

F12 → Legacy SanDisk → GRUB 菜单按 C。必须在 grub> 命令行，不是 ubuntu-server@ubuntu-server:~$ 的 Linux shell。依次：

```text
insmod part_gpt
ls
set root=(hd1,gpt2)
configfile /boot/grub/grub.cfg
```

本次 hd0 为 U 盘，hd1 为希捷；加载 part_gpt 后看到 hd1,gpt1 与 hd1,gpt2。磁盘号以实际 ls 为准。ls -l 曾出现长时间无提示符，可以重新启动后避免重复执行。进入已安装系统后，确认根分区确实在目标硬盘（本次 sda2）才尝试：

```bash
sudo grub-install --target=i386-pc --recheck /dev/sda
sudo update-grub
sudo parted /dev/sda disk_set pmbr_boot on
sudo parted /dev/sda print
sudo poweroff
```

target 后是等号，不是减号；grub-install 必须指向整盘，不是分区。pmbr_boot 仅适用于 GPT，不用于 MBR。update-grub 的 os-prober 警告不影响单系统。关机后拔 U 盘测试。上述操作本次均成功，但独立启动仍失败，不建议反复执行。最终转为第 2 节 MBR 安装。

## 4. SMART 硬盘健康排查

在正常 Linux shell 内执行（核对目标盘）：

```bash
sudo apt install smartmontools
sudo smartctl -a /dev/sda
sudo smartctl -t short /dev/sda
sudo smartctl -l selftest /dev/sda
```

可使用 sudo watch -n 5 smartctl -l selftest /dev/sda 自动刷新，Ctrl+C 退出；不要重复启动自检。Completed without error、00% 表示短检完成无错误。本次实际结果：05/197/198/199 原始值均为 0，温度约 38℃，通电 20,988 小时，无 SMART 错误日志，短时自检通过。长期使用前可执行 sudo smartctl -t long /dev/sda 并在完成后检查日志。短检不排除所有故障。

## 5. 最终验收

- [x] 原 GPT 系统可通过 U 盘手动引导。
- [x] 原 GPT GRUB 安装和更新命令成功，但独立启动失败。
- [x] SMART 短检通过。
- [x] 手动 MBR、boot 标记及自定义 ext4 / 布局在安装前验证。
- [x] 用户报告最终装机成功。
- [ ] 建议补录最终拔 U 盘冷启动、再次重启和最终分区命令输出。
- [ ] 建议验证第二台 SSH、记录实际 IP（私下保存）、进行安全更新及长时硬盘检测。

不要在引导未稳定时升级发行版。文档不保存实际 IP、账户、密码或密钥。