# setup-ssh

Windows OpenSSH 服务端 / 客户端一键安装与配置脚本（PowerShell 5.1+，当前版本 **v7.6**），附 Linux 端 `setup-ssh.sh`。

面向“全新系统装不上、装上了连不上、连上了密钥登录又失败”这类真实场景，把主机密钥、ACL、账号 profile、防火墙、客户端密钥、自检等一整套流程做成可重复执行的幂等脚本。所有关键修复都有实机复现依据，详见脚本文件头的版本说明。

> Windows 适用于 Windows 10 / 11；Windows Server 2019+ 理论兼容但未充分验证。Linux 端支持 Debian/Ubuntu、RHEL/CentOS/Rocky/Alma/Fedora/openEuler、openSUSE/SLES、Arch、Alpine、Amazon Linux、Alibaba Cloud Linux。

---

## 功能特性

- **多级安装降级链**：`Add-WindowsCapability` → `DISM` → 本地离线包 → `winget` → GitHub 官方包，适配无外网 / 被墙 / 组件库损坏的机器。
- **主机密钥自愈**：全新系统缺 `rsa/ecdsa/ed25519` 主机密钥时主动补齐；检测到带口令或被改坏的旧密钥会自动改名保留并重建。
- **ACL / owner 强制规范化**（v7.4）：主机私钥、`sshd_config`、数据目录只保留 `SYSTEM` + `Administrators`，owner 也必须是二者之一。这解决了“管理员跑 `sshd -t` 能过、服务却起不来（SCM 7034）”和“公钥登录 Permission denied”的根因。
- **规避 `Match Group administrators` 崩溃**：Windows OpenSSH 9.5.6.2 / 10.0p2 均实测复现鉴权子进程 `0xc0000005` 崩溃；脚本会自动注释该配置块，统一使用用户级 `authorized_keys`。
- **账号与 profile 处理**：支持创建专用 SSH 账号（默认 `ssh`）、启用 Administrator、加入 Administrators 组（按 SID `S-1-5-32-544` 解析，不依赖本地化组名）；预建用户 profile，避免家目录漂移导致公钥读不到。
- **防火墙放行判定**（v7.6）：按活动网络 Profile、规则作用域、GPO `ActiveStore`、Block 优先级综合判断；不再出现“规则看似存在、22 却被静默丢弃”。
- **配置校验**：写入后立即 `sshd -t`；启动失败自动收集 SCM / OpenSSH / 崩溃日志并重试。
- **真实登录自检**：端口监听 + 回环 TCP + 密钥登录三重验证，问题在安装当场暴露。
- **客户端配置**：生成 `ed25519` 密钥对、修正 `.ssh` ACL、配置 `ssh-agent` 服务。
- **可恢复**：全程日志；支持 `-Preflight`（只读预检）、`-Uninstall`、`-RebootNow`（重启后自动续跑）。
- **幂等**：重复运行不会重复建账号/密钥/规则（v7.6 起无活动网络时也会复用已有规则）。

---

## 快速开始

### 方式一：双击运行（推荐）

```text
setup-ssh.bat
```

自动请求 UAC 提权，然后按默认流程安装：安装 OpenSSH Server → 配置主机密钥与 sshd_config → 放行防火墙 → 创建 `ssh/ssh` 账号（加入 Administrators）→ 启动服务 → 生成客户端密钥 → 自检并输出连接信息。

> **默认账号 `ssh` / 密码 `ssh` 仅供初始连接，登录后请立即修改或改用密钥。**

### 方式二：命令行

```powershell
# 只读预检（不改任何东西）
.\setup-ssh.ps1 -Preflight

# 自定义端口，不创建账号（沿用现有账号/密钥）
.\setup-ssh.ps1 -Port 2222 -SkipAccount

# 创建专用 SSH 账号并加入管理员组
.\setup-ssh.ps1 -AddSshUser
.\setup-ssh.ps1 -AddSshUser -SshUserName ops -SshUserPassword 'Ch@ngeMe123'

# 创建普通本地用户
.\setup-ssh.ps1 -CreateUser 'dev:P@ssw0rd'

# 只配置客户端（生成密钥、ssh-agent），不装服务端
.\setup-ssh.ps1 -ClientOnly

# 无外网 / 被墙：优先使用脚本目录下的离线包
.\setup-ssh.ps1 -PreferOffline
.\setup-ssh.ps1 -PackagePath 'D:\pkg\OpenSSH-Offline-Bundle.zip'

# 卸载
.\setup-ssh.ps1 -Uninstall
```

> 服务端安装与卸载需要管理员权限；`-ClientOnly` 不需要。`setup-ssh.bat` 会自动提权并转发参数。

### 离线安装

离线包**不在本仓库中**（体积原因），可从 [Releases](https://github.com/Misszyw/setup-ssh/releases) 下载，或自行准备以下任一种，放在脚本同目录或上级目录：

```text
setup-ssh.ps1
OpenSSH-Offline-Bundle.zip     ← 内含 OpenSSH-Win64 负载
# 或解出的目录：
payload\sshd.exe ...
```

`-PreferOffline` 会优先走离线路径；普通模式下离线包位于降级链的 `DISM` 之后、`winget` 之前。

---

### Linux 端（setup-ssh.sh）

```bash
sudo bash setup-ssh.sh                          # 安装 + 启动 + 防火墙 + 验证
sudo bash setup-ssh.sh --port=2222              # 自定义端口
sudo bash setup-ssh.sh --no-firewall            # 跳过防火墙
sudo bash setup-ssh.sh --root-login             # 启用 root 密码登录（可选 =密码）
sudo bash setup-ssh.sh --create-user=ops        # 创建可登录用户（可选 :密码）
```

自动识别发行版并选择 `ufw` / `firewalld` / `nftables` / `iptables` 后端。

---

## 参数说明

| 参数 | 说明 |
|---|---|
| `-Port <int>` | sshd 监听端口，默认 `22`。 |
| `-AddSshUser` | 创建专用 SSH 账号（默认 `ssh/ssh`，启用并加入 Administrators）。幂等。 |
| `-SshUserName <name>` | 配合 `-AddSshUser` 指定账号名。 |
| `-SshUserPassword <pwd>` | 配合 `-AddSshUser` 指定密码；留空时交互输入，非交互模式随机生成。 |
| `-CreateUser "user[:pwd]"` | 创建本地用户；不写密码则交互/随机生成。 |
| `-AdminUser` | 配合 `-CreateUser`，把新用户加入 Administrators。 |
| `-EnableAdmin` | 启用内置 Administrator 并设置密码。 |
| `-AdminPassword <pwd>` | 配合 `-EnableAdmin`。 |
| `-SkipAccount` | 跳过账号配置（已有可用账号或只用密钥时）。 |
| `-ClientOnly` | 只做客户端配置（密钥、ssh-agent）。 |
| `-DefaultShell PowerShell\|Cmd\|Keep` | 设置默认 Shell，默认 `Keep`（不修改）。 |
| `-NoFirewall` | 跳过防火墙配置。 |
| `-NoKeygen` | 跳过用户密钥对生成。 |
| `-Preflight` | 只读预检，不修改任何系统状态。 |
| `-Uninstall` | 停止并删除 sshd 服务与配置（需管理员）。 |
| `-RebootNow` | 组件已暂存需重启时，注册续跑任务并立即重启，登录后自动继续。 |
| `-ResumeAfterReboot` | 内部参数，由续跑任务调用，一般无需手动指定。 |
| `-PreferOffline` | 优先使用本地离线负载，跳过联网安装路径。 |
| `-PackagePath <path>` | 显式指定离线包（zip 或含 `sshd.exe` 的目录）。 |
| `-Help` | 显示完整帮助。 |

退出码：`0` 成功；`1` 权限/安装失败；`2` 端口非法；`4` 组件已暂存、需要重启。

---

## 执行流程

正常模式共 8 步（`-ClientOnly` 4 步，`-Preflight` / `-Uninstall` 2 步）：

1. **环境预检**：系统版本、组件状态、待重启标记、现有 sshd 服务。
2. **安装 OpenSSH Server**：按降级链选择安装方式，识别 `InstallPending` 等待重启状态。
3. **配置 sshd**：补齐/自愈主机密钥，写 `sshd_config`（备份保留最近 3 份），`sshd -t` 语法校验，规范化 ACL/owner。
4. **配置防火墙**：见下节。
5. **配置登录账号**：创建/启用账号，处理 profile，写 `authorized_keys`（含 SYSTEM/Administrators ACL）。
6. **设置默认 Shell 并启动 sshd**：失败时自动收集诊断并重试。
7. **客户端配置**：生成密钥、修正 `.ssh` ACL、配置 `ssh-agent`。
8. **验证与输出**：监听检查、TCP 回环、真实密钥登录自检、主机指纹、IP 与连接命令。

日志：`%TEMP%\setup-ssh-<时间戳>.log`。日志不写入账号密码。

---

## 防火墙说明（v7.6）

Windows 防火墙按 **网络类别（Domain / Private / Public）** 分别生效。一个常见陷阱是：机器上存在一条 `TCP 22 Allow` 规则，但它只对 `Private` 生效，而当前网络被 Windows 判定为 `Public` —— 结果端口被静默丢弃（表现为 ARP 通、ping 和所有端口都超时，容易误判为“机器没开机”）。

v7.6 的判定逻辑：

- 取 `Get-NetConnectionProfile` 的**所有**活动网络类别，规则必须 **全部覆盖**（`Profile=Any` 或位掩码包含所有活动档）。
- 除端口与 Profile 外，还校验规则作用域：`Program`（必须匹配实际 `sshd.exe`）、`Service`（Any / sshd）、`InterfaceType`、`Local/RemoteAddress`、`Authentication`。
- 所有查询使用 `-PolicyStore ActiveStore`，能看到 GPO 下发的 Block 规则和策略；建规则后回读 `ActiveStore` 确认实际生效。
- 命中以下情况会明确报错而不是假装成功：`AllowInboundRules=False`（阻止所有传入连接）、`AllowLocalFirewallRules=False` 且需新建本地规则、存在命中端口的入站 Block 规则（Block 优先于 Allow）。
- 端口过滤器按 `LocalPort` 支持单端口、范围（`8000-8100`）、`Any`、`{80,22}` 等写法。
- 规则统一创建为 `Profile=Any`，以便网络类别变化后仍然可用；**这会在所有网络（含公用网络）放行该端口**，安全要求高的环境请自行收窄。
- 防火墙开启时 **ping 不通是正常现象**（Windows 默认拦截 ICMP），请用 `Test-NetConnection -ComputerName <IP> -Port 22` 或直接 SSH 验证。

---

## 安全建议

1. **立即修改默认口令**：`-AddSshUser` 的默认 `ssh/ssh` 只用于首次连接；建议登录后改密码，随后切换为密钥登录。
2. **优先使用密钥**：脚本会自动生成 `ed25519` 密钥并写入 `authorized_keys`，确认密钥登录可用后，可在 `sshd_config` 中设置 `PasswordAuthentication no`。
3. **限制来源**：若只在局域网使用，可在防火墙规则上增加 `-RemoteAddress LocalSubnet`，或在网络设备上限制 22 端口访问。
4. **不要在公网直接暴露 22**：如确需公网访问，建议改非默认端口 + 防火墙白名单 + 仅密钥登录 + 失败锁定（如 fail2ban / 账号锁定策略）。
5. **备份主机密钥**：`C:\ProgramData\ssh\ssh_host_*` 丢失会导致客户端指纹变化；迁移/重装前请备份。
6. **审计**：脚本日志位于 `%TEMP%`，不包含明文密码；但安装结束的汇总信息会在控制台打印初始口令，请注意屏幕保密。

---

## 常见问题

**`no hostkeys available -- exiting`**
全新系统 `C:\ProgramData\ssh` 下没有主机密钥，而 `sshd -t` 在服务首次启动前执行。v6.1+ 会在校验前主动生成三把默认主机密钥；若仍出现，删除 `C:\ProgramData\ssh\ssh_host_*` 后重跑脚本。

**`UNPROTECTED PRIVATE KEY FILE` / `too open` / 服务 7034**
主机私钥 ACL 或 owner 不符合要求。v7.4+ 会自动修复：断继承、移除非白名单 ACE、授予 `SYSTEM:F` / `Administrators:F`、`/setowner Administrators`。

**客户端 `Connection reset by peer`**
`sshd_config` 中残留 `Match Group administrators` 块（Windows OpenSSH 已知崩溃）。脚本会自动注释；也可手动检查 `C:\ProgramData\ssh\sshd_config`。

**公钥登录 `Permission denied (publickey)`**
`authorized_keys` 或 `.ssh` 目录缺少 `SYSTEM` / `Administrators` 读权限，或账号 profile 漂移到 `C:\Users\<user>.<计算机名>`。脚本已处理并在第 8 步自检；手动修复见自检输出中的 `icacls` 命令。

**防火墙关掉才能连**
先看活动网络类别与 SSH 规则的 Profile 是否匹配：

```powershell
Get-NetConnectionProfile | Select InterfaceAlias,NetworkCategory
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object DisplayName -match 'ssh' |
  ForEach-Object { $_.DisplayName + ' | ' + $_.Profile + ' | ' + ($_ | Get-NetFirewallPortFilter).LocalPort }
```

v7.6 会自动创建 `Profile=Any` 规则；旧版本请手动补建。

**组件一直显示 InstallPending / 0x800f0954**
系统存在待重启的组件操作。重启后重跑，或使用 `-RebootNow` 自动续跑；也可改用 `-PreferOffline`。

**微软账号不能用密码 SSH 登录**
这是预期行为：微软账号（MSA）不适用于 Windows OpenSSH 的密码认证。请使用本地账号或密钥登录。

---

## 已知限制

- 不检测第三方防火墙 / 杀毒软件的 WFP 过滤、IPsec 强制策略；这些情况下脚本可能无法放行端口。
- 非 22 端口安装时，内置的 22 端口规则不会被自动关闭（脚本不修改内置规则）。
- `Profile=Any` 规则作用域较宽，公网环境请自行收紧。
- 脚本只验证本机回环登录，不验证跨主机 / 跨网段连通性。
- Windows Server 版本未做完整矩阵验证；老旧系统（PowerShell < 5.1）不支持。
- 默认口令策略偏弱，生产环境请务必覆盖。

---

## 版本要点

| 版本 | 重点 |
|---|---|
| v7.6 | 防火墙判定按全部活动 Profile / ActiveStore(GPO) / 规则作用域校验；Block 与策略失败不再报成功；端口范围匹配；批量过滤器。 |
| v7.5 | 初步修复“Private-only 规则被误判已放行”。 |
| v7.4 | 主机私钥 ACL/owner 强制规范化，解决 SCM 7034 与公钥失败根因。 |
| v7.3 | 启动失败两级探针（管理员 / SYSTEM），定位 SCM 7034。 |
| v7.2 | 启动失败自动收集 SCM/OpenSSH/崩溃日志；数据目录 ACL 补齐。 |
| v7.1 | 消除注入面；离线负载签名校验；重启续跑参数透传。 |
| v7 | 空口令密钥宿主差异修复；主机密钥自愈；离线安装降级链。 |
| v6 | 专用 SSH 账号；profile 漂移修复；authorized_keys 时序修复。 |
| v5 | 安装位置自适应；真实密钥登录自检。 |
| v4 | authorized_keys ACL、Match 块崩溃规避。 |

---

## 仓库内容

| 文件 | 说明 |
|---|---|
| `setup-ssh.ps1` | 主脚本（v7.6）。 |
| `setup-ssh.bat` | 双击入口，自动提权并转发参数。 |
| `fix-sshd-keys.ps1/.cmd` | 主机密钥 ACL/owner 修复工具（独立版）。 |
| `setup-ssh.sh` | Linux 端安装脚本（多发行版 + 防火墙后端自动选择）。 |
| `创建SSH账号.cmd` | 账号创建辅助入口（等价于 `setup-ssh.bat -AddSshUser`）。 |
| `OpenSSH-Offline-Bundle.zip` | 离线负载，**未纳入仓库**；从 [Releases](https://github.com/Misszyw/setup-ssh/releases) 下载。 |

---

## 免责声明与许可

- 本脚本会修改系统服务、防火墙、账号与密钥配置，请在测试环境验证后再用于生产；使用风险自负。
- 本项目采用 [MIT License](LICENSE)。离线包内的 OpenSSH 二进制遵循其自带的 `LICENSE.txt` / `NOTICE.txt`。
