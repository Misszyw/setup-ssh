#requires -Version 5.1
<#
.SYNOPSIS
    Windows OpenSSH 一键安装与配置（服务端 + 客户端），v7.6 实测修正版。

.DESCRIPTION
    === v7.6 修复（2026-10-20，4 路对抗性审查后的加固；本机只读实测验证）===
    【1】多活动网络必须【全部】覆盖：v7.5 用「任一活动 Profile 命中」判定，双网卡
        （如 Private + Public）时 Private-only 旧规则仍会被误判已放行，原故障复现。
        现按 Profile 位掩码（Domain=1/Private=2/Public=4/Any=0）要求覆盖全部活动档。
    【2】作用域校验：除端口/Profile 外，还校验 Program（须匹配实际 sshd.exe）、
        Service（Any/sshd）、InterfaceType（Any）、LocalAddress/RemoteAddress（Any）、
        Authentication（NotRequired/Any）；避免「22/TCP Allow 但限程序/限网段/IPsec」
        被误判为已覆盖。
    【3】改读 ActiveStore：默认查询是 PersistentStore，看不到 GPO 下发的 Block 规则
        与策略；现在规则/配置查询统一 -PolicyStore ActiveStore，建规则后也回读
        ActiveStore 验证真实生效。
    【4】策略失败不报成功：AllowInboundRules=False（阻止所有传入连接）、
        AllowLocalFirewallRules=False（本地规则被策略禁止）且需新建规则、
        存在命中端口的 Block 规则（Block 优先）→ Write-Err，不再打印「已放行」。
    【5】端口范围/数组匹配：LocalPort 支持 "22"、"8000-8100"、"Any"、"{...}" 形式。
    【6】性能：批量 Get-NetFirewallPortFilter -All 建 InstanceID 哈希（实测 605 条
        ~0.1s），失败时逐条回退；慢速路径先筛 Profile/端口再做作用域检查。
    【7】创建后用 -PassThru 拿到确切规则再回读，避免同名旧规则干扰；
        无活动网络时复用已有 Any 规则，不再每次重跑堆积同名规则。
    【8】AllowInboundRules/AllowLocalFirewallRules 只检查活动网络档，避免噪音。

    === v7.5 修复（2026-10-20，目标机实测：防火墙「已放行」误判导致 22 被拦）===
    【1】判定补上 Profile 覆盖检查：原逻辑只比对 Direction/Action/Enabled/
        Protocol/LocalPort，把一条 Private-only 的旧规则（实测为
        "OpenSSH SSH Server Preview (sshd)"）当成已覆盖；而活动网络是 Public，
        实际 22 被静默丢弃 —— 现象是 ARP 通、ping 和全端口都不通，只能关防火墙。
        现要求规则 Profile=Any 或包含任一活动网络类别（DomainAuthenticated→Domain）。
    【2】慢速路径改为保留规则对象再取端口过滤器（原写法管道后 $_ 只剩过滤器，
        拿不到 Profile）。
    【3】新增生效性检查：AllowInboundRules=False（阻止所有传入连接）告警；
        启用中的入站 Block 规则告警（Windows 防火墙 Block 优先于 Allow）。
    【4】创建后回读校验 Profile/LocalPort/Enabled，并打印活动网络类别。
    【5】活动网络含 Public 时给出提示（规则用 Profile=Any 放行）。

    === v7.4 修复（2026-10-16，本机实证复现：主机密钥 ACL/owner 的"服务必挂"根因）===
    【1】根因（本机 15:44-15:46 用 SYSTEM 身份探针逐步实证）：sshd 对主机私钥的
        UNPROTECTED PRIVATE KEY FILE 检查有两条硬性要求：
        a) ACL 只能含 {SYSTEM, Administrators} —— ssh-keygen 以管理员账号运行会残留
           创建者用户 ACE，服务以 SYSTEM 运行时即属 "others" → "too open"；
        b) 文件 OWNER 也必须是 SYSTEM 或 Administrators —— 实证：ACL 清干净但 owner
           仍是创建者用户时依旧被拒，/setowner 后立即通过。
        管理员跑 sshd -t 时白名单含当前用户所以能过 —— 完整解释「sshd -t 过、
        服务起不来(SCM 7034)」。一切由脚本现场生成主机密钥的机器都会命中此坑
        （此前反复出现的「全新系统经常失败」极可能主要就是它）。
    【2】修复：主机私钥强制规范化 —— 断继承 + 摘掉白名单外全部 ACE（含创建者用户 /
        Users / Authenticated Users）+ 授予 SYSTEM:F 与 Administrators:F +
        /setowner Administrators。达标机器为无操作；第 3 步与第 6 步各幂等执行。

    === v7.3 修复（2026-10-16，目标机实测反馈：SCM 7034「服务意外停止」无声退出）===
    【1】启动失败时新增两级决定性诊断（服务秒退且无事件日志时唯一的信息来源）：
        探针 1：管理员上下文前台运行 `sshd -d -e` 3 秒并捕获输出；
        探针 2：若探针 1 正常，再通过一次性计划任务以 SYSTEM（服务的真实身份）
                运行同一探针，输出到 ProgramData\ssh\probe-system.txt ——
                覆盖「管理员能跑、SYSTEM 跑不了」的权限/上下文类故障。
        两级都正常才判定为服务层拦截（安全软件/策略）；另打印 `sc qc sshd`。
    【2】修 v7.2 引入的瑕疵：Ensure-SshDataAcls 返回值泄漏到控制台（步骤 3/6 出现多余的 0）。

    === v7.2 修复（2026-10-16，目标机实测反馈：sshd 服务启动失败专项）===
    【1】第 6 步启动失败时自动收集诊断：服务控制管理器(SCM)事件、OpenSSH/Operational
        日志、Application 崩溃记录、sshd.log 末尾，并自动重试一次启动；
        RebootPending 时给出「先重启再重跑」的明确提示。此前失败只能靠人工翻事件日志。
    【2】新增 Ensure-SshDataAcls（第 3、6 步调用）：数据目录 / sshd_config / 主机密钥
        对 SYSTEM 与 Administrators 的可读性自动检查并补齐（仅缺时补，幂等）。
        sshd 服务以 SYSTEM 运行；从其它机器拷贝的密钥常缺 SYSTEM ACL ——
        典型症状正是「sshd -t 以管理员身份通过、服务却启动失败」。
    【3】启动前端口占用预检：端口被其它进程占用时点名 PID/进程名（sshd 绑定失败
        同样表现为服务起不来）。

    === v7.1 修复（2026-10-16 对抗性审查后的加固；三路独立审查 + 本机双宿主复现）===
    【1】修复 v7 引入的命令注入/`%` 二次展开面：New-EmptyPassphraseKey 首选路径
        从「cmd.exe /c 拼命令行」改为「Start-Process 直拉 ssh-keygen」（不经 shell）。
        实测复现：cmd 对路径/注释里的 % 会再展开一次（%USERNAME% 等被替换；若某环境
        变量值含 " 与 & 即可越出引号执行命令——审查用 marker 文件双宿主复现成功）。
        Start-Process 只做 CRT 参数解析：% 保持字面、& | ^ 无解析；并拒绝含 " 的
        路径/注释（真实输入不可能出现）。三个写法回退与 cipher 校验保留。
    【2】生成校验升级：每次尝试要求「退出码=0 + 私钥 cipher=none + .pub 已存在」
        三项全过（原实现 .pub 写入失败可被静默吞掉，私钥被锁场景会假报成功）。
    【3】主机密钥自愈扩展：加密的旧式 PEM（Proc-Type: 4,ENCRYPTED / DEK-Info）
        同样被 sshd 拒载，现一并识别并改名重生成；未加密 PEM 仍保守跳过。
    【4】自愈改名加随机后缀（同秒重入撞名时 Rename-Item 会抛错并走到兜底删除）。
    【5】离线负载加固：自动探测到的负载先校验 sshd.exe 的 Microsoft Authenticode
        签名（显式 -PackagePath 视为已人工确认）；注册后复核 sshd 服务、补建
        ssh-agent 服务、成功后清理临时解压目录；sc.exe 改免内嵌引号写法；
        zip 内含多架构时优先 Win64；-PackagePath 无效时明确告警。
    【6】-PreferOffline 不再抢先于「组件已暂存待重启（InstallPending）」的处置。
    【7】-ClientOnly 不再绕过 -Uninstall 的管理员门禁；卸载流程复核删除结果，
        不再无条件打印成功。
    【8】-RebootNow 注册的续跑任务现在原样透传本次参数（原实现只带
        -ResumeAfterReboot，-Port/-AddSshUser 等重启后全部丢失）。
    【9】-AddSshUser 弱口令告警不再把口令明文写进日志文件（审查确认日志会落盘）。
    【10】步骤计数优先级修正：预检/卸载 2 步优先于客户端模式的 4 步判定。

    === v7 修复（2026-10-16，全新系统安装失败专项；在本机 28120 上双宿主实测）===
    【1】修复「空口令」密钥生成的宿主差异 —— v6.1 新增的主机密钥补齐用了
        ssh-keygen -N '""'，该写法在 Windows PowerShell 5.1 下是空口令，
        但在 PowerShell 7 下会把两个引号字符本身当口令、生成 AES 加密的密钥：
        sshd 无法加载主机密钥（sshd -t 报 "no hostkeys available -- exiting"），
        全新系统安装必挂在第 4 步 —— 因为 .bat 走 5.1 所以时灵时不灵。
        用户密钥（第 8 步）同理会生成带口令私钥，ssh-add / 密钥自检全挂。
        另一种写法 -N '' 在 5.1 下同样错（空串被吞、下一个参数 -q 被当成口令）。
        现统一走 New-EmptyPassphraseKey()：生成后解析私钥头部校验，失败自动换
        写法重试（三种写法全败才报错）。
        注：v7.1 修复了该函数首选路径 cmd.exe 拼行带来的 % 二次展开/注入面（见 v7.1【1】）。
    【2】主机密钥自愈：已存在但带口令的主机密钥（旧版正是在 pwsh7 下生成的）
        会被原「存在即跳过」逻辑永远跳过、永远装不好 —— 现在检测到
        cipher≠none 时改名保留（.broken-<时间戳>）并重新生成；正常密钥不动。
    【3】新增本地离线负载降级路径（全新系统常无外网/被墙：WU/DISM 与
        winget/GitHub 全链路都会失败）：脚本目录（或上级目录）放
        OpenSSH-Offline-Bundle.zip / 解出的 payload 目录即可离线完成安装，
        插在 DISM 之后、winget 之前；-PreferOffline 供无网机器直接走离线安装；
        -PackagePath 可显式指定离线包（zip 或目录）。
    【4】用户私钥带口令检测：旧版 pwsh7 下生成的现有 id_ed25519/id_rsa 会被
        检出并给出处置指引（不自动重建 —— 该公钥可能已授权到其它服务器，
        重建会更换身份）。
    【5】GitHub 离线包解压改到唯一临时目录（原实现扫 TEMP 里所有
        OpenSSH-Win64*，可能命中历史残留目录）。
    【6】PS5.1 下对联网路径补 TLS1.2（老系统 .NET 默认协议可能不含 TLS1.2，
        GitHub API / 下载会直接失败）。
    【7】步骤计数修正：正常运行实为 8 步（原显示 x/9）、预检/卸载 2 步、
        客户端模式 4 步。

    === v6 修复（专用 SSH 账号 + 若干稳健性修复）===
    【1】新增 -AddSshUser：一键创建专用 SSH 登录账号（默认 ssh/ssh，自动加入
        Administrators）。幂等：账号已存在则启用 + 重置密码 + 确认管理员成员。
        可用 -SshUserName / -SshUserPassword 覆盖默认值。
    【2】修复 authorized_keys 的两个顺序缺陷（v5 起就存在，都会让第 9 步密钥自检必挂）
        a) 第 4 步写 keys 时账号还没创建（第 6 步才建），$script:UserReady 为空
           → -CreateUser / -AddSshUser 的新账号永远拿不到 authorized_keys；
        b) 密钥对到第 8 步才生成 → 全新机器首次运行，第 4 步公钥还不存在，
           整段写入被静默跳过（老机器有现成密钥所以没暴露）。
        现提取 Add-PublicKeyToUser()：账号创建后立即补写，并在第 8 步密钥就绪后
        为相关用户统一补写（幂等）。
    【3】创建带密码账号后自动检查 sshd_config：若 PasswordAuthentication no
        则改回 yes（原文件备份 .bak-pwauth 并明确警告），否则新账号从设计上就无法登录。
    【4】弱密码被本机密码策略拒绝时，错误信息附带 net accounts 排查与放宽指引。
    【5】防火墙「快速路径」修复顺序依赖：原逻辑只看第一条命中的规则，
        内置规则与自定义规则并存时结果取决于枚举顺序，可能误判或退化到慢速全量比对；
        且仍会枚举全部入站规则。现改为按规则名定向查询（不再全量枚举），
        采用「任一命中规则覆盖当前端口即放行」语义。
    【6】管理员组按 SID S-1-5-32-544 解析，避免非中英文系统组名本地化导致加组失败。
    【7】修复「新账号公钥登录必然失败」的真正根因（2026-10-12 本机实测定位，两轮定位）
        症状：账号/密码登录全正常，唯独公钥报 "Permission denied (publickey)"（密码
        登录不读文件，所以只有密钥路径暴露问题）。真机链条：
          写公钥时预建了 C:\Users\<user> 目录 → 该账号首次 profiling 时 Windows 认为
          该目录不是有效 profile，改用 C:\Users\<user>.<COMPUTERNAME> 注册为【临时
          profile】（注册表 ProfileList\<SID>\ProfileImagePath，实测 Flags=1）→ sshd 的
          home 与 authorized_keys 查找路径都跟随 ProfileImagePath（session 内
          $env:USERPROFILE 实测 = C:\Users\<user>.<COMPUTERNAME>）→ 写在规范路径的
          公钥永远读不到。
        修复（三处配合）：
          a) 账号创建后立即 Initialize-UserProfile（LogonUser+LoadUserProfile）预建
             标准 profile —— 必须赶在任何目录被预建之前，profile 才会落在规范路径；
          b) Add-PublicKeyToUser 按 ProfileImagePath 解析家目录写公钥 —— 历史账号即使
             profile 已被注册到带 <计算机名> 后缀的路径也能正确工作；
          c) 未注册 profile 时双路径兜底写入。
    【8】Add-PublicKeyToUser 内文件写入补 -ErrorAction Stop
        ErrorActionPreference=Continue 下非终止错误会被吞掉、函数假报成功（实测踩到）。
    【9】v6.1: 全新安装「缺主机密钥」死锁修复（2026-10-12 目标机实测踩中）
        全新机器 C:\ProgramData\ssh 下还没有任何主机密钥时，第 4 步的
        sshd -t 语法校验会报 "no hostkeys available -- exiting"（退出 1），
        脚本在校验处直接中止 —— 而主机密钥本应在第 7 步服务首次启动时自动生成，
        「先校验、后起服务」的顺序让首次安装必挂。现于校验前主动补齐
        rsa/ecdsa/ed25519 三把默认主机密钥（幂等，已存在即跳过）。
        注：v7 修正了该补齐流程的空口令写法（见 v7【1】）—— 原 -N '""' 写法
        在 PowerShell 7 下会把密钥加密，反成新的全新安装必挂点。

    === v5 修复（在 v4 可用基础上复核脚本自身逻辑，全部有实测依据）===
    【1】安装位置不再写死 System32\OpenSSH
        新增 Get-SshdExePath()：依次从「服务注册的 ImagePath」→ System32 →
        Program Files\OpenSSH → ProgramData\OpenSSH 解析实际生效的 sshd.exe。
        原逻辑只认 System32，导致：明明装好且服务在跑，脚本仍判定「未安装」，
        重复折腾甚至误报「需要重启」；winget / 离线包装到 Program Files 后
        也用 System32 的路径判成败 → 永远 False。
    【2】安装判定以「磁盘上是否真有可用 sshd.exe」为准，而非 capability 状态
        本机实例：sshd 装在 Program Files 且正常运行，但 capability 因 CBS 卡死
        永远停在 InstallPending，旧逻辑据此误报「需要重启」并拒绝继续。
    【3】新增真实密钥登录自检（步骤 9）—— 全脚本最有价值的一步
        TCP 通不等于能登录。本机曾出现 TCP 全绿、公钥鉴权却全挂（根因是
        authorized_keys 缺 SYSTEM/Administrators 读权限）。有了自检，这类问题
        会在安装当场暴露并直接给出修法，而不是留到用户第一次连接时才炸。
    【4】写完 sshd_config 立刻 sshd -t 校验语法（本机排查时正是靠它定位问题）
    【5】修复 ssh-add 参数错误
        原代码传的是「公钥文件的内容」，而 ssh-add 需要「私钥文件的路径」。
        参数类型都不对且输出被吞，一直静默失败 —— 实测 ssh-add -l 永远为空。
    【6】防火墙检测性能：原写法对每条入站规则都调一次 Get-NetFirewallPortFilter
        （N+1 查询），本机实测耗时 21 秒。改为先按规则名精确匹配，命中即秒回。
    【7】sshd_config 备份只保留最近 3 份，避免反复运行堆满目录。

    === v4 关键修复 ===
    【1】authorized_keys 的 ACL 必须含 SYSTEM + Administrators
        sshd 的鉴权子进程以特权身份读取 authorized_keys，但 Windows 的 SYSTEM
        并不像 Linux root 那样绕过文件 ACL。若 authorized_keys 或 .ssh 目录的 ACL
        只授予用户本人（很多教程的写法），sshd 根本读不到文件，表现为
        "Permission denied (publickey)" —— 即使密钥明明写在文件里。
        正确 ACL：用户本人 + SYSTEM(S-1-5-18) + Administrators(S-1-5-32-544)。
        注意 StrictModes no 无法绕过这一条（它不是常规的 StrictModes 检查）。
    【2】不要用 Match Group administrators 块
        本机实测：只要该块匹配到用户，鉴权子进程立即访问冲突崩溃
        （事件日志 Application Error 1000，异常码 0xc0000005），客户端表现为
        "Connection reset by peer"。OpenSSH 9.5.6.2（OS 组件）与 10.0p2
        （官方独立版）均复现，非构建特有。故统一使用用户级 authorized_keys。
        若检测到旧配置里残留该块，会自动注释掉。
    【3】.ssh 目录 ACL 不能只给用户
        目录只给用户时，特权子进程连目录都无法穿越，同样读不到密钥文件。

    === v2/v3 累积的修复 ===
      1) 账号检测：v1 用 Get-LocalUser 的 PasswordRequired 判断可用账号，
         而微软账号（MSA）该属性恒为 False，v1 会误判「无可用账号」并直接 exit 1。
         现改用 Get-LocalUser 的 Enabled + net user 解析，并支持 -SkipAccount。
      2) 检测 Component Based Servicing RebootPending（存在时 Add-WindowsCapability
         会失败并报 0x800f0954 / 0x800f081f）。
      3) 识别 InstallPending 状态：组件已下载暂存、只差重启落地，不是失败。
      4) 四级安装降级链：Add-WindowsCapability -> DISM -> winget -> GitHub 离线包。
         winget 正确包 ID 是 Microsoft.OpenSSH.Preview（不是 .Beta）；
         GitHub 资产 tag 形如 10.0.0.0p2-Preview，资产名 OpenSSH-Win64.zip。
      5) 修复 SecureString BSTR 内存泄漏（PtrToStringAuto 后未 FreeBSTR）。
      6) 新增 -ClientOnly / -SkipAccount / -Uninstall / -NoKeygen。
      7) 全程写日志到 %TEMP%，失败时保留现场。
      8) 新增 ssh-agent 客户端服务配置与密钥对生成。
      9) 修复 bat 提权时未转发 %* 导致 -RebootNow 等参数被静默丢弃的问题。

.PARAMETER Port
    sshd 监听端口，默认 22。

.PARAMETER EnableAdmin
    启用内置 Administrator 并设置密码。

.PARAMETER CreateUser
    创建本地用户，格式 "用户名" 或 "用户名:密码"。

.PARAMETER AdminUser
    配合 -CreateUser，把新用户加入 Administrators 组。

.PARAMETER AddSshUser
    创建专用 SSH 登录账号（默认 ssh / ssh），启用并加入 Administrators 组。
    可用 -SshUserName / -SshUserPassword 覆盖。与 -SkipAccount 同时使用时后者优先。

.PARAMETER SshUserName
    -AddSshUser 的账号名，默认 ssh。

.PARAMETER SshUserPassword
    -AddSshUser 的密码，默认 ssh。留空则交互输入（非交互模式随机生成）。

.PARAMETER AdminPassword
    -EnableAdmin 时给内置 Administrator 设置的密码；留空则交互输入/随机生成。

.PARAMETER SkipAccount
    跳过账号配置（自建密钥登录或已有可用账号时使用）。

.PARAMETER ClientOnly
    只做客户端配置（生成密钥、ssh-agent），不安装服务端。

.PARAMETER DefaultShell
    PowerShell / Cmd / Keep（默认 Keep）。

.PARAMETER NoFirewall
    跳过防火墙配置。

.PARAMETER NoKeygen
    跳过密钥对生成。

.PARAMETER Preflight
    只读预检，不修改任何东西。

.PARAMETER Uninstall
    停用并删除 sshd 服务与配置。

.PARAMETER RebootNow
    安装处于「已暂存待重启」状态时，注册自动续跑任务并立即重启，
    重启登录后自动继续完成剩余配置。

.PARAMETER ResumeAfterReboot
    内部参数：由 RebootNow 注册的计划任务调用，用于重启后自动续跑。
    一般不需要手动指定。

.PARAMETER PreferOffline
    跳过联网路径（Add-WindowsCapability / DISM），优先用脚本目录里的离线包
    （OpenSSH-Offline-Bundle.zip 或解出的 payload 目录）完成服务端安装。
    无外网/被墙机器建议直接用它。未找到离线包时自动回退常规链路。

.PARAMETER PackagePath
    显式指定离线包路径（zip 或含 sshd.exe 的目录），优先于目录自动探测。

.EXAMPLE
    .\setup-ssh.ps1 -Preflight
    .\setup-ssh.ps1 -Port 2222 -SkipAccount
    .\setup-ssh.ps1 -CreateUser 'dev:P@ssw0rd'
    .\setup-ssh.ps1 -AddSshUser
    .\setup-ssh.ps1 -AddSshUser -SshUserName ops -SshUserPassword 'Ch@ngeMe123'
    .\setup-ssh.ps1 -PreferOffline
    .\setup-ssh.ps1 -PackagePath 'D:\pkg\OpenSSH-Win64.zip'
    .\setup-ssh.ps1 -ClientOnly
    .\setup-ssh.ps1 -RebootNow
    .\setup-ssh.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [int]$Port = 22,
    [switch]$EnableAdmin,
    [string]$AdminPassword = "",
    [string]$CreateUser = "",
    [switch]$AdminUser,
    [switch]$AddSshUser,
    [string]$SshUserName = 'ssh',
    [string]$SshUserPassword = 'ssh',
    [switch]$SkipAccount,
    [switch]$ClientOnly,
    [ValidateSet('PowerShell', 'Cmd', 'Keep')]
    [string]$DefaultShell = 'Keep',
    [switch]$NoFirewall,
    [switch]$NoKeygen,
    [switch]$Preflight,
    [switch]$Uninstall,
    [switch]$RebootNow,
    [switch]$ResumeAfterReboot,
    [switch]$PreferOffline,
    [string]$PackagePath = "",
    [switch]$Help
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
# v7: PS5.1 (.NET Framework) 下 GitHub API/下载要求 TLS1.2，老系统默认协议可能不含
if ($PSVersionTable.PSEdition -ne 'Core') {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
}
# v7.1: 预检/卸载（2 步）优先于客户端模式（4 步）判定
$script:TotalSteps     = if ($Preflight -or $Uninstall) { 2 } elseif ($ClientOnly) { 4 } else { 8 }
$script:StepNum        = 0
$script:StepTimer      = $null
$script:LogPath        = Join-Path $env:TEMP ("setup-ssh-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Write-Step { param($m) Write-Host "[*] $m" -ForegroundColor Cyan; Log $m }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green; Log $m }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow; Log "WARN: $m" }
function Write-Err  { param($m) Write-Host "[x] $m" -ForegroundColor Red;   Log "ERROR: $m" }
function Log {
    param($m)
    try { Add-Content -LiteralPath $script:LogPath -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) -Encoding UTF8 } catch { }
}

# v5: 解析「当前实际生效的 sshd.exe 路径」。
# 不要写死 System32\OpenSSH —— 官方独立版与 winget 都装在 Program Files\OpenSSH，
# 早期手工部署可能落在 ProgramData\OpenSSH。只认 System32 会导致：
#   1) 明明装好且服务在跑，脚本却判定「未安装」，重复折腾甚至误报「需要重启」
#   2) winget / 离线包装到 Program Files 后，用 System32 的路径去判断成败 → 永远 False
function Get-SshdExePath {
    $cands = @()
    # 1) 以服务注册的 ImagePath 为准（最权威）：剥掉引号与后面的启动参数
    $reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -ErrorAction SilentlyContinue
    if ($reg -and $reg.ImagePath) {
        $p = $reg.ImagePath.Trim()
        if ($p -match '^\s*"([^"]+)"') { $p = $Matches[1] }
        elseif ($p -match '(\S+\.exe)') { $p = $Matches[1] }
        if ($p) { $cands += ($p -replace '/', '\') }
    }
    # 2) 常见安装位置
    $cands += (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe')
    $cands += 'C:\Program Files\OpenSSH\sshd.exe'
    $cands += (Join-Path $env:ProgramData 'OpenSSH\sshd.exe')

    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

# v7.6: 防火墙「有效覆盖」判定（v7.5 基础上按 4 路对抗性审查加固）
# 三类盲区：① 多活动网络只要求「任一」命中（Private+Public 时原 bug 复现）；
# ② 只看端口/Profile，忽略 Program/Service/RemoteAddress/Authentication 作用域；
# ③ 默认查 PersistentStore，看不到 GPO 下发的 Block/策略。
# Profile 位掩码：Domain=1 / Private=2 / Public=4 / Any=0（[int]$Rule.Profile）。
function Get-FirewallProfileBit {
    param([string]$Name)
    $m = @{ 'Domain' = 1; 'Private' = 2; 'Public' = 4 }
    if ($m.ContainsKey($Name)) { return $m[$Name] }
    return 0
}

function Get-EffectiveFirewallProfile {
    $map = @{ 'DomainAuthenticated' = 'Domain'; 'Private' = 'Private'; 'Public' = 'Public' }
    return @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
             ForEach-Object { $map[[string]$_.NetworkCategory] } |
             Where-Object { $_ } | Sort-Object -Unique)
}

function Test-FirewallRuleCoversProfiles {
    param($Rule, [string[]]$ActiveProfiles)
    if (-not $Rule) { return $false }
    $ruleBits = [int]$Rule.Profile
    if ($ruleBits -eq 0) { return $true }
    if (-not $ActiveProfiles -or $ActiveProfiles.Count -eq 0) { return $false }
    $activeBits = 0
    foreach ($a in $ActiveProfiles) { $activeBits = $activeBits -bor (Get-FirewallProfileBit $a) }
    if ($activeBits -eq 0) { return $false }
    # v7.6: 必须覆盖全部活动档；只覆盖部分（如仅 Private）不算
    return (($ruleBits -band $activeBits) -eq $activeBits)
}

function Test-FirewallPortInFilter {
    param($LocalPort, [int]$Port)
    foreach ($raw in @($LocalPort)) {
        $s = ([string]$raw).Trim().Trim('{', '}', '"')
        foreach ($tok in ($s -split ',')) {
            $t = $tok.Trim()
            if ($t -eq 'Any') { return $true }
            if ($t -match '^(\d+)$' -and [int]$Matches[1] -eq $Port) { return $true }
            if ($t -match '^(\d+)\s*-\s*(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        }
    }
    return $false
}

function Get-FirewallPortFilterMap {
    # 批量取端口过滤器（避免逐规则 N+1 查询）；非管理员/失败时返回 $null 走逐条回退
    try {
        $map = @{}
        foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction Stop)) { $map[$f.InstanceID] = $f }
        return $map
    } catch { return $null }
}

function Get-RulePortFilter {
    param($Rule, $PortFilterMap)
    if ($PortFilterMap -and $PortFilterMap.ContainsKey($Rule.InstanceID)) { return $PortFilterMap[$Rule.InstanceID] }
    return ($Rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
}

function Test-FirewallRuleUnrestricted {
    param($Rule, [string]$SshdExe)
    $app = $Rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    if ($app -and $app.Program -and $app.Program -ne 'Any') {
        $p = [Environment]::ExpandEnvironmentVariables([string]$app.Program)
        if (-not $SshdExe -or ($p.Trim() -ne $SshdExe.Trim())) { return $false }
    }
    $svc = $Rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
    if ($svc -and $svc.Service -and $svc.Service -ne 'Any' -and $svc.Service -ne 'sshd') { return $false }
    $it = $Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction SilentlyContinue
    if ($it -and $it.InterfaceType -and $it.InterfaceType -ne 'Any') { return $false }
    $af = $Rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    if ($af) {
        if ($af.LocalAddress  -and -not (@($af.LocalAddress)  -contains 'Any')) { return $false }
        if ($af.RemoteAddress -and -not (@($af.RemoteAddress) -contains 'Any')) { return $false }
    }
    $sf = $Rule | Get-NetFirewallSecurityFilter -ErrorAction SilentlyContinue
    if ($sf -and $sf.Authentication -and $sf.Authentication -notin @('NotRequired', 'Any')) { return $false }
    return $true
}

function Get-BlockingFirewallRule {
    param([int]$Port, [string[]]$ActiveProfiles, $PortFilterMap)
    return @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
             ForEach-Object {
                 $r = $_
                 if (-not (Test-FirewallRuleCoversProfiles -Rule $r -ActiveProfiles $ActiveProfiles)) { return }
                 $pf = Get-RulePortFilter -Rule $r -PortFilterMap $PortFilterMap
                 if ($pf -and @('TCP', 'Any') -contains $pf.Protocol -and
                     (Test-FirewallPortInFilter -LocalPort $pf.LocalPort -Port $Port)) { $r }
             })
}

# v5: sshd_config 备份保留最近 N 份，避免反复运行把目录堆满
function Remove-OldBackup {
    param([string]$BasePath, [int]$Keep = 3)
    try {
        $old = @(Get-ChildItem (Split-Path $BasePath) -Filter ((Split-Path $BasePath -Leaf) + '.bak-*') -ErrorAction SilentlyContinue |
                 Sort-Object Name -Descending | Select-Object -Skip $Keep)
        foreach ($f in $old) { Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue }
    } catch { }
}

# v7: 解析可用的 ssh-keygen.exe（优先系统内置，退 PATH）
function Get-SshKeygenPath {
    $c = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
    if (Test-Path -LiteralPath $c) { return $c }
    $cmd = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return 'ssh-keygen.exe'
}

# v7: 读取 OpenSSH 私钥头部 cipher 字段；'none' = 无口令，其余（如 aes256-ctr）= 带口令。
# 非 OPENSSH 新格式（PEM 等）或解析失败返回 $null —— 调用方应保守处理。
function Get-PrivateKeyCipher {
    param([string]$Path)
    try {
        $txt = [IO.File]::ReadAllText($Path)
        $m = [regex]::Match($txt, '(?s)-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----')
        if (-not $m.Success) { return $null }
        $b = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
        if ($b.Length -lt 24) { return $null }
        $len = [System.BitConverter]::ToUInt32(@($b[18], $b[17], $b[16], $b[15]), 0)
        if ($len -lt 1 -or ($len + 19) -gt $b.Length) { return $null }
        return [Text.Encoding]::ASCII.GetString($b, 19, $len)
    } catch { return $null }
}

# v7.1: 识别「加密的旧式 PEM 私钥」（Proc-Type: 4,ENCRYPTED / DEK-Info 头）。
# sshd 同样加载不了这类密钥，但它不是 OPENSSH 新格式、Get-PrivateKeyCipher 返回 $null；
# 未加密 PEM 返回 $false（可正常加载，应保守跳过不动）。
function Test-PrivateKeyEncryptedPem {
    param([string]$Path)
    try {
        $head = (Get-Content -LiteralPath $Path -TotalCount 40 -ErrorAction Stop) -join "`n"
        return [bool]($head -match '(?m)^Proc-Type:\s*4,ENCRYPTED' -or $head -match '(?m)^DEK-Info:')
    } catch { return $false }
}

# v7.2: 确保 sshd 数据目录 / sshd_config / 主机密钥的 SYSTEM 可读性。
# v7.4: 主机私钥升级为「强制规范化」——见文件头 v7.4【1】：
#   sshd 对私钥有 UNPROTECTED PRIVATE KEY FILE 检查，两条硬性要求（本机 15:44/15:46 实证）：
#   a) ACL 只能含 {SYSTEM, Administrators}（创建者用户/Users/Authenticated Users 等
#      任何白名单外条目 → "too open"；管理员跑 sshd -t 时白名单含当前用户所以能过）；
#   b) 文件 OWNER 也必须是 SYSTEM 或 Administrators（本机实证：ACL 干净但 owner 为
#      创建者用户时仍被拒；/setowner 后立即通过）。
#   修复：断继承 + 摘掉白名单外全部 ACE + 授予 SYSTEM:F/Administrators:F + /setowner Administrators。
#   健康机器（已达标）为无操作；幂等。返回补齐/规范化的文件数。
function Ensure-SshDataAcls {
    param([string]$DataDir, [string]$CfgPath)
    $fixed = @()
    $keep = @('S-1-5-18', 'S-1-5-32-544')   # SYSTEM / Administrators

    if ($DataDir -and (Test-Path -LiteralPath $DataDir)) {
        foreach ($kf in @(Get-ChildItem -LiteralPath $DataDir -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })) {
            try {
                $needFix = $false
                $have = @{}
                $aclObj = Get-Acl -LiteralPath $kf
                try {
                    $ownerSid = $aclObj.GetOwner([Security.Principal.SecurityIdentifier]).Value
                    if ($ownerSid -and ($keep -notcontains $ownerSid)) { $needFix = $true }
                } catch { }
                foreach ($ace in @($aclObj.Access)) {
                    try {
                        $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                        if ($ace.AccessControlType -eq 'Allow') { $have[$sid] = $true }
                        if ($keep -notcontains $sid -or $ace.AccessControlType -ne 'Allow') { $needFix = $true }
                    } catch { $needFix = $true }
                }
                if (-not ($have['S-1-5-18'] -and $have['S-1-5-32-544'])) { $needFix = $true }
                if ($needFix) {
                    & icacls.exe $kf /inheritance:r 2>&1 | Out-Null
                    foreach ($ace in @((Get-Acl -LiteralPath $kf).Access)) {
                        try {
                            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                            if ($keep -notcontains $sid -or $ace.AccessControlType -ne 'Allow') { & icacls.exe $kf /remove:g "*$sid" 2>&1 | Out-Null }
                        } catch { }
                    }
                    & icacls.exe $kf /grant '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1 | Out-Null
                    & icacls.exe $kf /setowner '*S-1-5-32-544' 2>&1 | Out-Null
                    $fixed += $kf
                }
            } catch { }
        }
    }

    # 数据目录 / sshd_config：SYSTEM 可读即可（缺才补，不收紧）
    $targets2 = @()
    if ($DataDir -and (Test-Path -LiteralPath $DataDir)) { $targets2 += $DataDir }
    if ($CfgPath -and (Test-Path -LiteralPath $CfgPath)) { $targets2 += $CfgPath }
    foreach ($t in $targets2) {
        try {
            $isDir = (Get-Item -LiteralPath $t).PSIsContainer
            $hasSystem = $false
            foreach ($ace in @((Get-Acl -LiteralPath $t).Access)) {
                try {
                    if ($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-18') { $hasSystem = $true; break }
                } catch { }
            }
            if (-not $hasSystem) {
                if ($isDir) { & icacls.exe $t /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null }
                else        { & icacls.exe $t /grant '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1 | Out-Null }
                $fixed += $t
            }
        } catch { }
    }
    if ($fixed.Count) { Write-Warn ("已规范化 sshd 密钥/配置 ACL（主机私钥 = 仅 SYSTEM + Administrators）: " + ($fixed -join '; ')) }
    return $fixed.Count
}

# v7: 生成「空口令」密钥对，跨 Windows PowerShell 5.1 / PowerShell 7 一致 —— 见文件头 v7【1】。
# 宿主差异实测矩阵（2026-10-16 本机）:
#   & exe -N '""'            → PS5.1: 空口令 ✓ / pwsh7: 把 "" 两字符当口令 → aes256-ctr ✗
#   & exe -N ''              → pwsh7: 空口令 ✓ / PS5.1: 空串被吞、-q 被当成口令 ✗
# v7.1: 首选路径为 Start-Process 直拉（不经 shell；实测两宿主 cipher=none，% 保持字面）。
#   审查实测原 cmd.exe /c 拼行写法会把路径/注释里的 % 再展开一次（%USERNAME% 被替换、
#   可被环境变量值里的 " 与 & 越出引号执行命令）——已弃用 shell 路线。
# 三种写法依次尝试；每次生成后要求「退出码 0 + 私钥 cipher=none + .pub 已存在」三项全过，
# 失败清掉重试；全败返回 $false。
function New-EmptyPassphraseKey {
    param(
        [Parameter(Mandatory)][string]$KeyType,
        [Parameter(Mandatory)][string]$KeyPath,
        [int]$Bits = 0,
        [string]$Comment = ''
    )
    # 真实路径/注释不可能含双引号；含则拒绝（防止参数字符串被越出）
    if ($KeyPath -match '"' -or $Comment -match '"') { return $false }
    $exe = Get-SshKeygenPath
    $q = '"'
    $verify = {
        param([int]$ExitCode)
        if ($ExitCode -ne 0) { return $false }
        if (-not (Test-Path -LiteralPath $KeyPath)) { return $false }
        if (-not (Test-Path -LiteralPath "$KeyPath.pub")) { return $false }
        return ((Get-PrivateKeyCipher $KeyPath) -eq 'none')
    }
    $clear = {
        foreach ($f in @($KeyPath, "$KeyPath.pub")) {
            if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
    }

    # 策略 1（首选）: Start-Process 直拉（不经 shell，无 %/元字符展开）
    & $clear
    $argStr = (@('-q', '-t', $KeyType) + $(if ($Bits -gt 0) { @('-b', "$Bits") } else { @() }) +
                @('-f', ($q + $KeyPath + $q), '-N', ($q + $q)) +
                $(if ($Comment) { @('-C', ($q + $Comment + $q)) } else { @() })) -join ' '
    $p = Start-Process -FilePath $exe -ArgumentList $argStr -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
    if ($p -and (& $verify ([int]$p.ExitCode))) { return $true }

    # 策略 2: PS 原生 -N '""'（Windows PowerShell 5.1 语义）
    & $clear
    $a = @('-q', '-t', $KeyType); if ($Bits -gt 0) { $a += @('-b', "$Bits") }
    $a += @('-f', $KeyPath, '-N', '""'); if ($Comment) { $a += @('-C', $Comment) }
    & $exe @a 2>&1 | Out-Null
    if (& $verify ([int]$LASTEXITCODE)) { return $true }

    # 策略 3: PS 原生 -N ''（PowerShell 7 语义）
    & $clear
    $a = @('-q', '-t', $KeyType); if ($Bits -gt 0) { $a += @('-b', "$Bits") }
    $a += @('-f', $KeyPath, '-N', ''); if ($Comment) { $a += @('-C', $Comment) }
    & $exe @a 2>&1 | Out-Null
    return (& $verify ([int]$LASTEXITCODE))
}

# v7: 解析本地离线负载目录（含 sshd.exe）。候选：显式 -PackagePath（zip 或目录）→
# 脚本目录下的常见布局（bundle zip / 解出的 payload / Win64 zip）→ 上级目录的 bundle zip。
# 全新系统常无外网或被墙：有离线负载即可不依赖 WU / winget / GitHub 完成安装。
function Resolve-OfflinePayload {
    param([string]$ExplicitPath = "")
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $cands = @(
        (Join-Path $here 'OpenSSH-Offline-Bundle'),
        (Join-Path $here 'payload'),
        (Join-Path $here 'OpenSSH-Win64')
    )
    $zips = @(
        (Join-Path $here 'OpenSSH-Offline-Bundle.zip'),
        (Join-Path $here 'OpenSSH-Win64.zip'),
        (Join-Path (Split-Path $here -Parent) 'OpenSSH-Offline-Bundle.zip')
    )
    if ($ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath -PathType Container) { $cands = @($ExplicitPath) + $cands }
        else { $zips = @($ExplicitPath) + $zips }
    }
    $result = $null
    foreach ($c in $cands) {
        if (-not $c) { continue }
        foreach ($sub in @('', 'payload')) {
            $d = if ($sub) { Join-Path $c $sub } else { $c }
            if (Test-Path -LiteralPath (Join-Path $d 'sshd.exe')) { $result = $d; break }
        }
        if ($result) { break }
    }
    if (-not $result) {
        foreach ($z in $zips) {
            if (-not $z -or -not (Test-Path -LiteralPath $z -PathType Leaf)) { continue }
            try {
                $ex = Join-Path $env:TEMP ('openssh-payload-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
                Expand-Archive -LiteralPath $z -DestinationPath $ex -Force -ErrorAction Stop
                Log "offline payload extracted: $z -> $ex"
                # v7.1: 含多架构时优先 Win64（原「递归取第一个」可能选中 Win32）
                $hits = @(Get-ChildItem -LiteralPath $ex -Recurse -Filter 'sshd.exe' -File -ErrorAction SilentlyContinue)
                if ($hits.Count -gt 0) {
                    $best = @($hits | Where-Object { $_.FullName -match 'Win64' -and $_.FullName -notmatch 'Win32' } | Select-Object -First 1)
                    if (-not $best.Count) { $best = @($hits | Select-Object -First 1) }
                    $result = $best[0].DirectoryName; break
                }
            } catch { Log "offline payload extract failed: $z : $($_.Exception.Message)" }
        }
    }
    if ($result) { Log "offline payload resolved: $result" }
    # v7.1: 显式指定的路径不可用时明确告警（不再静默改用其它候选）
    elseif ($ExplicitPath) { Write-Warn "指定的离线包不可用（zip 或含 sshd.exe 的目录）: $ExplicitPath" }
    return $result
}

# v7: 从离线负载安装 OpenSSH Server（复制到 System32\OpenSSH，与系统内置布局一致）。
# v7.1: 默认校验负载内 sshd.exe 的 Microsoft Authenticode 签名（-TrustPayload 跳过，
#       显式 -PackagePath 视为已人工确认）；注册后复核服务（防"复制成功但服务没注册"
#       的假成功）；补建 ssh-agent 服务；sc.exe 改免内嵌引号写法（pwsh7 会把引号转义成
#       字面 \" 传参）；成功后清理临时解压目录。返回 sshd.exe 路径，失败返回 $null。
function Install-FromPayload {
    param([string]$PayloadDir, [switch]$TrustPayload)
    if (-not $PayloadDir -or -not (Test-Path -LiteralPath (Join-Path $PayloadDir 'sshd.exe'))) { return $null }
    if (-not $TrustPayload) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $PayloadDir 'sshd.exe') -ErrorAction Stop
            if ($sig.Status -ne 'Valid' -or -not ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'Microsoft')) {
                Write-Warn "离线负载未通过 Microsoft 签名校验（$($sig.Status)），已拒绝自动使用；如确认来源可信请用 -PackagePath 显式指定"
                return $null
            }
        } catch {
            Write-Warn "离线负载签名校验失败（$($_.Exception.Message)），已拒绝自动使用"
            return $null
        }
    }
    try {
        $dst = Join-Path $env:WINDIR 'System32\OpenSSH'
        $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service sshd -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 400 }
        if (-not (Test-Path -LiteralPath $dst)) { New-Item -ItemType Directory -Force -Path $dst | Out-Null }
        Copy-Item -Path (Join-Path $PayloadDir '*') -Destination $dst -Recurse -Force -ErrorAction Stop
        $sshdFull = Join-Path $dst 'sshd.exe'
        $setupScript = Join-Path $dst 'install-sshd.ps1'
        if (Test-Path -LiteralPath $setupScript) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript 2>&1 | Out-Null
            Log "payload: ran install-sshd.ps1 (exit=$LASTEXITCODE)"
        } else {
            & sc.exe create sshd binPath= $sshdFull start= auto DisplayName= 'OpenSSH SSH Server' obj= LocalSystem 2>&1 | Out-Null
            Log "payload: sc create sshd (exit=$LASTEXITCODE)"
        }
        # v7.1: 复核服务（失败时第 6 步会再兜底重试，但这里必须可见）
        if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
            Write-Warn "sshd 服务未注册成功（binPath=$sshdFull），后续步骤将重试"
        }
        # v7.1: 离线新装补齐 ssh-agent 服务（能力/官方包路径通常会带，本路径需要自己建）
        $agentExe = Join-Path $dst 'ssh-agent.exe'
        if ((Test-Path -LiteralPath $agentExe) -and -not (Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            & sc.exe create ssh-agent binPath= $agentExe start= demand DisplayName= 'OpenSSH Authentication Agent' obj= LocalSystem 2>&1 | Out-Null
            Log "payload: sc create ssh-agent (exit=$LASTEXITCODE)"
        }
        # v7.1: 临时解压目录只服务于本次安装，完成后清理
        if ($PayloadDir -like (Join-Path $env:TEMP 'openssh-payload-*')) {
            Remove-Item -LiteralPath $PayloadDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        return (Get-SshdExePath)
    } catch {
        Log "Install-FromPayload failed: $($_.Exception.Message)"
        return $null
    }
}

# v6: 解析「sshd 实际会使用的家目录」（2026-10-12 真机定位的关键修复）。
# sshd 的 home 与 authorized_keys 查找路径都跟随注册表 ProfileList\<SID>\ProfileImagePath：
#   - 正常账号 → C:\Users\<user>；
#   - 目录被预建过的账号 → Windows 改用 C:\Users\<user>.<COMPUTERNAME> 注册（实测，
#     且可能被标记为临时 profile）。所以不能写死 C:\Users\<user>，必须按
#     ProfileImagePath 写 authorized_keys。
# 未注册 profile 时 sshd 行为不可靠，返回两个候选路径做兜底。
function Get-SshHomeDirs {
    param([string]$UserName)
    $real = Join-Path 'C:\Users' $UserName
    $sid  = $null
    try { $sid = (Get-LocalUser -Name $UserName -ErrorAction Stop).SID.Value } catch { }
    if ($sid) {
        $pip = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue).ProfileImagePath
        if ($pip) { return @($pip) }
    }
    return @((Join-Path 'C:\Users' "$UserName.$env:COMPUTERNAME"), $real)
}

# v6: 预建标准用户 profile。关键背景见 v6【7】：若先预建了 C:\Users\<user> 目录、
# 再让 Windows 去 profiling，Windows 会改注册 <user>.<COMPUTERNAME> 临时 profile，
# 导致 sshd 家目录漂移、公钥登录失败。所以必须「先建 profile，后写任何文件」。
# 已注册则直接返回；注册在非常规路径时给出告警（历史账号）。
$script:ProfileHelperSrc = @'
using System;
using System.Runtime.InteropServices;

public static class WinUserProfileNative
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROFILEINFO
    {
        public int dwSize;
        public int dwFlags;
        public string lpUserName;
        public string lpProfilePath;
        public string lpDefaultPath;
        public string lpServerName;
        public string lpPolicyPath;
        public IntPtr hProfile;
    }

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LoadUserProfile(IntPtr token, ref PROFILEINFO profileInfo);

    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool UnloadUserProfile(IntPtr token, IntPtr profile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

function Initialize-UserProfile {
    param([string]$UserName, [string]$PlainPassword)
    if (-not $UserName) { return $false }
    $sid = $null
    try { $sid = (Get-LocalUser -Name $UserName -ErrorAction Stop).SID.Value } catch { return $false }
    $regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (Test-Path -LiteralPath $regKey) {
        $pip = (Get-ItemProperty -LiteralPath $regKey -ErrorAction SilentlyContinue).ProfileImagePath
        if ($pip) {
            if ($pip -ne (Join-Path 'C:\Users' $UserName)) {
                Write-Warn "账号 $UserName 的 profile 注册在非常规路径: $pip（常见原因：目录曾被预建）。公钥将按该路径写入。"
            }
            Log "profile already registered for $UserName -> $pip"
            return $true
        }
    }
    if (-not $PlainPassword) { return $false }
    try {
        if (-not ('WinUserProfileNative' -as [type])) {
            Add-Type -TypeDefinition $script:ProfileHelperSrc -ErrorAction Stop
        }
        $hTok = [IntPtr]::Zero
        # 2 = LOGON32_LOGON_INTERACTIVE（本机账号默认有"允许本地登录"权限）
        if (-not [WinUserProfileNative]::LogonUser($UserName, '.', $PlainPassword, 2, 0, [ref]$hTok)) {
            Log "LogonUser($UserName) failed: win32err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            return $false
        }
        try {
            $pi = [WinUserProfileNative+PROFILEINFO]::new()
            $pi.dwSize = [Runtime.InteropServices.Marshal]::SizeOf([type]'WinUserProfileNative+PROFILEINFO')
            $pi.dwFlags = 1   # PI_NOUI
            $pi.lpUserName = $UserName
            if ([WinUserProfileNative]::LoadUserProfile($hTok, [ref]$pi) -and $pi.hProfile -ne [IntPtr]::Zero) {
                [WinUserProfileNative]::UnloadUserProfile($hTok, $pi.hProfile) | Out-Null
                # v6: LoadUserProfile 可能"假成功"——若该 SID 存在残留的已加载 hive，
                # 它会直接复用、不写 ProfileList 注册（2026-10-12 实测），必须回读校验
                $pip = (Get-ItemProperty -LiteralPath $regKey -ErrorAction SilentlyContinue).ProfileImagePath
                Log "profile materialized for $UserName -> $pip"
                if (-not $pip) {
                    Write-Warn "账号 $UserName 的 profile 注册未落盘（疑似存在残留 hive/临时 profile，建议重启后重跑本脚本）"
                    return $false
                }
                return $true
            }
            Log "LoadUserProfile($UserName) failed: win32err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            return $false
        } finally { [WinUserProfileNative]::CloseHandle($hTok) | Out-Null }
    } catch {
        Log "Initialize-UserProfile($UserName) exception: $($_.Exception.Message)"
        return $false
    }
}

# v6: 把「公钥写入某用户的 authorized_keys + 修 ACL」提取为函数。
# 原实现是内联的，且只覆盖当前用户：账号要到第 6 步才创建，第 4 步写密钥时
# $script:UserReady 还没赋值，于是 -CreateUser / -AddSshUser 场景下新账号的
# authorized_keys 永远写不上，第 9 步密钥登录自检必然失败。
# 返回：写成功的 authorized_keys 路径数组（失败为空数组）。
function Add-PublicKeyToUser {
    param([string]$UserName)
    if (-not $UserName) { return @() }
    $pub = Join-Path $script:SshDir 'id_ed25519.pub'
    if (-not (Test-Path -LiteralPath $pub)) { return @() }
    $pubLine = (Get-Content -LiteralPath $pub -Raw).Trim()
    if (-not $pubLine) { return @() }
    $domUser = "$env:COMPUTERNAME\$UserName"
    $written = @()
    foreach ($homeDir in @(Get-SshHomeDirs -UserName $UserName)) {
        $sshD     = Join-Path $homeDir '.ssh'
        $userKeys = Join-Path $sshD 'authorized_keys'
        try {
            # v6: 必须带 -ErrorAction Stop —— 全局 ErrorActionPreference=Continue 下，
            # 非终止错误会被静默吞掉、函数假报成功（实测踩到，误导排查）
            if (-not (Test-Path -LiteralPath $sshD)) { New-Item -ItemType Directory -Force -Path $sshD -ErrorAction Stop | Out-Null }
            $existing = if (Test-Path -LiteralPath $userKeys) { Get-Content -LiteralPath $userKeys -Raw } else { '' }
            if ($existing -notmatch [regex]::Escape($pubLine)) {
                Add-Content -LiteralPath $userKeys -Value $pubLine -Encoding ascii -ErrorAction Stop
            }
            # .ssh 目录与 authorized_keys 必须含 SYSTEM + Administrators 读权限（见 v4 修复说明）
            & icacls.exe $sshD /inheritance:r 2>&1 | Out-Null
            & icacls.exe $sshD /grant:r "${domUser}:(OI)(CI)F" 2>&1 | Out-Null
            & icacls.exe $sshD /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
            & icacls.exe $userKeys /inheritance:r 2>&1 | Out-Null
            & icacls.exe $userKeys /grant:r "${domUser}:F" 2>&1 | Out-Null
            & icacls.exe $userKeys /grant '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1 | Out-Null
            $written += $userKeys
        } catch {
            Log "Add-PublicKeyToUser($UserName) -> $sshD failed: $($_.Exception.Message)"
        }
    }
    if ($written.Count) { Log "Add-PublicKeyToUser($UserName) wrote: $($written -join '; ')" }
    return $written
}

# v6: 按 SID 解析管理员组名，避免系统组名本地化差异
function Get-AdminGroupName {
    try {
        $g = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        if ($g -and $g.Name) { return $g.Name }
    } catch { }
    return 'Administrators'
}

# v6: 幂等地确保用户属于管理员组；返回 'added' / 'already' / $null（失败）
function Add-UserToAdminGroup {
    param([string]$UserName)
    try {
        $member   = "$env:COMPUTERNAME\$UserName"
        $isMember = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -ieq $member -or $_.Name -ieq $UserName }).Count -gt 0
        if ($isMember) { return 'already' }
        Add-LocalGroupMember -Group (Get-AdminGroupName) -Member $UserName -ErrorAction Stop
        return 'added'
    } catch {
        Log "Add-UserToAdminGroup($UserName) failed: $($_.Exception.Message)"
        return $null
    }
}

function Show-Step {
    param([string]$Title, [string]$Hint = "", [string]$Expect = "")
    $script:StepNum++
    $script:StepTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkGray
    Write-Host ("  步骤 {0}/{1}: {2}" -f $script:StepNum, $script:TotalSteps, $Title) -ForegroundColor Magenta
    if ($Expect) { Write-Host "    预计: $Expect" -ForegroundColor DarkGray }
    if ($Hint)   { Write-Host "    说明: $Hint" -ForegroundColor DarkGray }
}
function End-Step {
    if ($script:StepTimer) {
        $script:StepTimer.Stop()
        Write-Host ("    耗时: {0:N1} 秒" -f $script:StepTimer.Elapsed.TotalSeconds) -ForegroundColor DarkGray
        $script:StepTimer = $null
    }
}
function Show-Progress2 {
    param([string]$Activity, [string]$Status)
    if (-not $script:Interactive) { return }
    Write-Progress -Activity $Activity -Status $Status -PercentComplete -1
}
function Stop-Progress2 {
    param([string]$Activity = "任务")
    if (-not $script:Interactive) { return }
    Write-Progress -Activity $Activity -Status "完成" -Completed
}

# v3: 注册「重启后自动续跑」计划任务（登录时以最高权限运行）
# v7.1: 新增 -ExtraArgs，把本次显式参数原样透传给续跑（否则 -Port / -AddSshUser 等丢失）
function Register-AutoResume {
    param([string]$ScriptPath, [string]$ExtraArgs = "")
    $taskName = 'SetupSSH-AutoResume'
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        # 用 WindowsIdentity 取全限定名，对微软账号（MSA）比 $env:USERDOMAIN\$env:USERNAME 可靠
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResumeAfterReboot"
        if ($ExtraArgs) { $arg += " $ExtraArgs" }
        $action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arg
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $me
        $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null
        Log "auto-resume task registered: $taskName (user=$me)"
        return $true
    } catch {
        Log "register auto-resume failed: $($_.Exception.Message)"
        return $false
    }
}

if ($Help) { Get-Help $PSCommandPath -Detailed; exit 0 }

if ($Port -lt 1 -or $Port -gt 65535) { Write-Err "无效端口: $Port"; exit 2 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# v3: 重启后续跑模式 —— 先无条件清理计划任务（必须在权限判断之前，避免残留任务）
$script:IsResumeRun = [bool]$ResumeAfterReboot
if ($script:IsResumeRun) {
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "  重启后自动续跑模式（ResumeAfterReboot）" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    try {
        Unregister-ScheduledTask -TaskName 'SetupSSH-AutoResume' -Confirm:$false -ErrorAction SilentlyContinue
        Log "auto-resume task removed"
    } catch { }
    # 给系统服务与文件落地留出初始化时间
    Start-Sleep -Seconds 8
    if (-not $isAdmin) {
        Write-Warn "续跑任务未获得管理员权限，后续步骤可能失败。请手动以管理员身份重新运行。"
    }
}

# 客户端步骤不需要管理员；服务端安装与卸载（-Uninstall）需要
# v7.1: -ClientOnly 不再放行 -Uninstall（卸载必须管理员）
if (-not $isAdmin -and -not $Preflight -and ($Uninstall -or -not $ClientOnly)) {
    Write-Err "服务端安装需要管理员权限。"
    Write-Err "请右键 setup-ssh.bat -> 以管理员身份运行，或执行："
    Write-Err '  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \"' + $PSCommandPath + '\""'
    exit 1
}

$script:Interactive    = $Host.Name -eq 'ConsoleHost' -and -not [Console]::IsInputRedirected
$script:RandomPassword = ""
$script:AdminReady     = $false
$script:UserReady      = ""
$script:SshDir         = Join-Path $env:USERPROFILE '.ssh'
$script:CfgPath        = Join-Path $env:ProgramData 'ssh\sshd_config'
$script:NeedsRebootForStaged = $false

# v7.1: 记录本次显式传入的参数，供 -RebootNow 注册的续跑任务原样透传
# （原实现只带 -ResumeAfterReboot，-Port / -AddSshUser 等在重启后全部丢失）
$script:ForwardArgs = (@(
    foreach ($__k in @($PSBoundParameters.Keys)) {
        if ($__k -in @('RebootNow', 'ResumeAfterReboot', 'Help')) { continue }
        $__v = $PSBoundParameters[$__k]
        if ($__v -is [switch]) { if ($__v.IsPresent) { "-$__k" } }
        elseif ($__v -is [int]) { "-$__k $__v" }
        elseif ($__v -is [string] -and $__v) { "-$__k `"$($__v -replace '"', '\"')`"" }
    }
) -join ' ')
Log "forward args for reboot-resume: [$($script:ForwardArgs)]"

Log "===== setup-ssh v7.6 start (admin=$isAdmin clientOnly=$ClientOnly resume=$script:IsResumeRun addSshUser=$AddSshUser) ====="

# ============================================================
# 步骤 1/8: 环境预检
# ============================================================
Show-Step -Title "环境预检" -Expect "几秒" -Hint "系统版本 / 功能状态 / 待重启标记 / sshd 服务"

$os = Get-CimInstance Win32_OperatingSystem
Log "OS: $($os.Caption) build $($os.BuildNumber)"
Write-Host ("    系统: {0} build {1} ({2})" -f $os.Caption, $os.BuildNumber, $os.OSArchitecture)
Write-Host ("    管理员权限: {0}" -f $isAdmin)

# v2 新增：待重启检测 —— 这是 Add-WindowsCapability 失败的常见根因
$script:RebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
if ($script:RebootPending) {
    Write-Warn "检测到系统待重启（RebootPending）"
    Write-Host "       这会导致 Add-WindowsCapability 失败（0x800f0954 / 0x800f081f）。" -ForegroundColor DarkYellow
    Write-Host "       建议：先重启系统，再重新运行本脚本。脚本仍会尝试其它降级路径。" -ForegroundColor DarkYellow
    Log "RebootPending = TRUE"
} else {
    Write-Host "    待重启标记: 无"
}

# v5: 用解析出的实际路径；解析不到时退回 System32 作为「安装目标」默认值
# v6: 只解析一次（原来连调两次 Get-SshdExePath，多余）
$sshdExe = Get-SshdExePath
$sshdFound = [bool]$sshdExe
if (-not $sshdExe) { $sshdExe = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe' }
Write-Host ("    sshd.exe: {0}" -f $(if ($sshdFound) { "已存在 -> $sshdExe" } else { '缺失' }))
$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($svc) { Write-Host ("    sshd 服务: {0} / {1}" -f $svc.Status, $svc.StartType) } else { Write-Host "    sshd 服务: 未安装" }
End-Step

# ============================================================
# 预检/卸载模式（仅 -Preflight / -Uninstall；运行时显示为步骤 2/2）
# ============================================================
if ($Preflight -or $Uninstall) {
    Show-Step -Title $(if ($Preflight) { "预检模式（只读）" } else { "卸载 OpenSSH Server" })

    if ($Preflight) {
        try {
            $c = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop
            if (@($c).Count -gt 0) { $c | Select-Object Name, State | Format-Table -AutoSize | Out-String | Write-Host }
            else { Write-Warn "未查询到 OpenSSH.Server 功能（组件库可能不完整）" }
        } catch { Write-Warn "读取功能状态失败: $($_.Exception.Message)" }

        $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
        Write-Host ("sshd 服务: " + $(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { '未安装' }))
        $resolved = Get-SshdExePath
        Write-Host ("sshd.exe : " + $(if ($resolved) { "存在 -> $resolved" } else { '缺失' }))
        $svcReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -ErrorAction SilentlyContinue
        if ($svcReg) { Write-Host ("服务 ImagePath: " + $svcReg.ImagePath) }
        Write-Host ("sshd_config: " + $(if (Test-Path $script:CfgPath) { '存在' } else { '缺失' }))
        Write-Host ("客户端 ssh: " + (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source)
        Write-Host ("用户密钥目录: " + $(if (Test-Path $script:SshDir) { '存在' } else { '缺失' }))
        Write-Host "预检完成（只读，未做任何修改）"
    } else {
        if ($svc) {
            try {
                Stop-Service sshd -Force -ErrorAction SilentlyContinue
                Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
                & sc.exe delete sshd 2>&1 | Out-Null
                # v7.1: 复核删除结果，不再无条件打印成功
                Start-Sleep -Milliseconds 300
                if (Get-Service sshd -ErrorAction SilentlyContinue) {
                    Write-Warn "sshd 服务仍未删除（权限不足或需重启后清理）"
                } else {
                    Write-Ok "sshd 服务已停止并删除"
                }
            } catch { Write-Warn "删除服务时出现问题: $($_.Exception.Message)" }
        } else { Write-Host "sshd 服务不存在，跳过" }

        foreach ($f in @('C:\ProgramData\ssh\administrators_authorized_keys')) {
            if (Test-Path $f) { Remove-Item $f -Force; Write-Ok "已删除 $f" }
        }
        Write-Warn "未删除 C:\ProgramData\ssh 下的主机密钥与配置（便于重装复用）。"
        Write-Warn "如需彻底清除 OpenSSH 功能："
        Write-Host "  Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0" -ForegroundColor DarkGray
    }
    End-Step
    Write-Host ""
    Write-Host "日志: $script:LogPath" -ForegroundColor DarkGray
    exit 0
}

# ============================================================
# 步骤 2/8: 安装 OpenSSH Server（五级降级链）
# ============================================================
if ($ClientOnly) {
    Show-Step -Title "客户端模式：跳过服务端安装" -Expect "0 秒"
    Write-Host "    -ClientOnly 已指定，仅进行客户端配置"
    End-Step
} else {
    Show-Step -Title "安装 OpenSSH Server" -Expect "1-5 分钟" -Hint "降级链: Add-WindowsCapability -> DISM -> 本地离线包 -> winget -> GitHub"

    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -like 'OpenSSH.Server*' } | Select-Object -First 1
    if ($cap) { Write-Host "    功能状态: $($cap.State)" } else { Write-Host "    功能状态: 未查询到" }

    $capState = if ($cap) { $cap.State } else { 'NotFound' }
    # v5 关键修复：以「磁盘上是否真有可用的 sshd.exe」为准，而不是以 capability 状态为准。
    # 本机实例：sshd 装在 Program Files 且服务正常运行，但 capability 因 CBS 卡死
    # 永远停留在 InstallPending —— 旧逻辑会据此误报「需要重启」并拒绝继续。
    $onDisk = Get-SshdExePath
    $installed = [bool]$onDisk
    if ($installed) { $sshdExe = $onDisk }
    $installMode = ""
    Log "install begin: capState=$capState sshdOnDisk=$onDisk rebootPending=$($script:RebootPending)"

    # v7: -PreferOffline —— 全新/无网环境优先用本地离线负载（成功则跳过全部联网路径）
    # v7.1: 若组件已暂存待重启（InstallPending），优先走重启落地，不抢装
    if ($PreferOffline -and -not $installed -and $capState -ne 'InstallPending') {
        $payload = Resolve-OfflinePayload -ExplicitPath $PackagePath
        if ($payload) {
            Write-Host "    -PreferOffline：使用本地离线负载 $payload"
            $pExe = Install-FromPayload -PayloadDir $payload -TrustPayload:([bool]$PackagePath)
            if ($pExe) {
                $sshdExe = $pExe; $installed = $true; $installMode = "本地离线包"
                Write-Ok "安装成功（本地离线包）-> $pExe"
            } else {
                Write-Warn "本地离线负载安装未成功，回退常规链路"
            }
        } else {
            Write-Warn "-PreferOffline 已指定，但未找到本地离线负载（脚本目录需含 OpenSSH-Offline-Bundle.zip 或 payload 目录），回退常规链路"
        }
    }

    if ($installed) {
        Write-Ok "OpenSSH Server 已安装：$sshdExe"
        $svcChk = Get-Service sshd -ErrorAction SilentlyContinue
        if ($svcChk) { Write-Host ("    服务: {0} / {1}" -f $svcChk.Status, $svcChk.StartType) -ForegroundColor DarkGray }
        if ($capState -eq 'InstallPending') {
            Write-Host "    注：capability 状态仍为 InstallPending（本机 CBS 卡死所致），已忽略。" -ForegroundColor DarkGray
        }
    } elseif ($capState -eq 'InstallPending') {
        # v3 修复：InstallPending = 组件已下载并暂存，只差一次重启落地，不是失败
        Write-Warn "检测到组件已下载并暂存（InstallPending）—— 安装其实已完成，只差一次重启"
        Write-Host "    重启后 sshd.exe 会自动出现在 $sshdExe" -ForegroundColor DarkYellow
        $script:NeedsRebootForStaged = $true
    } else {

        # --- 降级 1: Add-WindowsCapability ---
        if ($script:RebootPending) {
            Write-Warn "跳过 Add-WindowsCapability（存在待重启标记，大概率失败）"
        } else {
            try {
                Show-Progress2 -Activity "安装 OpenSSH Server" -Status "从 Windows Update 获取组件 ..."
                if ($cap) { $cap | Add-WindowsCapability -Online -ErrorAction Stop | Out-Null }
                else { Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction Stop | Out-Null }
                Stop-Progress2 -Activity "安装 OpenSSH Server"
                $installed = (Test-Path $sshdExe)
                if ($installed) { $installMode = "Add-WindowsCapability"; Write-Ok "安装成功（Add-WindowsCapability）" }
            } catch {
                Stop-Progress2 -Activity "安装 OpenSSH Server"
                Write-Warn "Add-WindowsCapability 失败: $($_.Exception.Message)"
                Log "Add-WindowsCapability failed: $($_.Exception.Message)"
            }
        }

        # --- 降级 2: DISM ---
        if (-not $installed) {
            try {
                Write-Host "    尝试 DISM /Add-Capability ..."
                $d = & dism.exe /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 2>&1
                $code = $LASTEXITCODE
                Log "dism exit=$code : $(($d | Out-String) -replace "`r?`n", ' | ')"
                if ($code -eq 0 -or $code -eq 3010) {
                    $installed = (Test-Path $sshdExe)
                    if ($installed) { $installMode = "DISM"; Write-Ok "安装成功（DISM）" }
                    else {
                        # v3 修复：DISM 返回 0 但文件未落地 = 已暂存，等重启
                        Log "dism reported success but sshd.exe absent -> treating as staged-pending-reboot"
                        Write-Warn "DISM 报告成功，但文件需重启后才落地（暂存完成）"
                        $script:NeedsRebootForStaged = $true
                    }
                } else { Write-Warn "DISM 返回 $code" }
            } catch { Write-Warn "DISM 调用异常: $($_.Exception.Message)" }
        }

        # --- 降级 2.5 (v7): 本地离线负载 ---
        # 全新系统常无外网（或被墙）：WU/DISM 与 winget/GitHub 全链路都会失败，
        # 脚本目录带离线包（OpenSSH-Offline-Bundle.zip / payload 目录）时在此离线完成安装。
        if (-not $installed -and -not $script:NeedsRebootForStaged) {
            $payload = Resolve-OfflinePayload -ExplicitPath $PackagePath
            if ($payload) {
                Write-Host "    尝试本地离线负载安装（$payload）..."
                $pExe = Install-FromPayload -PayloadDir $payload -TrustPayload:([bool]$PackagePath)
                if ($pExe) {
                    $sshdExe = $pExe; $installed = $true; $installMode = "本地离线包"
                    Write-Ok "安装成功（本地离线包）-> $pExe"
                } else {
                    Write-Warn "本地离线负载安装未成功（继续后续降级）"
                }
            }
        }

        # --- 降级 3: winget ---
        if (-not $installed -and -not $script:NeedsRebootForStaged -and (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            # v3 修复：真实包 ID 是 Microsoft.OpenSSH.Preview（旧代码写的 .Beta 不存在）
            foreach ($pkgId in @('Microsoft.OpenSSH.Preview', 'Microsoft.OpenSSH.Beta')) {
                if ($installed) { break }
                try {
                    Write-Host "    尝试 winget install $pkgId ..."
                    $w = & winget.exe install --id $pkgId --source winget `
                            --accept-source-agreements --accept-package-agreements --silent --disable-interactivity 2>&1
                    $wcode = $LASTEXITCODE
                    Log "winget $pkgId exit=$wcode : $(($w | Out-String) -replace "`r?`n", ' | ')"
                    # v5 修复：winget 装到 Program Files\OpenSSH，不能用 System32 的路径判断成败
                    $afterW = Get-SshdExePath
                    if ($wcode -eq 0 -and $afterW) {
                        $sshdExe = $afterW
                        $installMode = "winget"; $installed = $true; Write-Ok "安装成功（winget: $pkgId）-> $afterW"
                    } else {
                        Write-Warn "winget $pkgId 未成功（exit=$wcode）"
                    }
                } catch { Write-Warn "winget 调用异常: $($_.Exception.Message)" }
            }
        }

        # --- 降级 4: GitHub 离线包 ---
        if (-not $installed -and -not $script:NeedsRebootForStaged) {
            try {
                Write-Host "    尝试 GitHub 官方离线包（Win32-OpenSSH-Portable）..."
                # v3 修复：原代码 tag 'V_9_5_p2_Labs' 是错的（404）。
                # 改为动态查询最新 release，失败时回退到已知有效 tag。
                $ver  = $null
                $asset = 'OpenSSH-Win64.zip'
                try {
                    $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest' `
                              -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
                    if ($rel.tag_name) { $ver = $rel.tag_name }
                } catch { Log "github api failed: $($_.Exception.Message)" }
                if (-not $ver) { $ver = '10.0.0.0p2-Preview'; Write-Host "    API 不可用，回退到 tag $ver" }
                Log "github tag resolved: $ver"

                $url = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/$ver/$asset"
                $zip = Join-Path $env:TEMP $asset
                # v5: 装到 Program Files\OpenSSH，与 winget / 官方约定一致
                $dst = 'C:\Program Files\OpenSSH'
                Write-Host "    下载 $url"
                Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
                Log "downloaded $((Get-Item $zip).Length) bytes"
                # v7: 解到唯一目录 —— 原实现扫 TEMP 里所有 OpenSSH-Win64*，可能命中历史残留
                $ex = Join-Path $env:TEMP ('openssh-dl-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
                Expand-Archive -LiteralPath $zip -DestinationPath $ex -Force -ErrorAction Stop
                $inner = Get-ChildItem $ex -Directory -Filter 'OpenSSH-Win64*' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($inner) {
                    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
                    Move-Item $inner.FullName $dst -Force
                    # v3: 优先用官方 install-sshd.ps1 注册服务（它会正确设置权限与 StartType）
                    $setupScript = Join-Path $dst 'install-sshd.ps1'
                    if (Test-Path $setupScript) {
                        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript 2>&1 | Out-Null
                        Log "ran install-sshd.ps1 (exit=$LASTEXITCODE)"
                    } else {
                        # v7.1: 静态串走 cmd（Program Files 路径含空格；无用户输入，无注入面）
                        & cmd.exe /c ('sc.exe create sshd binPath= "' + $dst + '\sshd.exe" start= auto DisplayName= "OpenSSH SSH Server"') 2>&1 | Out-Null
                    }
                    # v5 修复：同样不能再拿 System32 的路径判断成败
                    $afterDl = Get-SshdExePath
                    if ($afterDl) {
                        $sshdExe = $afterDl
                        $installed = $true
                        $installMode = "GitHub离线包"
                        Write-Ok "安装成功（离线包 + 官方 install-sshd.ps1）-> $afterDl"
                    }
                }
            } catch { Write-Warn "离线包安装失败: $($_.Exception.Message)" }
        }
    }

    # v3: 暂存待重启的情形单独处理 —— 引导重启并注册自动续跑
    if ($script:NeedsRebootForStaged -and -not (Test-Path $sshdExe)) {
        Write-Host ""
        Write-Warn "==> 组件已就绪，需要重启系统才能完成落地"
        Write-Host "    重启后 sshd.exe 会自动出现，本脚本会自动继续完成剩余配置。" -ForegroundColor DarkYellow
        if ($script:IsResumeRun) {
            # 防死循环：续跑过一轮后仍处于 InstallPending，不再自动重启
            Write-Warn "续跑后仍为 InstallPending，已停止自动重启以免循环。"
            Write-Host "    请手动检查：Get-WindowsCapability -Online -Name OpenSSH.Server*" -ForegroundColor DarkYellow
            Write-Host "    日志: $script:LogPath" -ForegroundColor DarkGray
            End-Step
            exit 4
        }
        if ($RebootNow) {
            if (Register-AutoResume -ScriptPath $PSCommandPath -ExtraArgs $script:ForwardArgs) {
                Write-Ok "已注册自动续跑任务（登录后以最高权限运行）"
                Write-Host ""
                Write-Host "    即将重启系统以完成 OpenSSH 组件落地。" -ForegroundColor Yellow
                Write-Host "    请先保存其它程序中的未保存工作！按 Ctrl+C 可取消。" -ForegroundColor Yellow
                Write-Host ""
                for ($s = 30; $s -gt 0; $s--) {
                    Write-Host ("`r    倒计时 {0,2} 秒 ...  " -f $s) -NoNewline -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
                Write-Host ""
                Log "RebootNow: restarting after countdown"
                End-Step
                Restart-Computer -Force
                exit 4
            } else {
                Write-Warn "自动续跑注册失败，请手动重启后重新运行脚本"
            }
        } else {
            Write-Host "    请重启后重新运行本脚本；或加 -RebootNow 自动重启并续跑：" -ForegroundColor DarkYellow
            Write-Host "        setup-ssh.bat -RebootNow" -ForegroundColor White
        }
        Write-Host "日志: $script:LogPath" -ForegroundColor DarkGray
        End-Step
        exit 4
    }

    if (-not (Test-Path $sshdExe)) {
        Write-Err "OpenSSH Server 安装失败，所有降级路径均未成功。"
        Write-Err "建议按顺序排查："
        Write-Host "  1. 重启系统后重试（当前 RebootPending=$($script:RebootPending)）" -ForegroundColor DarkGray
        Write-Host "  2. 手动: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0" -ForegroundColor DarkGray
        Write-Host "  3. 检查 Windows Update 服务与代理设置" -ForegroundColor DarkGray
        Write-Host "  4. 控制面板 -> 程序 -> 启用或关闭 Windows 功能 -> 勾选 OpenSSH 服务器" -ForegroundColor DarkGray
        Write-Host "日志: $script:LogPath" -ForegroundColor DarkGray
        End-Step; exit 1
    }
    Write-Ok ("sshd.exe 就位" + $(if ($installMode) { "（来源: $installMode）" } else { "" }))
    End-Step

    # ========================================================
    # 步骤 3/8: 生成主机密钥 + 配置 sshd_config
    # ========================================================
    Show-Step -Title "配置 sshd（主机密钥 + sshd_config）" -Expect "几秒" -Hint "校验前补齐主机密钥；配置正确且已备份"

    function Set-SshdPort {
        param([int]$Port, [string]$CfgPath)
        $dir = Split-Path $CfgPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

        if (-not (Test-Path $CfgPath)) {
            Write-Warn "未找到 sshd_config，创建标准默认配置"
            @(
                "# OpenSSH Server config (created by setup-ssh.ps1 v4)",
                "Port $Port",
                "",
                "# 认证设置",
                "PasswordAuthentication yes",
                "PubkeyAuthentication yes",
                "",
                "# v4 修复：不使用 Match Group administrators 块。",
                "# 本机实测该块会让鉴权子进程访问冲突崩溃（OpenSSH 9.5.6.2 与 10.0p2 均复现），",
                "# 因此统一走用户级 ~/.ssh/authorized_keys。",
                "AuthorizedKeysFile .ssh/authorized_keys",
                "",
                "# v4 关键：authorized_keys 及其 .ssh 目录必须给 SYSTEM 与 Administrators 读权限。",
                "# Windows 上 sshd 的鉴权子进程以特权身份读取该文件，而 SYSTEM 不像 Linux root",
                "# 那样绕过文件 ACL —— ACL 只给用户本人时，sshd 读不到文件，会报",
                "# 'Permission denied (publickey)'，即使密钥就写在里面。",
                "",
                "Subsystem sftp sftp-server.exe"
            ) | Set-Content -LiteralPath $CfgPath -Encoding ascii
            return
        }

        Copy-Item -LiteralPath $CfgPath -Destination ("$CfgPath.bak-{0}" -f (Get-Date -Format yyyyMMdd-HHmmss)) -Force
        Remove-OldBackup -BasePath $CfgPath -Keep 3   # v5: 只保留最近 3 份，避免反复运行堆满目录
        $lines = @(Get-Content -LiteralPath $CfgPath)
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*Port\s+\d+') { $lines[$i] = "Port $Port"; $found = $true }
        }
        if (-not $found) {
            $idx = -1
            for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*Match\s+') { $idx = $i; break } }
            if ($idx -ge 0 -and $idx -gt 0) { $lines = @($lines[0..($idx-1)]) + "Port $Port" + @($lines[$idx..($lines.Count-1)]) }
            else { $lines += "Port $Port" }
        }
        $lines | Set-Content -LiteralPath $CfgPath -Encoding ascii
    }

    Set-SshdPort -Port $Port -CfgPath $script:CfgPath
    Write-Ok "sshd 监听端口设置为 $Port（原配置已备份）"

    # v6.1: 全新安装死锁修复 —— 见文件头 v6 修复【9】。
    # sshd -t 校验要求主机密钥已存在；密钥本在服务首次启动时才自动生成，
    # 不先补齐则「全新机器首次运行」必然卡在下方校验处退出。
    # v7: 改走 New-EmptyPassphraseKey（原 -N '""' 在 pwsh7 下会把密钥加密，
    #     sshd 加载失败 → 校验依旧必挂）；并对旧的加密主机密钥自愈重生成。
    try {
        $hostKeyDir = Join-Path $env:ProgramData 'ssh'
        if (-not (Test-Path $hostKeyDir)) { New-Item -ItemType Directory -Force -Path $hostKeyDir | Out-Null }
        foreach ($hk in @(
            @{ t = 'rsa';     b = 3072; f = 'ssh_host_rsa_key' },
            @{ t = 'ecdsa';   b = 0;    f = 'ssh_host_ecdsa_key' },
            @{ t = 'ed25519'; b = 0;    f = 'ssh_host_ed25519_key' }
        )) {
            $kp = Join-Path $hostKeyDir $hk.f
            if (Test-Path -LiteralPath $kp) {
                $c = Get-PrivateKeyCipher $kp
                if ($c -eq 'none') { continue }   # 正常密钥跳过
                # v7.1: 非 OPENSSH 新格式时，识别加密 PEM（sshd 同样加载不了）；未加密 PEM 保守跳过
                if (-not $c) {
                    if (-not (Test-PrivateKeyEncryptedPem $kp)) { continue }
                    $c = 'PEM-encrypted'
                }
                # v7 自愈：带口令的主机密钥（旧版在 pwsh7 下生成）sshd 无法加载
                $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 4)
                Write-Warn "主机密钥 $($hk.f) 带口令（$c，旧版脚本/旧机拷贝所致），sshd 无法加载 — 改名保留并重新生成"
                try { Rename-Item -LiteralPath $kp -NewName "$($hk.f).broken-$stamp" -Force -ErrorAction Stop }
                catch { Remove-Item -LiteralPath $kp -Force -ErrorAction SilentlyContinue }
                if (Test-Path -LiteralPath "$kp.pub") { Rename-Item -LiteralPath "$kp.pub" -NewName "$($hk.f).pub.broken-$stamp" -Force -ErrorAction SilentlyContinue }
            }
            if (New-EmptyPassphraseKey -KeyType $hk.t -KeyPath $kp -Bits $hk.b) {
                Write-Ok "已生成主机密钥 $($hk.f)"
            } else {
                Write-Warn "主机密钥 $($hk.f) 生成失败（sshd -t 将因此失败）"
            }
        }
    } catch { Write-Warn "补齐主机密钥失败: $($_.Exception.Message)" }

    # v5 新增：写完配置立刻做语法校验（本机排查时正是靠 sshd -t 才定位到配置问题）
    try {
        $tOut = & $sshdExe -t 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "sshd_config 语法校验通过（sshd -t）"
        } else {
            Write-Err "sshd_config 语法校验失败（sshd -t 退出码 $LASTEXITCODE）："
            ($tOut.Trim() -split "`r?`n") | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
            Log "sshd -t failed: $($tOut.Trim())"
            End-Step
            exit 1
        }
    } catch { Write-Warn "无法执行 sshd -t 校验: $($_.Exception.Message)" }

    # 密钥登录准备（v4 重写）
    # v4 关键修复：把本机公钥写入【各用户自己的】~/.ssh/authorized_keys，
    # 并把该文件与 .ssh 目录的 ACL 设为「用户 + SYSTEM + Administrators」。
    # 少了 SYSTEM/Administrators 读权限，sshd 的鉴权子进程读不到文件，
    # 表现为 "Permission denied (publickey)"（本机实测踩过，排查了很久）。
    if (-not $NoKeygen) {
        # v6: 此步只能覆盖「当前用户」—— 新账号要到第 6 步才创建，这里 $script:UserReady
        # 还是空的（v5 正是因此在 -CreateUser / -AddSshUser 场景下漏写新账号的公钥）。
        # 新账号由创建成功后调用 Add-PublicKeyToUser 单独补写。
        $pkPaths = @(Add-PublicKeyToUser -UserName $env:USERNAME)
        if ($pkPaths.Count) {
            Write-Ok "公钥已写入 $env:USERNAME 的 authorized_keys（ACL: 用户 + SYSTEM + Administrators）"
            $pkPaths | ForEach-Object { Write-Host "      -> $_" -ForegroundColor DarkGray }
        } else {
            Write-Host "    未写入当前用户 authorized_keys（尚无公钥或写入失败，见日志）" -ForegroundColor DarkGray
        }
    }

    # 防止旧的 administrators_authorized_keys 与 Match 块残留引发崩溃
    # （v6: 从 NoKeygen/公钥存在性的嵌套里提出，改为始终执行）
    if (Test-Path $script:CfgPath) {
        $cfgTxt = Get-Content -LiteralPath $script:CfgPath -Raw
        if ($cfgTxt -match '(?m)^\s*Match\s+Group\s+administrators') {
            Write-Warn "检测到 sshd_config 仍含 Match Group administrators 块（本机会崩溃），已自动注释"
            Copy-Item $script:CfgPath "$($script:CfgPath).bak-v4" -Force -ErrorAction SilentlyContinue
            $fixed = ($cfgTxt -split "`r?`n" | ForEach-Object {
                if ($_ -match '^\s*Match\s+Group\s+administrators' -or $_ -match '^\s*AuthorizedKeysFile\s+__PROGRAMDATA__') { "# [v4 disabled] $_" } else { $_ }
            }) -join "`r`n"
            Set-Content -LiteralPath $script:CfgPath -Value $fixed -Encoding ascii
        }
    }

    # v7.2: 保障 sshd（SYSTEM 身份）可读数据目录/配置/主机密钥 —— 见文件头 v7.2【2】
    # v7.3: $null = 吞掉返回值（否则控制台会多打印一行数字）
    $null = Ensure-SshDataAcls -DataDir (Join-Path $env:ProgramData 'ssh') -CfgPath $script:CfgPath
    End-Step

    # ========================================================
    # 步骤 4/8: 防火墙
    # ========================================================
    Show-Step -Title "配置防火墙（TCP $Port）" -Expect "几秒" -Hint "先按规则名精确匹配（快速路径），未命中才做全量端口比对"

    if (-not $NoFirewall) {
        $myRuleName = "OpenSSH Server (sshd) - TCP $Port"
        # v7.6: 读 ActiveStore（含 GPO），并要求覆盖【全部】活动网络档
        $activeProfiles = @(Get-EffectiveFirewallProfile)
        $profileText = if ($activeProfiles.Count) { $activeProfiles -join ', ' } else { '无活动网络' }
        $sshdExe = Get-SshdExePath
        $pfMap = Get-FirewallPortFilterMap

        $activeBits = 0
        foreach ($a in $activeProfiles) { $activeBits = $activeBits -bor (Get-FirewallProfileBit $a) }
        $blockAll = $false
        $localRulesDisabled = $false
        foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
            $bit = Get-FirewallProfileBit $p.Name
            if ($activeBits -ne 0 -and -not ($activeBits -band $bit)) { continue }
            if ($p.Enabled -ne 'True') { continue }
            if ($p.AllowInboundRules -eq 'False') {
                Write-Err "防火墙 $($p.Name) 档为「阻止所有传入连接」(AllowInboundRules=False)，放行规则不会生效"
                $blockAll = $true
            }
            if ($p.AllowLocalFirewallRules -eq 'False') {
                $localRulesDisabled = $true
            }
        }

        # 候选规则：Inbound/Allow/Enabled（ActiveStore）
        $candidates = @()
        $candidates += @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $myRuleName -ErrorAction SilentlyContinue)
        $candidates += @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
        $candidates = @($candidates | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' })

        $covered = $false
        foreach ($r in $candidates) {
            if (-not (Test-FirewallRuleCoversProfiles -Rule $r -ActiveProfiles $activeProfiles)) { continue }
            $pf = Get-RulePortFilter -Rule $r -PortFilterMap $pfMap
            if (-not ($pf -and @('TCP', 'Any') -contains $pf.Protocol -and (Test-FirewallPortInFilter -LocalPort $pf.LocalPort -Port $Port))) { continue }
            if (-not (Test-FirewallRuleUnrestricted -Rule $r -SshdExe $sshdExe)) { continue }
            $covered = $true; break
        }

        if ($covered) {
            Write-Ok "防火墙已放行 TCP $Port（现有规则覆盖全部活动网络：$profileText）"
        } else {
            # 慢速路径：ActiveStore 全量枚举，先筛 Profile/端口，再验作用域
            $existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
                          ForEach-Object {
                              $r = $_
                              if (-not (Test-FirewallRuleCoversProfiles -Rule $r -ActiveProfiles $activeProfiles)) { return }
                              $pf = Get-RulePortFilter -Rule $r -PortFilterMap $pfMap
                              if (-not ($pf -and @('TCP', 'Any') -contains $pf.Protocol -and (Test-FirewallPortInFilter -LocalPort $pf.LocalPort -Port $Port))) { return }
                              if (-not (Test-FirewallRuleUnrestricted -Rule $r -SshdExe $sshdExe)) { return }
                              $r
                          })
            if ($existing.Count -gt 0) {
                Write-Ok "防火墙已放行 TCP $Port（现有规则覆盖全部活动网络：$profileText）"
            } elseif ($localRulesDisabled) {
                Write-Err "活动网络档由组策略禁止本地防火墙规则 (AllowLocalFirewallRules=False)，无法自动放行 TCP $Port"
            } else {
                try {
                    $newRule = New-NetFirewallRule -DisplayName $myRuleName `
                        -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
                        -Profile Any -Enabled True -PassThru -ErrorAction Stop
                    Write-Host "    已创建规则: $($newRule.DisplayName)" -ForegroundColor DarkGray
                    # 回读 ActiveStore（策略合并后的真实生效状态）
                    $eff = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                             Where-Object { $_.Name -eq $newRule.Name } | Select-Object -First 1)
                    if ($eff) {
                        $npf = Get-RulePortFilter -Rule $eff -PortFilterMap (Get-FirewallPortFilterMap)
                        $okProfile = Test-FirewallRuleCoversProfiles -Rule $eff -ActiveProfiles $activeProfiles
                        $okPort = ($npf -and @('TCP', 'Any') -contains $npf.Protocol -and (Test-FirewallPortInFilter -LocalPort $npf.LocalPort -Port $Port))
                        if ($okProfile -and $okPort -and $eff.Enabled -eq 'True') {
                            Write-Ok "规则回读校验通过（Profile=$($eff.Profile)，活动网络：$profileText）"
                        } else {
                            Write-Warn "规则已创建但覆盖不完整：Profile=$($eff.Profile)，LocalPort=$(@($npf.LocalPort) -join ',')；活动网络：$profileText"
                        }
                    } else {
                        Write-Err "规则未在 ActiveStore 中生效（可能被组策略屏蔽）：$myRuleName"
                    }
                } catch { Write-Err "创建防火墙规则失败: $($_.Exception.Message)" }
            }
        }

        # Block 优先于 Allow（有批量过滤器时总是检查；否则仅在未覆盖时检查）
        $blockHits = if ($pfMap -or -not $covered) { @(Get-BlockingFirewallRule -Port $Port -ActiveProfiles $activeProfiles -PortFilterMap $pfMap) } else { @() }
        foreach ($b in $blockHits) {
            Write-Err "存在阻止 TCP $Port 的入站规则（Block 优先于 Allow）: $($b.DisplayName) [Profile=$($b.Profile)]"
        }

        if ($blockAll -or $blockHits.Count -gt 0) {
            Write-Err "防火墙配置未能保证 TCP $Port 可达，请检查上述策略/规则"
        }
        if ($activeProfiles.Count -eq 0) {
            Write-Warn "未检测到活动网络（NLA/网卡异常）；已按 Profile=Any 配置，规则对所有网络生效"
        } elseif ($activeProfiles -contains 'Public') {
            Write-Host "    提示: 活动网络含「公用」，本步用 Profile=Any 放行；若需收紧，请把网络改为专用后缩小规则 Profile" -ForegroundColor DarkGray
        }
    } else { Write-Warn "已跳过防火墙配置" }
    Write-Host "    提示: 云服务器还需在云控制台安全组放行 $Port/tcp" -ForegroundColor DarkGray
    End-Step

    # ========================================================
    # 步骤 5/8: 登录账号（v2 修复 MSA 误判）
    # ========================================================
    Show-Step -Title "配置 SSH 登录账号" -Expect "几秒" -Hint "v2 修复: 微软账号 PasswordRequired=False 不再被误判为不可用"

    function Get-PlainText {
        param([Security.SecureString]$Secure)
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
        try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::FreeBSTR($bstr) }   # v2: 修复内存泄漏
    }
    function Get-RandomPassword {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%'
        -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    }
    function Get-Password {
        param([string]$Provided)
        if ($Provided) { return $Provided }
        if ($script:Interactive) {
            Write-Host "请输入密码（不显示）:" -NoNewline
            $s1 = Read-Host -AsSecureString
            Write-Host "再次输入:" -NoNewline
            $s2 = Read-Host -AsSecureString
            $p1 = Get-PlainText $s1; $p2 = Get-PlainText $s2
            if (-not $p1 -or $p1 -ne $p2) { throw "密码为空或两次不一致" }
            return $p1
        }
        $rp = Get-RandomPassword
        $script:RandomPassword = $rp
        return $rp
    }

    # v2: 用 net user 判断账号是否真的可用于密码登录
    function Get-UsableAccounts {
        $result = @()
        try {
            $lines = & net.exe user 2>&1
            foreach ($ln in $lines) {
                $t = ($ln -replace "`r", '').Trim()
                if ($t -match '^(\S+)\s+(Active|Passive|没有任何密码)\s*(\S*)\s*(\S*)\s*(\S*)\s*(.*)$') {
                    $name = $Matches[1]
                    if ($name -match '^(命令成功|User|用户)$') { continue }
                    $result += [pscustomobject]@{ Name = $name; Line = $t }
                }
            }
        } catch { }
        return $result
    }

    $accounts = Get-UsableAccounts
    if ($accounts.Count -gt 0) {
        Write-Host "    系统账号（net user 解析）:" -ForegroundColor DarkGray
        $accounts | ForEach-Object { Write-Host ("      " + $_.Line) -ForegroundColor DarkGray }
    }

    if ($SkipAccount) {
        Write-Warn "已按 -SkipAccount 跳过账号配置"
    } elseif ($AddSshUser) {
        # v6: 专用 SSH 登录账号（默认 ssh/ssh），始终加入 Administrators
        $uname = $SshUserName.Trim()
        if (-not $uname -or $uname -notmatch '^[a-zA-Z0-9_.-]{1,20}$') {
            Write-Err "非法用户名: $uname（仅限 1-20 位字母/数字/_.-）"
        } else {
            $upass = $SshUserPassword
            try {
                if (-not $upass) { $upass = Get-Password "" }
                $sec = ConvertTo-SecureString $upass -AsPlainText -Force
                if (Get-LocalUser -Name $uname -ErrorAction SilentlyContinue) {
                    Enable-LocalUser -Name $uname -ErrorAction Stop
                    Set-LocalUser -Name $uname -Password $sec -PasswordNeverExpires $true -AccountNeverExpires -ErrorAction Stop
                    Write-Ok "账号 $uname 已存在：已启用 + 密码已重置"
                } else {
                    New-LocalUser -Name $uname -Password $sec -FullName 'SSH Login Account' `
                        -Description 'Dedicated SSH login account (setup-ssh.ps1)' `
                        -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
                    Enable-LocalUser -Name $uname -ErrorAction SilentlyContinue
                    Write-Ok "账号 $uname 已创建"
                }
                $grp = Get-AdminGroupName
                switch (Add-UserToAdminGroup -UserName $uname) {
                    'added'   { Write-Ok "已加入 $grp 组" }
                    'already' { Write-Ok "已在 $grp 组中" }
                    default   { Write-Warn "加入管理员组失败，请手动执行: Add-LocalGroupMember -Group '$grp' -Member $uname" }
                }
                # v6: 先预建 profile 再写任何文件 —— 顺序反了会让 Windows 注册临时 profile，
                # 导致 sshd 家目录漂移、公钥登录失败（真机踩过，见 v6【7】）
                if (Initialize-UserProfile -UserName $uname -PlainPassword $upass) {
                    Write-Ok "账号 $uname 的配置文件已就绪"
                } else {
                    Write-Warn "预建账号配置文件失败，公钥将走双路径兜底（不影响密码登录）"
                }
                $script:UserReady = $uname
                # v6: 账号建在第 4 步之后，必须在此补写公钥（公钥第 8 步才有，第 8 步还会再补一次）
                $pkPaths = @(Add-PublicKeyToUser -UserName $uname)
                if ($pkPaths.Count) {
                    Write-Ok "公钥已写入 $uname 的 authorized_keys"
                    $pkPaths | ForEach-Object { Write-Host "      -> $_" -ForegroundColor DarkGray }
                }
                if ($upass -eq 'ssh' -or $upass.Length -lt 8) {
                    Write-Warn "账号 $uname 使用了弱口令（默认或过短口令）且属于管理员组，建议仅用于内网/测试环境，并尽快改密。"
                }
            } catch {
                Write-Err "创建账号失败: $($_.Exception.Message)"
                Write-Host "    若为密码策略拒绝（短口令），查看当前策略: net accounts" -ForegroundColor DarkYellow
                Write-Host "    放宽最短长度: net accounts /minpwlen:0（复杂性要求需在 secpol.msc 中调整）" -ForegroundColor DarkYellow
            }
        }
    } elseif ($EnableAdmin) {
        try {
            $pw = Get-Password $AdminPassword
            Enable-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
            $sec = ConvertTo-SecureString $pw -AsPlainText -Force
            Set-LocalUser -Name 'Administrator' -Password $sec -ErrorAction Stop
            $script:AdminReady = $true
            Write-Ok "内置 Administrator 已启用并设置密码"
        } catch { Write-Err "启用 Administrator 失败: $($_.Exception.Message)" }
    } elseif ($CreateUser) {
        $idx = $CreateUser.IndexOf(':')
        if ($idx -gt 0) { $uname = $CreateUser.Substring(0,$idx); $upass = $CreateUser.Substring($idx+1) }
        else { $uname = $CreateUser; $upass = '' }
        $uname = $uname.Trim()
        if (-not $uname -or $uname -notmatch '^[a-zA-Z0-9_.-]{1,20}$') {
            Write-Err "非法用户名: $uname（仅限 1-20 位字母/数字/_.-）"
        } else {
            try {
                $pw = Get-Password $upass
                $sec = ConvertTo-SecureString $pw -AsPlainText -Force
                if (Get-LocalUser -Name $uname -ErrorAction SilentlyContinue) {
                    Enable-LocalUser -Name $uname -ErrorAction SilentlyContinue
                    Set-LocalUser -Name $uname -Password $sec -ErrorAction Stop
                    Write-Ok "用户 $uname 已存在，密码已更新"
                } else {
                    New-LocalUser -Name $uname -Password $sec -FullName $uname `
                        -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
                    Write-Ok "用户 $uname 已创建"
                }
                if ($AdminUser) {
                    Add-LocalGroupMember -Group 'Administrators' -Member $uname -ErrorAction SilentlyContinue
                    Write-Ok "已加入 Administrators 组"
                }
                # v6: 先预建 profile（否则 Windows 会注册临时 profile，公钥路径漂移，见 v6【7】）
                if (Initialize-UserProfile -UserName $uname -PlainPassword $pw) {
                    Write-Ok "用户 $uname 的配置文件已就绪"
                } else {
                    Write-Warn "预建用户配置文件失败，公钥将走双路径兜底（不影响密码登录）"
                }
                $script:UserReady = $uname
            } catch { Write-Err "创建用户失败: $($_.Exception.Message)" }
        }
    } else {
        # v2 关键修复：不再因 PasswordRequired=False（微软账号）直接 exit 1
        $hasNonAdmin = @(Get-LocalUser -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -and $_.Name -notin @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount') }).Count -gt 0
        if ($hasNonAdmin) {
            Write-Ok "检测到已启用的本地账号，跳过账号创建"
            Write-Host "    若无法登录，请使用：setup-ssh.bat -EnableAdmin、-CreateUser 'user:pass' 或 -AddSshUser" -ForegroundColor DarkGray
            Write-Host "    微软账号（MSA）无法直接用于 SSH 密码登录，密钥登录不受影响。" -ForegroundColor DarkGray
        } elseif ($script:Interactive) {
            Write-Warn "未检测到可用的本地账号"
            Write-Host "  1) 启用 Administrator  2) 创建新用户  3) 跳过" -ForegroundColor DarkGray
            $c = Read-Host "选择 1/2/3"
            switch ($c) {
                '1' { $EnableAdmin = $true }
                '2' { $CreateUser = Read-Host "新用户名"; $AdminUser = $true }
                default { }
            }
            if ($EnableAdmin) {
                try {
                    $pw = Get-Password ""
                    Enable-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
                    Set-LocalUser -Name 'Administrator' -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
                    $script:AdminReady = $true; Write-Ok "Administrator 已配置"
                } catch { Write-Err "失败: $($_.Exception.Message)" }
            } elseif ($CreateUser) {
                try {
                    $uname = $CreateUser.Trim()
                    $pw = Get-Password ""
                    New-LocalUser -Name $uname -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -FullName $uname `
                        -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
                    Add-LocalGroupMember -Group 'Administrators' -Member $uname -ErrorAction SilentlyContinue
                    if (-not (Initialize-UserProfile -UserName $uname -PlainPassword $pw)) {
                        Write-Warn "预建账号配置文件失败，公钥将走双路径兜底"
                    }
                    $script:UserReady = $uname; Write-Ok "用户 $uname 已创建并加入管理员组"
                } catch { Write-Err "失败: $($_.Exception.Message)" }
            }
        } else {
            # v2: 非交互不再直接 exit 1，改为警告 + 继续（密钥登录不需要密码账号）
            Write-Warn "未检测到已启用的本地账号，且当前为非交互模式。"
            Write-Host "    密钥登录无需密码账号，脚本将继续。若需密码登录请加 -EnableAdmin、-CreateUser 或 -AddSshUser。" -ForegroundColor DarkGray
        }
    }

    # v6: 刚配置了带密码的账号，必须确认 sshd_config 没有禁用密码认证，否则账号形同虚设
    if (-not $SkipAccount -and ($script:UserReady -or $script:AdminReady) -and (Test-Path $script:CfgPath)) {
        try {
            $cfgTxt = Get-Content -LiteralPath $script:CfgPath -Raw
            if ($cfgTxt -match '(?m)^\s*PasswordAuthentication\s+no\s*$') {
                Copy-Item -LiteralPath $script:CfgPath -Destination "$($script:CfgPath).bak-pwauth" -Force -ErrorAction SilentlyContinue
                $cfgTxt = [regex]::Replace($cfgTxt, '(?m)^\s*PasswordAuthentication\s+no\s*$', 'PasswordAuthentication yes')
                Set-Content -LiteralPath $script:CfgPath -Value $cfgTxt -Encoding ascii
                Write-Warn "sshd_config 原为 PasswordAuthentication no，已改回 yes 以支持密码登录（备份 .bak-pwauth）"
            }
        } catch { Write-Warn "检查 PasswordAuthentication 失败: $($_.Exception.Message)" }
    }
    End-Step

    # ========================================================
    # 步骤 6/8: 默认 Shell + 启动服务
    # ========================================================
    Show-Step -Title "设置默认 Shell 并启动 sshd" -Expect "几秒"

    if ($DefaultShell -ne 'Keep') {
        $shellPath = if ($DefaultShell -eq 'PowerShell') { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
                     else { "$env:SystemRoot\System32\cmd.exe" }
        try {
            New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -Value $shellPath -ErrorAction Stop
            Write-Ok "默认 shell 已设为 $DefaultShell"
        } catch { Write-Warn "设置默认 shell 失败: $($_.Exception.Message)" }
    } else { Write-Host "    保持系统默认 shell（Keep）" }

    # v7.2: 端口占用预检 —— sshd 绑定失败同样表现为服务起不来，先把占用者点出来
    $occ = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    foreach ($c in $occ) {
        $pname = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        if ($pname -and $pname -ne 'sshd') {
            Write-Warn "端口 $Port 已被其它进程占用: PID=$($c.OwningProcess)（$pname），sshd 可能因此启动失败"
        }
    }
    # v7.2: 启动前再确保一次 SYSTEM 可读（覆盖从其它机器拷贝密钥的场景）
    # v7.3: $null = 吞掉返回值（否则控制台会多打印一行数字）
    $null = Ensure-SshDataAcls -DataDir (Join-Path $env:ProgramData 'ssh') -CfgPath $script:CfgPath

    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Warn "未找到 sshd 服务。尝试注册："
        # v7.1: 路径无空格用免引号 argv（跨宿主一致）；有空格改用 cmd 静态串（无用户输入）
        if ($sshdExe -match '\s') {
            & cmd.exe /c ('sc.exe create sshd binPath= "' + $sshdExe + '" start= auto DisplayName= "OpenSSH SSH Server"') 2>&1 | Out-Null
        } else {
            & sc.exe create sshd binPath= $sshdExe start= auto DisplayName= 'OpenSSH SSH Server' obj= LocalSystem 2>&1 | Out-Null
        }
        $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    }
    if ($svc) {
        Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
        try {
            Restart-Service -Name sshd -Force -ErrorAction Stop
            Write-Ok "sshd 已启动（开机自启）"
        } catch {
            Write-Err "sshd 启动失败: $($_.Exception.Message)"
            # v7.2: 自动收集失败原因（SCM / OpenSSH 日志 / 应用崩溃 / sshd.log）—— 见文件头 v7.2【1】
            try {
                Write-Host "    ---- 自动诊断（另见日志）----" -ForegroundColor DarkYellow
                $scm = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 60 -ErrorAction SilentlyContinue |
                         Where-Object { $_.Message -match 'sshd|OpenSSH' } | Select-Object -First 4)
                foreach ($e in $scm) { $m = ($e.Message -replace "`r?`n", ' '); Write-Host ("    [SCM $($e.Id)] $m") -ForegroundColor DarkYellow; Log "SCM $($e.Id): $m" }
                $ops = @(Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 8 -ErrorAction SilentlyContinue)
                foreach ($e in $ops) { $m = ($e.Message -replace "`r?`n", ' '); Write-Host ("    [OpenSSH $($e.Id)] $m") -ForegroundColor DarkYellow; Log "OpenSSH $($e.Id): $m" }
                $app = @(Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 20 -ErrorAction SilentlyContinue |
                         Where-Object { $_.Message -match 'sshd' } | Select-Object -First 2)
                foreach ($e in $app) { $m = ($e.Message -split "`r?`n")[0]; Write-Host ("    [AppCrash] $m") -ForegroundColor DarkYellow; Log "AppCrash: $m" }
                $sl = Join-Path $env:ProgramData 'ssh\logs\sshd.log'
                if (Test-Path -LiteralPath $sl) {
                    $tail = @(Get-Content -LiteralPath $sl -Tail 8 -ErrorAction SilentlyContinue)
                    if ($tail.Count) { Write-Host "    [sshd.log 末尾]" -ForegroundColor DarkYellow; $tail | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
                }
                # v7.3: 服务配置快照（ImagePath / 账户 / 依赖）
                $qc = & sc.exe qc sshd 2>&1 | Out-String
                $qcLines = @(($qc -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -First 12)
                if ($qcLines.Count) { Write-Host "    [sc qc sshd]"; $qcLines | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
                # v7.3: 决定性诊断 —— 前台运行 sshd -d -e 3 秒捕获真实报错
                # （服务秒退且无事件日志时，stderr 是唯一线索；SCM 会把它丢弃）
                $dbgOut = Join-Path $env:TEMP 'sshd-debug-out.txt'
                $dbgErr = Join-Path $env:TEMP 'sshd-debug-err.txt'
                Remove-Item $dbgOut, $dbgErr -Force -ErrorAction SilentlyContinue
                $dbg = Start-Process -FilePath $sshdExe -ArgumentList @('-d', '-e') -RedirectStandardOutput $dbgOut -RedirectStandardError $dbgErr -WindowStyle Hidden -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 3
                $adminProbeOk = $false
                if ($dbg -and -not $dbg.HasExited) {
                    $adminProbeOk = $true
                    $dbg.Kill()
                    Write-Host "    [探针1 管理员] sshd -d -e 启动正常（3 秒未退出）→ 继续用 SYSTEM 上下文复测" -ForegroundColor DarkYellow
                    Log "probe1 admin: running fine 3s"
                } else {
                    $lines = @(Get-Content $dbgOut, $dbgErr -ErrorAction SilentlyContinue | Where-Object { $_ })
                    if ($lines.Count) {
                        Write-Host "    [探针1 管理员 — 真实启动报错]" -ForegroundColor DarkYellow
                        $lines | Select-Object -Last 10 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow; Log "sshd-dbg: $_" }
                    } else {
                        Write-Host ("    [探针1 管理员] 无输出退出（ExitCode=" + $dbg.ExitCode + "）—— 典型为进程被拦截或依赖缺失") -ForegroundColor DarkYellow
                    }
                }
                # v7.3 探针 2: SYSTEM 上下文复测（服务的真实运行身份）——
                # 覆盖「管理员能跑、SYSTEM 跑不了」的权限/上下文类故障
                if ($adminProbeOk) {
                    try {
                        $wrapCmd = Join-Path $env:ProgramData 'ssh\probe-system.cmd'
                        $wrapOut = Join-Path $env:ProgramData 'ssh\probe-system.txt'
                        [IO.File]::WriteAllText($wrapCmd, ('@echo off' + "`r`n" + '"' + $sshdExe + '" -d -e > "' + $wrapOut + '" 2>&1' + "`r`n"), (New-Object Text.ASCIIEncoding))
                        Remove-Item -LiteralPath $wrapOut -Force -ErrorAction SilentlyContinue
                        & schtasks.exe /create /tn 'OpSshProbe' /tr $wrapCmd /sc once /st 00:00 /ru SYSTEM /f 2>&1 | Out-Null
                        & schtasks.exe /run /tn 'OpSshProbe' 2>&1 | Out-Null
                        Start-Sleep -Seconds 3
                        & schtasks.exe /end /tn 'OpSshProbe' 2>&1 | Out-Null
                        & schtasks.exe /delete /tn 'OpSshProbe' /f 2>&1 | Out-Null
                        $sys = @(Get-Content -LiteralPath $wrapOut -ErrorAction SilentlyContinue)
                        $sysOk = @($sys | Where-Object { $_ -match 'Server listening' }).Count -gt 0
                        if ($sysOk) {
                            Write-Host "    [探针2 SYSTEM] sshd 在 SYSTEM 上下文正常监听 → 配置/密钥/权限/服务本身均正常，强烈指向安全软件/策略拦截服务启动" -ForegroundColor DarkYellow
                            Log "probe2 SYSTEM: listening OK"
                        } elseif ($sys.Count) {
                            Write-Host "    [探针2 SYSTEM 输出 — 服务同身份的真实报错]" -ForegroundColor DarkYellow
                            $sys | Select-Object -Last 10 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow; Log "sshd-sysprobe: $_" }
                        } else {
                            Write-Host "    [探针2 SYSTEM] 无输出（任务可能被策略/安全软件阻止执行）" -ForegroundColor DarkYellow
                            Log "probe2 SYSTEM: no output"
                        }
                    } catch { Log "system probe failed: $($_.Exception.Message)" }
                }
            } catch { }
            if ($script:RebootPending) {
                Write-Warn "本机处于待重启状态（RebootPending）：CBS 事务未完成时 OpenSSH 服务可能拒绝启动 —— 建议先重启系统再重跑本脚本"
            }
            Write-Host "    排查: & `"$sshdExe`" -t ; sc.exe qc sshd ; Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20" -ForegroundColor DarkGray
            # 自动重试一次（若服务确实未运行，先清掉探针可能留下的 sshd 进程再重试）
            if ((Get-Service -Name sshd -ErrorAction SilentlyContinue).Status -ne 'Running') {
                Get-Process -Name sshd -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Milliseconds 800
            try {
                Start-Service -Name sshd -ErrorAction Stop
                Write-Ok "sshd 已启动（重试成功）"
            } catch {
                Write-Err "sshd 仍无法启动: $($_.Exception.Message)"
                End-Step; exit 1
            }
        }
    } else { Write-Err "无法创建/找到 sshd 服务"; End-Step; exit 1 }
    End-Step
}

# ============================================================
# 步骤 7/8: 客户端配置（密钥 + ssh-agent）
# ============================================================
Show-Step -Title "客户端配置（密钥 / ssh-agent）" -Expect "十几秒" -Hint "生成密钥对、修正 ACL、配置 ssh-agent"

if (-not (Test-Path $script:SshDir)) {
    New-Item -ItemType Directory -Force -Path $script:SshDir | Out-Null
    Write-Ok "已创建 $script:SshDir"
}
try {
    # v4 修复：.ssh 目录必须同时给 SYSTEM 与 Administrators。
    # 只给用户本人时，sshd 的鉴权子进程连目录都无法穿越，读不到 authorized_keys。
    & icacls.exe $script:SshDir /inheritance:r 2>&1 | Out-Null
    & icacls.exe $script:SshDir /grant:r "${env:USERNAME}:(OI)(CI)F" 2>&1 | Out-Null
    & icacls.exe $script:SshDir /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
} catch { }

if (-not $NoKeygen) {
    foreach ($k in @(@{t='ed25519'; b=0;    f='id_ed25519'}, @{t='rsa'; b=4096; f='id_rsa'})) {
        $kp = Join-Path $script:SshDir $k.f
        if (Test-Path -LiteralPath $kp) {
            $c = Get-PrivateKeyCipher $kp
            if ($c -and $c -ne 'none') {
                # v7: 历史遗留 —— 旧版脚本在 pwsh7 下把 "" 当口令，密钥被加密，ssh/ssh-add 会要口令。
                # 不自动重建：该公钥可能已授权到其它服务器，重建等于更换身份。
                Write-Warn "现有私钥 $($k.f) 带口令（cipher=$c，疑旧版脚本 pwsh7 下生成），密钥自检将失败。"
                Write-Host "        如需无口令密钥：先备份 $kp 及其 .pub，删除后重跑本脚本（注意已分发的公钥授权需重新配置）。" -ForegroundColor DarkYellow
            } else {
                Write-Host "    已存在密钥: $($k.f)" -ForegroundColor DarkGray
            }
            continue
        }
        try {
            if (New-EmptyPassphraseKey -KeyType $k.t -KeyPath $kp -Bits ([int]$k.b) -Comment "$env:USERNAME@$env:COMPUTERNAME") {
                Write-Ok "已生成 $($k.f)"
            } else {
                Write-Warn "生成 $($k.f) 失败（见日志）"
            }
        } catch { Write-Warn "生成 $($k.f) 失败: $($_.Exception.Message)" }
    }
    # 修正私钥 ACL，否则 ssh 报 UNPROTECTED PRIVATE KEY FILE
    foreach ($k in @('id_ed25519','id_rsa')) {
        $kp = Join-Path $script:SshDir $k
        if (Test-Path $kp) {
            & icacls.exe $kp /inheritance:r 2>&1 | Out-Null
            & icacls.exe $kp /grant:r "${env:USERNAME}:(R)" 2>&1 | Out-Null
        }
    }
    Write-Ok "私钥 ACL 已收紧（仅当前用户可读）"
}

# v6: 密钥对刚在第 8 步生成 —— 第 4/6 步执行时公钥可能还不存在（全新机器首次运行），
# 在此为相关用户补写 authorized_keys，否则第 9 步密钥登录自检必然失败。
# 幂等：公钥已在文件里时不会重复追加。
if (Test-Path (Join-Path $script:SshDir 'id_ed25519.pub')) {
    $keyUsers = @($env:USERNAME, $script:UserReady) | Where-Object { $_ } | Select-Object -Unique
    foreach ($u in $keyUsers) {
        $pkPaths = @(Add-PublicKeyToUser -UserName $u)
        if ($pkPaths.Count) {
            Write-Ok "公钥已写入用户 $u 的 authorized_keys"
            $pkPaths | ForEach-Object { Write-Host "      -> $_" -ForegroundColor DarkGray }
        }
    }
}

$agent = Get-Service ssh-agent -ErrorAction SilentlyContinue
if ($agent) {
    if (-not $isAdmin) {
        Write-Host "    ssh-agent 服务需管理员权限才能改为自动启动（当前已跳过）" -ForegroundColor DarkGray
    } else {
        try {
            Set-Service ssh-agent -StartupType Automatic -ErrorAction Stop
            Start-Service ssh-agent -ErrorAction SilentlyContinue
            Write-Ok "ssh-agent 已设为自动启动并运行"
            # v5 修复：这里原本传的是「公钥文件的内容」，而 ssh-add 需要的是
            # 「私钥文件的路径」。参数类型都不对，且输出被 Out-Null 吞掉，
            # 于是一直静默失败 —— 表现为 ssh-add -l 永远 "The agent has no identities"。
            $privKey = Join-Path $script:SshDir 'id_ed25519'
            if (Test-Path $privKey) {
                $privCipher = Get-PrivateKeyCipher $privKey
                if ($privCipher -and $privCipher -ne 'none') {
                    # v7.1: 带口令私钥会让 ssh-add 交互索要口令，无人值守下会悬挂
                    Write-Warn "跳过 ssh-add：私钥带口令（$privCipher），无人值守运行会卡在口令提示"
                } else {
                    # v6: 同自检，2>&1 的 stderr 会带 NativeCommandError 装饰，转纯文本
                    $addOut = @(& ssh-add.exe $privKey 2>&1 | ForEach-Object { "$_" }) -join "`n"
                    Log "ssh-add: $($addOut.Trim())"
                    $agentList = @(& ssh-add.exe -l 2>&1 | ForEach-Object { "$_" }) -join "`n"
                    if ($agentList -match 'no identities|没有') {
                        Write-Warn "ssh-add 未成功加入密钥: $($addOut.Trim())"
                    } else {
                        Write-Host "    代理中的密钥: $($agentList.Trim())" -ForegroundColor DarkGray
                    }
                }
            }
        } catch { Write-Warn "配置 ssh-agent 失败: $($_.Exception.Message)" }
    }
} else { Write-Warn "未找到 ssh-agent 服务" }
End-Step

# ============================================================
# 步骤 8/8: 验证 + 输出（v7 起总步数动态：正常 8 步 / 预检卸载 2 步 / 客户端 4 步）
# ============================================================
Show-Step -Title "验证与输出" -Expect "几秒" -Hint "端口监听 + 回环连接 + 汇总连接信息"

if (-not $ClientOnly) {
    Start-Sleep -Seconds 2
    $listening = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if ($listening.Count -gt 0) { Write-Ok "端口 $Port 正在监听 ($($listening.Count) 个监听)" }
    else { Write-Warn "未检测到端口 $Port 监听" }

    $tcpOk = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($tcpOk) { Write-Ok "TCP 回环连接成功 (127.0.0.1:$Port)" } else { Write-Err "TCP 回环连接失败" }

    # v5 新增：真实密钥登录自检 —— 这是整套脚本里最有价值的一步。
    # TCP 能通不代表能登录：本机曾出现 TCP 测试全绿、公钥鉴权却全挂的情况，
    # 根因是 authorized_keys 的 ACL 缺少 SYSTEM/Administrators。
    # 有这一步，同类问题会在安装当场暴露并给出确切修法，而不是留到用户第一次连接时才炸。
    $loginUser = if ($script:UserReady) { $script:UserReady } else { $env:USERNAME }
    $privKey   = Join-Path $script:SshDir 'id_ed25519'
    if (Test-Path $privKey) {
        Write-Host "    密钥登录自检中（$loginUser@127.0.0.1 -p $Port）..." -ForegroundColor DarkGray
        $ssArgs = @('-i', $privKey, '-o','BatchMode=yes','-o','StrictHostKeyChecking=no',
                    '-o','UserKnownHostsFile=NUL','-o','LogLevel=ERROR','-o','ConnectTimeout=10','-p',"$Port",
                    "$loginUser@127.0.0.1", 'echo SSH_SELFTEST_OK')
        # v6: 2>&1 捕获的原生 stderr 会变成带装饰的 ErrorRecord（NativeCommandError 噪音），
        # 用 "$_" 转纯文本，失败提示里只保留有效信息
        $lt = @(& ssh.exe @ssArgs 2>&1 | ForEach-Object { "$_" }) -join "`n"
        if ($LASTEXITCODE -eq 0 -and $lt -match 'SSH_SELFTEST_OK') {
            Write-Ok "密钥登录自检通过"
        } else {
            Write-Err "密钥登录自检失败（端口通，但登不上）"
            Write-Host "      按下列顺序排查:" -ForegroundColor DarkYellow
            Write-Host "      1) authorized_keys 或 .ssh 目录的 ACL 缺少 SYSTEM / Administrators。" -ForegroundColor DarkYellow
            Write-Host "         Windows 上 sshd 的鉴权子进程以特权身份读该文件，而 SYSTEM 不像" -ForegroundColor DarkYellow
            Write-Host "         Linux root 那样绕过 ACL，缺读权限即报 publickey 失败。修复:" -ForegroundColor DarkYellow
            Write-Host "         icacls `"$env:USERPROFILE\.ssh`" /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'" -ForegroundColor DarkYellow
            Write-Host "      2) sshd_config 是否残留 Match Group administrators 块（本机会崩溃）。" -ForegroundColor DarkYellow
            Write-Host "      3) 账号是否启用: Get-LocalUser -Name '$loginUser'" -ForegroundColor DarkYellow
            Write-Host "      原始输出: $($lt.Trim())" -ForegroundColor DarkGray
            Log "selftest failed: $($lt.Trim())"
        }
    } else {
        Write-Host "    跳过登录自检（未找到私钥 $privKey）" -ForegroundColor DarkGray
    }

    # v2: 抓取本机指纹，方便客户端 known_hosts 核对
    try {
        $fp = & ssh-keygen.exe -lf (Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key') 2>&1 | Out-String
        if ($fp.Trim()) { Write-Host "    本机主机密钥指纹: $($fp.Trim())" -ForegroundColor DarkGray }
    } catch { }
}

$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object -ExpandProperty IPAddress -Unique)

Write-Host ""
Write-Host "================ 连接信息 ================" -ForegroundColor Cyan
if ($ips.Count -gt 0) { Write-Host "本机 IPv4 : $($ips -join ', ')" }
Write-Host "计算机名  : $env:COMPUTERNAME"
Write-Host "当前用户  : $env:USERNAME"
if (-not $ClientOnly) {
    Write-Host "SSH 端口  : $Port"
    Write-Host "客户端    : $((Get-Command ssh.exe -ErrorAction SilentlyContinue).Source)"
    Write-Host "客户端版本: $(& ssh.exe -V 2>&1 | Select-Object -First 1)"
    Write-Host ""
    if ($script:UserReady) {
        Write-Host "可登录账号: $script:UserReady" -ForegroundColor Green
        Write-Host "连接命令  : ssh $script:UserReady@<本机IP> -p $Port"
        if ($AddSshUser) {
            $pwShown = if ($script:RandomPassword) { $script:RandomPassword } else { $SshUserPassword }
            if ($pwShown) { Write-Host "账号口令  : $pwShown   （建议首次登录后修改）" -ForegroundColor Yellow }
        }
    } elseif ($script:AdminReady) {
        Write-Host "可登录账号: Administrator" -ForegroundColor Green
        Write-Host "连接命令  : ssh Administrator@<本机IP> -p $Port"
    } else {
        Write-Host "连接命令  : ssh $env:USERNAME@<本机IP> -p $Port" -ForegroundColor Green
    }
    if (-not $SkipAccount -and -not $script:AdminReady -and -not $script:UserReady) {
        Write-Host "提示      : 微软账号不能直接用于 SSH 密码登录，请用密钥登录" -ForegroundColor DarkGray
    }
}
Write-Host "密钥目录  : $script:SshDir"
if ($script:RandomPassword) {
    Write-Host "随机密码  : $script:RandomPassword  （请立即保存）" -ForegroundColor Yellow
}
Write-Host "日志文件  : $script:LogPath" -ForegroundColor DarkGray
Write-Host "=========================================" -ForegroundColor Cyan
End-Step

Write-Host ""
Write-Host "[+] 完成。首次连接若提示确认指纹，输入 yes。" -ForegroundColor Green
exit 0
