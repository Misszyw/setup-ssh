#!/usr/bin/env bash
#
# setup-ssh.sh — 自动识别 Linux 发行版，安装 openssh-server，开放端口并保证可直连
# 用法:
#   sudo bash setup-ssh.sh                            # 全自动：安装 + 启动 + 防火墙 + 验证
#   sudo bash setup-ssh.sh --port=2222                # 自定义 SSH 端口（--port 2222 亦可）
#   sudo bash setup-ssh.sh --no-firewall              # 跳过防火墙配置
#   sudo bash setup-ssh.sh --root-login[=密码]         # 启用 root 密码登录（可选指定密码）
#   sudo bash setup-ssh.sh --create-user=名称[:密码]    # 创建可登录用户（可选指定密码）
#
# 覆盖发行版（自动检测）:
#   Debian/Ubuntu/Raspbian, RHEL/CentOS/Rocky/Alma/Fedora/openEuler,
#   openSUSE/SLES, Arch, Alpine, Amazon Linux, Alibaba Cloud Linux
#
# 防火墙后端（按可用性自动选择）:
#   ufw / firewalld / nftables / iptables(IPv4+IPv6)
#
# 需要 bash（Alpine 等最小系统请先: apk add bash）
#

set -euo pipefail

# ---------- 参数 ----------
PORT=22
SKIP_FIREWALL=0
CREATE_USER_ARG=""
ROOT_LOGIN_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            if [[ $# -lt 2 ]]; then
                echo "[!] --port 缺少端口号参数" >&2; exit 2
            fi
            PORT="$2"; shift 2 ;;
        --port=*)      PORT="${1#--port=}"; shift ;;
        --no-firewall) SKIP_FIREWALL=1; shift ;;
        --root-login)  ROOT_LOGIN_ARG="auto"; shift ;;
        --root-login=*) ROOT_LOGIN_ARG="${1#--root-login=}"; shift ;;
        --create-user=*) CREATE_USER_ARG="${1#--create-user=}"; shift ;;
        -h|--help)
            sed -n '2,19p' "$0"; exit 0 ;;
        *) echo "[!] 未知参数: $1" >&2; exit 2 ;;
    esac
done

# ---------- 颜色 ----------
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_CYN=$'\033[36m'; C_MAG=$'\033[35m'; C_RST=$'\033[0m'
else
    C_RED=''; C_YEL=''; C_GRN=''; C_CYN=''; C_MAG=''; C_RST=''
fi

log()  { printf '%s[*]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_GRN"  "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
err()  { printf '%s[✗]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }

# ---------- 显示增强：步骤进度 / spinner 动画 / 计时 ----------
STEP_TOTAL=10
STEP_NUM=0
STEP_START=0

show_step() {
    # 显示“步骤 N/10 + 标题 + 预计耗时 + 说明”，并开始计时
    local title="$1" expect="$2" hint="$3"
    STEP_NUM=$((STEP_NUM + 1))
    STEP_START=$SECONDS
    printf '\n%s============================================================%s\n' "$C_MAG" "$C_RST"
    printf '%s  步骤 %s/%s: %s%s\n' "$C_MAG" "$STEP_NUM" "$STEP_TOTAL" "$title" "$C_RST"
    [[ -n "$expect" ]] && printf '    - 预计: %s\n' "$expect"
    [[ -n "$hint" ]]   && printf '    - 说明: %s\n' "$hint"
}

end_step() {
    printf '    - 耗时: %ss\n' "$(( SECONDS - STEP_START ))"
}

spinner() {
    # 在后台任务运行期间显示转圈动画；用法: spinner <pid> <提示文字>
    local pid=$1 msg=$2 i=0
    local spin=('|' '/' '-' '\')
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r%s ... %s ' "$msg" "${spin[i]}"
        i=$(( (i + 1) % 4 ))
        sleep 0.15
    done
    printf '\r%s ... 完成%-12s\n' "$msg" ""
}

# 端口号合法性校验（10# 强制十进制，避免 --port 08 被当八进制绕过）
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( 10#$PORT < 1 || 10#$PORT > 65535 )); then
    err "无效端口号: $PORT（应为 1-65535）"; exit 2
fi

[[ $EUID -eq 0 ]] || { err "需要 root 权限，请用 sudo 重试"; exit 1; }

# ============================================================
# 步骤 1/10: 自动识别系统与包管理器
# ============================================================
show_step "识别操作系统与包管理器" "几秒钟" "读取 /etc/os-release 判断发行版，自动选择 apt/dnf/yum/zypper/pacman/apk"

. /etc/os-release 2>/dev/null || . /usr/lib/os-release 2>/dev/null || true

ID="${ID:-unknown}"
ID_LIKE="${ID_LIKE:-}"
PRETTY_NAME="${PRETTY_NAME:-${ID}}"

fallback_kernel() {
    if [[ -f /etc/redhat-release ]]; then
        echo "rhel"; return
    fi
    if [[ -f /etc/debian_version ]]; then
        echo "debian"; return
    fi
    if [[ -f /etc/alpine-release ]]; then
        echo "alpine"; return
    fi
    if [[ -f /etc/arch-release ]]; then
        echo "arch"; return
    fi
    echo "unknown"
}

if [[ "$ID" == "unknown" ]]; then
    ID="$(fallback_kernel)"
fi

case "$ID" in
    debian|ubuntu|raspbian|linuxmint|kali|elementary|zorin|deepin|uos)
        FAMILY=debian ;;
    rhel|centos|rocky|almalinux|ol|fedora|nobara|amzn|amazon|almalinux9|opencloudos|openanolis|anolis|tencentos|tencentos-server|openEuler*|openeuler*)
        FAMILY=rhel ;;
    opensuse*|sles|suse)
        FAMILY=suse ;;
    arch|manjaro|endeavouros|garuda)
        FAMILY=arch ;;
    alpine)
        FAMILY=alpine ;;
    *)
        # 兜底：依据 ID_LIKE
        case "$ID_LIKE" in
            *debian*|*ubuntu*) FAMILY=debian ;;
            *rhel*|*fedora*|*centos*) FAMILY=rhel ;;
            *suse*)  FAMILY=suse ;;
            *arch*)  FAMILY=arch ;;
            *alpine*) FAMILY=alpine ;;
            *) err "无法识别此发行版（ID=$ID ID_LIKE=$ID_LIKE）"; exit 1 ;;
        esac ;;
esac

ok "识别结果: $PRETTY_NAME → 归类到 [$FAMILY] 家族"

# ---------- 包管理器 ----------
case "$FAMILY" in
    debian) PM="apt-get"; PM_UPDATE=1; PKG="openssh-server" ;;
    rhel)
        if command -v dnf >/dev/null 2>&1; then PM="dnf"; else PM="yum"; fi
        PM_UPDATE=0; PKG="openssh-server" ;;
    suse)   PM="zypper"; PM_UPDATE=1; PKG="openssh" ;;
    arch)   PM="pacman"; PM_UPDATE=1; PKG="openssh" ;;
    alpine) PM="apk";    PM_UPDATE=1; PKG="openssh-server" ;;
esac

log "本机包管理器: $PM，目标软件包: $PKG"
end_step

# ============================================================
# 步骤 2/10: 检查登录账号可用性（全新系统“直连”的前提）
# ============================================================
show_step "检查可用的 SSH 登录账号" "几秒钟" "若系统无任何带密码账号且无授权密钥，SSH 将无法直连，脚本会引导创建"

CREATE_USER=""
NEWUSER_PASS=""
ROOT_LOGIN=0
ROOT_PW_INPUT=""
RANDOM_PW=""

have_usable_account() {
    local pw=""
    pw=$(awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$pw" && "$pw" != "!"* && "$pw" != "*"* ]]; then
        return 0
    fi
    [[ -s /root/.ssh/authorized_keys ]] && return 0
    local uname x uid gid gecos home shell
    while IFS=: read -r uname x uid gid gecos home shell; do
        [[ "$uname" == "root" || "$uname" == "nobody" ]] && continue
        if (( uid >= 1000 )); then
            [[ -n "$shell" ]] || continue
            case "$shell" in
                */nologin|*/false) continue ;;
            esac
            pw=$(awk -F: -v u="$uname" '$1==u{print $2}' /etc/shadow 2>/dev/null || true)
            if [[ -n "$pw" && "$pw" != "!"* && "$pw" != "*"* ]]; then
                return 0
            fi
            [[ -s "$home/.ssh/authorized_keys" ]] && return 0
        fi
    done < /etc/passwd
    return 1
}

if [[ -n "$CREATE_USER_ARG" ]]; then
    CREATE_USER="${CREATE_USER_ARG%%:*}"
    [[ "$CREATE_USER_ARG" == *:* ]] && NEWUSER_PASS="${CREATE_USER_ARG#*:}"
fi
if [[ -n "$ROOT_LOGIN_ARG" ]]; then
    ROOT_LOGIN=1
    [[ "$ROOT_LOGIN_ARG" != "auto" ]] && ROOT_PW_INPUT="$ROOT_LOGIN_ARG"
fi

if ! have_usable_account && [[ -z "$CREATE_USER" && "$ROOT_LOGIN" -eq 0 ]]; then
    warn "未检测到可用的 SSH 登录账号（无密码账号/无授权密钥）"
    if [[ -t 0 ]]; then
        echo "请选择账号配置方式:"
        echo "  1) 创建新用户并设置密码（推荐）"
        echo "  2) 启用 root 密码登录"
        echo "  3) 跳过（我已配置好账号/密钥）"
        read -r -p "输入 1/2/3: " choice
        case "$choice" in
            1) read -r -p "新用户名: " CREATE_USER ;;
            2) ROOT_LOGIN=1 ;;
            *) warn "跳过账号配置，请确保存在可登录账号" ;;
        esac
    else
        err "全新系统没有可登录账号，SSH 将无法直连。请任选其一重新运行:"
        err "  sudo bash setup-ssh.sh --create-user=用户名[:密码]"
        err "  sudo bash setup-ssh.sh --root-login[=密码]"
        err "  或预先放置 SSH 公钥到目标用户 ~/.ssh/authorized_keys"
        exit 1
    fi
fi
end_step

# ============================================================
# 步骤 3/10: 安装 openssh-server（最长，需联网）
# ============================================================
show_step "安装 openssh-server" "1-5 分钟（需联网，受网络与软件源速度影响）" "通过 $PM 安装 $PKG；网络慢或源配置不佳时可先换国内镜像源"

install_via() {
    case "$FAMILY" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            if [[ $PM_UPDATE -eq 1 ]]; then
                "$PM" update -y >/dev/null 2>&1 &
                local upd_pid=$!
                spinner "$upd_pid" "正在更新软件源（$PM update）"
                wait "$upd_pid" 2>/dev/null || warn "apt-get update 失败，继续尝试安装"
            fi
            "$PM" install -y "$PKG" ;;
        rhel)
            # 只安装目标包，不做全量系统更新（避免耗时/意外升级），dnf/yum 安装时会自动获取元数据
            "$PM" -y install "$PKG" ;;
        suse)
            "$PM" --non-interactive refresh >/dev/null 2>&1 &
            local upd_pid=$!
            spinner "$upd_pid" "正在刷新软件源（zypper refresh）"
            wait "$upd_pid" 2>/dev/null || true
            "$PM" --non-interactive install "$PKG" ;;
        arch)
            # Arch 推荐做法：先完整升级再安装，避免部分升级导致依赖不一致
            "$PM" -Syu --noconfirm "$PKG" ;;
        alpine)
            "$PM" update >/dev/null 2>&1 &
            local upd_pid=$!
            spinner "$upd_pid" "正在更新软件源（apk update）"
            wait "$upd_pid" 2>/dev/null || true
            "$PM" add "$PKG" ;;
    esac
}

if command -v sshd >/dev/null 2>&1; then
    ok "openssh-server 已安装（sshd 路径: $(command -v sshd)）"
else
    log "通过 $PM 安装 $PKG ..."
    install_via
    command -v sshd >/dev/null 2>&1 || { err "安装后仍未找到 sshd"; exit 1; }
    ok "安装完成: $(command -v sshd)"
fi
end_step

# ============================================================
# 步骤 4/10: host key 生成（精简镜像/Alpine 常缺失，缺失时 sshd 拒绝启动）
# ============================================================
show_step "检查并生成 SSH host key" "几秒钟" "精简镜像常缺少 /etc/ssh/ssh_host_*_key，缺失时 sshd 会拒绝启动"

ensure_host_keys() {
    if ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
        return 0
    fi
    log "未发现 SSH host key，正在生成 ..."
    ssh-keygen -A || { err "生成 host key 失败"; exit 1; }
    ok "host key 已生成"
}
ensure_host_keys
end_step

# ============================================================
# 步骤 5/10: 创建用户 / 启用 root 登录
# ============================================================
show_step "配置登录账号（用户创建 / root 登录）" "几秒钟（交互输入密码看您的速度）" "按参数或上一步的选择创建用户或启用 root 密码登录；非交互环境自动生成随机密码"

get_or_create_password() {
    local supplied="$1" p1 p2
    if [[ -n "$supplied" ]]; then
        RANDOM_PW=""
        NEWPASS="$supplied"
        return 0
    fi
    if [[ -t 0 ]]; then
        read -r -s -p "输入密码: " p1; echo
        read -r -s -p "再次输入: " p2; echo
        if [[ -z "$p1" || "$p1" != "$p2" ]]; then
            err "密码为空或两次不一致"; exit 2
        fi
        RANDOM_PW=""
        NEWPASS="$p1"
    else
        # 注意：tr 可能因 head 提前关闭管道收到 SIGPIPE，需 || true 防止 set -o pipefail 中断
        NEWPASS=$(tr -dc 'A-Za-z0-9_@#%' < /dev/urandom 2>/dev/null | head -c 16 || true)
        [[ -n "$NEWPASS" ]] || NEWPASS="$(openssl rand -hex 8 2>/dev/null || echo "ssh$(date +%s)$RANDOM")"
        RANDOM_PW=1
    fi
}

if [[ -n "$CREATE_USER" ]]; then
    if [[ ! "$CREATE_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        err "非法用户名: $CREATE_USER（仅限小写字母/数字/_-）"; exit 2
    fi
    if ! id "$CREATE_USER" >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            if ! useradd -m -s /bin/bash "$CREATE_USER" >/dev/null 2>&1; then
                useradd -m -s /bin/sh "$CREATE_USER" >/dev/null 2>&1 || { err "创建用户 $CREATE_USER 失败"; exit 1; }
            fi
        else
            # Alpine/busybox：使用 adduser
            adduser -D -s /bin/sh -h "/home/$CREATE_USER" "$CREATE_USER" >/dev/null 2>&1 || { err "创建用户 $CREATE_USER 失败"; exit 1; }
            mkdir -p "/home/$CREATE_USER"
            chown -R "$CREATE_USER":"$CREATE_USER" "/home/$CREATE_USER" >/dev/null 2>&1 || true
        fi
        ok "用户 $CREATE_USER 已创建"
    else
        ok "用户 $CREATE_USER 已存在，将更新密码"
    fi
    for g in sudo wheel; do
        getent group "$g" >/dev/null 2>&1 || continue
        if command -v usermod >/dev/null 2>&1; then
            usermod -aG "$g" "$CREATE_USER" >/dev/null 2>&1 || true
        elif command -v adduser >/dev/null 2>&1; then
            adduser "$CREATE_USER" "$g" >/dev/null 2>&1 || true
        fi
    done
    NEWPASS=""
    get_or_create_password "$NEWUSER_PASS"
    if echo "$CREATE_USER:$NEWPASS" | chpasswd; then
        ok "用户 $CREATE_USER 密码已设置"
    else
        err "为用户 $CREATE_USER 设置密码失败"; exit 1
    fi
    if [[ "$RANDOM_PW" == "1" ]]; then
        log "已为用户 $CREATE_USER 生成随机密码: $NEWPASS（请立即保存）"
    fi
fi

if [[ "$ROOT_LOGIN" -eq 1 ]]; then
    NEWPASS=""
    get_or_create_password "$ROOT_PW_INPUT"
    if echo "root:$NEWPASS" | chpasswd; then
        ok "root 密码已设置"
    else
        err "设置 root 密码失败"; exit 1
    fi
    if [[ "$RANDOM_PW" == "1" ]]; then
        log "已为 root 生成随机密码: $NEWPASS（请立即保存）"
    fi
fi
end_step

# ============================================================
# 步骤 6/10: sshd 配置（端口 / root 登录）
# ============================================================
show_step "配置 sshd（端口 / root 登录）" "几秒钟" "修改 /etc/ssh/sshd_config（自动备份），并做 sshd -t 预检，失败自动回滚"

SSHD_CFG=/etc/ssh/sshd_config
SSHD_DROPIN_DIR=/etc/ssh/sshd_config.d

set_sshd_option() {
    local key="$1" val="$2" cfg="$3"
    if grep -qE "^[[:space:]]*${key}[[:space:]]+" "$cfg"; then
        sed -i.bak -E "s/^([[:space:]]*)${key}([[:space:]]+).*/\1${key}\2${val}/" "$cfg"
    else
        printf '\n%s %s\n' "$key" "$val" >> "$cfg"
    fi
}

comment_out_in_dropins() {
    local key="$1" f
    [[ -d "$SSHD_DROPIN_DIR" ]] || return 0
    for f in "$SSHD_DROPIN_DIR"/*.conf; do
        [[ -f "$f" ]] || continue
        if grep -qE "^[[:space:]]*${key}[[:space:]]+" "$f"; then
            sed -i.bak -E "s/^([[:space:]]*)${key}([[:space:]]+.*)$/\1#${key}\2/" "$f"
            warn "已注释 $f 中的 $key 配置"
        fi
    done
}

set_sshd_port() {
    comment_out_in_dropins Port
    if grep -qE "^[[:space:]]*Port[[:space:]]+" "$SSHD_CFG"; then
        sed -i.bak -E "s/^[[:space:]]*Port[[:space:]]+.*/Port $PORT/" "$SSHD_CFG"
    else
        printf '\nPort %s\n' "$PORT" >> "$SSHD_CFG"
    fi
    warn "已设置 sshd 监听端口 $PORT（备份: ${SSHD_CFG}.bak）"
}

set_sshd_port

if [[ "$ROOT_LOGIN" -eq 1 ]]; then
    comment_out_in_dropins PermitRootLogin
    set_sshd_option PermitRootLogin yes "$SSHD_CFG"
    ok "已启用 root 密码登录（PermitRootLogin yes）"
fi

# sshd 配置预检，失败则回滚（先确保 /run/sshd 存在，否则 sshd -t 会报 Missing privilege separation directory）
mkdir -p /run/sshd 2>/dev/null || true
if ! sshd -t >/dev/null 2>&1; then
    err "sshd 配置校验失败（sshd -t），正在回滚 ..."
    [[ -f "$SSHD_CFG.bak" ]] && cp -a "$SSHD_CFG.bak" "$SSHD_CFG"
    exit 1
fi
ok "sshd 配置校验通过"
end_step

# ============================================================
# 步骤 7/10: SELinux（RHEL 系 + 自定义端口）
# ============================================================
show_step "SELinux 处理（仅 RHEL 系 + 自定义端口需要）" "几秒钟" "SELinux Enforcing 时自定义端口需放行 ssh_port_t，否则 sshd 无法监听"

handle_selinux() {
    [[ "$FAMILY" == "rhel" && "$PORT" != "22" ]] || return 0
    command -v getenforce >/dev/null 2>&1 || return 0
    [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]] || return 0
    log "SELinux Enforcing：为端口 $PORT 添加 ssh_port_t 放行 ..."
    command -v semanage >/dev/null 2>&1 || "$PM" -y install policycoreutils-python-utils >/dev/null 2>&1 || true
    if ! command -v semanage >/dev/null 2>&1; then
        err "未找到 semanage，无法放行 SELinux 端口 $PORT，sshd 可能无法启动"
        err "请手动执行: $PM -y install policycoreutils-python-utils && semanage port -a -t ssh_port_t -p tcp $PORT"
        exit 1
    fi
    if semanage port -a -t ssh_port_t -p tcp "$PORT" >/dev/null 2>&1 || semanage port -m -t ssh_port_t -p tcp "$PORT" >/dev/null 2>&1; then
        ok "SELinux: 已放行端口 $PORT (ssh_port_t)"
    else
        err "SELinux 端口放行失败"; exit 1
    fi
}
handle_selinux
end_step

# ============================================================
# 步骤 8/10: 启动服务
# ============================================================
show_step "启动 SSH 服务" "几秒钟" "优先 systemd；无 systemd 时自动降级 OpenRC / SysVinit / 直接调用 sshd"

start_service() {
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        # Ubuntu/Debian 新版默认 ssh.socket 激活，先停用避免与 ssh.service 端口冲突
        if systemctl list-unit-files ssh.socket >/dev/null 2>&1; then
            systemctl disable --now ssh.socket >/dev/null 2>&1 || true
            warn "已停用 ssh.socket（避免端口冲突）"
        fi
        local unit="sshd.service"
        [[ "$FAMILY" == "debian" ]] && unit="ssh.service"
        systemctl enable --now "$unit" >/dev/null 2>&1 || true
        systemctl restart "$unit" >/dev/null 2>&1 || true
        if systemctl is-active --quiet "$unit"; then
            ok "systemd: $unit 已启动"
            return 0
        fi
        err "systemd 启动 $unit 失败，请查看: journalctl -u $unit -n 50"
        return 1
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-update add sshd default >/dev/null 2>&1 || true
        if rc-service sshd restart >/dev/null 2>&1; then
            if pgrep -x sshd >/dev/null 2>&1 || pgrep sshd >/dev/null 2>&1; then
                ok "OpenRC: sshd 已启动"
                return 0
            fi
            err "OpenRC 服务脚本返回成功，但 sshd 未在运行（可能端口被占用）"; return 1
        fi
        err "OpenRC 启动 sshd 失败"; return 1
    fi
    if command -v service >/dev/null 2>&1; then
        if service sshd restart >/dev/null 2>&1 || service ssh restart >/dev/null 2>&1; then
            if pgrep -x sshd >/dev/null 2>&1 || pgrep sshd >/dev/null 2>&1; then
                ok "SysVinit: sshd 重启完成"
                return 0
            fi
            err "SysVinit 服务脚本返回成功，但 sshd 未在运行（可能端口被占用）"; return 1
        fi
        err "SysVinit 启动 sshd 失败"; return 1
    fi
    if command -v sshd >/dev/null 2>&1; then
        mkdir -p /var/run/sshd
        local sbin
        sbin=$(command -v sshd)
        if pgrep -x sshd >/dev/null 2>&1 || pgrep sshd >/dev/null 2>&1; then
            # 已有 sshd 进程（可能是旧配置）：发 HUP 重载配置
            pkill -HUP sshd >/dev/null 2>&1 || true
            ok "已向现有 sshd 发送 HUP 重载配置"
            return 0
        fi
        "$sbin"
        sleep 1
        if pgrep -x sshd >/dev/null 2>&1 || pgrep sshd >/dev/null 2>&1; then
            ok "直接调用 sshd 启动"
            return 0
        fi
        err "直接调用 sshd 启动失败"; return 1
    fi
    err "找不到可用的 init 系统"; return 1
}

start_service || { err "SSH 服务启动失败，已中止（请检查上方日志）"; exit 1; }
end_step

# ============================================================
# 步骤 9/10: 防火墙放行
# ============================================================
show_step "防火墙放行 TCP $PORT" "几秒钟" "自动选择 ufw/firewalld/nftables/iptables 放行端口；云服务器还需在控制台安全组放行"

open_port() {
    local port="$1"
    if [[ "$SKIP_FIREWALL" -eq 1 ]]; then
        warn "已跳过防火墙配置（--no-firewall）"; return 0
    fi

    # ufw（Ubuntu/Debian）：存在即放行（未启用时仅写配置）
    if command -v ufw >/dev/null 2>&1; then
        if LANG=C ufw status 2>/dev/null | grep -qi "Status: active"; then
            if ufw allow "$port/tcp" >/dev/null 2>&1; then
                ok "ufw: 已放行 $port/tcp"; return 0
            fi
        elif ufw allow "$port/tcp" >/dev/null 2>&1; then
            ok "ufw: 已写入放行规则 $port/tcp（ufw 当前未启用）"
        fi
    fi

    # firewalld（RHEL/Fedora）
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
            if firewall-cmd --add-port="${port}/tcp" >/dev/null 2>&1; then
                ok "firewalld: 已放行 $port/tcp"; return 0
            fi
        fi
    fi

    # nftables（Alpine/Debian）：配置文件为 /etc/nftables.conf 或 /etc/nftables.nft
    if command -v nft >/dev/null 2>&1 && { [[ -f /etc/nftables.conf ]] || [[ -f /etc/nftables.nft ]]; }; then
        if nft list ruleset 2>/dev/null | grep -qE "tcp dport $port (accept|drop)"; then
            ok "nftables: $port/tcp 已在规则中"; return 0
        fi
        local targets="" t added=0
        targets=$(nft list ruleset 2>/dev/null | awk '
            /^table / { if (NF >= 3) t = $2 " " $3; else t = $2 }
            /^[[:space:]]*chain / { c = $2 }
            /hook input/ { print t, c }
        ' || true)
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            if nft insert rule $t tcp dport "$port" accept >/dev/null 2>&1; then
                added=1
            fi
        done <<< "$targets"
        if (( added )); then
            ok "nftables: 已放行 $port/tcp（插入到 input 链首）"
            warn "nftables 为运行时规则；如需持久化请执行: nft list ruleset > /etc/nftables.conf（Alpine 为 /etc/nftables.nft）"
            return 0
        fi
    fi

    # iptables 兜底（IPv4 + IPv6）
    local fw_ok=0
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
            fw_ok=1
        elif iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
            fw_ok=1
        else
            warn "iptables 插入规则失败（IPv4）"
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || warn "ip6tables 插入规则失败（IPv6）"
            fi
        fi
        # 持久化（尽力而为）
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        elif [[ -d /etc/sysconfig ]]; then
            command -v iptables-save >/dev/null 2>&1 && iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        fi
        if (( fw_ok )); then
            ok "iptables: 已放行 $port/tcp（IPv4/IPv6）"; return 0
        fi
    fi

    warn "未找到防火墙工具（ufw/firewalld/nftables/iptables）或放行未生效"
    warn "若为云服务器，请务必到云控制台安全组放行 $port/tcp"
}

open_port "$PORT"
end_step

# ============================================================
# 步骤 10/10: 验证与连接信息
# ============================================================
show_step "验证连通性并输出连接信息" "几秒钟" "检查端口监听与回环连接，汇总本机 IP 与连接命令"

sleep 1
log "验证 sshd 监听状态 ..."
FAIL=0
listening_ok=0
loop_ok=0

LISTEN_LINE=""
if command -v ss >/dev/null 2>&1; then
    LISTEN_LINE=$(ss -tlnp 2>/dev/null | grep -E ":${PORT}[[:space:]]" || true)
elif command -v netstat >/dev/null 2>&1; then
    LISTEN_LINE=$(netstat -tlnp 2>/dev/null | grep -E ":${PORT}[[:space:]]" || true)
fi

if [[ -n "$LISTEN_LINE" ]]; then
    listening_ok=1
    ok "sshd 正在端口 $PORT 上监听："
    printf '   %s\n' "$LISTEN_LINE"
else
    warn "未检测到端口 $PORT 的监听（继续回环连接测试确认）"
fi

log "回环连接测试 127.0.0.1:$PORT ..."
if command -v timeout >/dev/null 2>&1; then
    if timeout 3 bash -c "</dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        loop_ok=1
        ok "TCP 回环连接成功"
    else
        err "TCP 回环连接失败"
        loop_ok=0
    fi
else
    warn "无 timeout 命令，跳过回环连接测试"
    loop_ok=0
fi

# 仅当“监听未确认”且“回环连接失败”时才判定失败
if (( !listening_ok && !loop_ok )); then
    FAIL=1
fi

# 服务状态摘要
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    SVC=$([[ "$FAMILY" == "debian" ]] && echo "ssh.service" || echo "sshd.service")
    STATE=$(systemctl is-active "$SVC" 2>/dev/null || echo "unknown")
    log "systemd 状态: $SVC = $STATE"
fi

# 主机 IP（忽略失败，避免 set -e 假失败）
IPs=""
if command -v hostname >/dev/null 2>&1; then
    IPs=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]' | paste -sd' ' - || true)
fi
[[ -n "$IPs" ]] && log "本机 IP: $IPs"

# 登录账号提示
if [[ -n "$CREATE_USER" ]]; then
    ok "可登录账号: $CREATE_USER（密码已设置）"
    log "连接命令: ssh $CREATE_USER@<host> -p $PORT"
elif [[ "$ROOT_LOGIN" -eq 1 ]]; then
    ok "已启用 root 密码登录"
    log "连接命令: ssh root@<host> -p $PORT"
else
    log "连接命令: ssh user@<host> -p $PORT（请使用已有账号/密钥）"
fi

if (( FAIL )); then
    err "SSH 服务未能就绪，请检查上方错误信息"
    exit 1
fi

end_step

printf '\n%s%s%s\n' "$C_GRN" "SSH 服务已就绪。首次连接如提示确认 host key 指纹，输入 yes 即可。" "$C_RST"
