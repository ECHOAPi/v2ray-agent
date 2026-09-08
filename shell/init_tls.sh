#!/usr/bin/env bash
installType='yum -y install'
removeType='yum -y remove'
upgrade="yum -y update"
echoType='echo -e'
tlsBackupDir=''
tlsChallengeConfig=''
tlsCertificateDir=''
tlsRestoreNeeded=0
tlsKeepCertificates=0
tlsTemporaryNginxRunning=0
tlsNginxNeedsRestart=0
tlsLockHeld=0
# 打印
echoColor(){
    case $1 in
        # 红色
        "red")
            ${echoType} "\033[31m$2 \033[0m"
        ;;
        # 天蓝色
        "skyBlue")
            ${echoType} "\033[36m$2 \033[0m"
        ;;
        # 绿色
        "green")
            ${echoType} "\033[32m$2 \033[0m"
        ;;
        # 白色
        "white")
            ${echoType} "\033[37m$2 \033[0m"
        ;;
        "magenta")
            ${echoType} "\033[31m$2 \033[0m"
        ;;
        "skyBlue")
            ${echoType} "\033[36m$2 \033[0m"
        ;;
        # 黄色
        "yellow")
            ${echoType} "\033[33m$2 \033[0m"
        ;;
    esac
}
# 选择系统执行工具
checkSystem(){

	if [[ ! -z `find /etc -name "redhat-release"` ]] || [[ ! -z `cat /proc/version | grep -i "centos" | grep -v grep ` ]] || [[ ! -z `cat /proc/version | grep -i "red hat" | grep -v grep ` ]] || [[ ! -z `cat /proc/version | grep -i "redhat" | grep -v grep ` ]]
	then
		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y"
	elif [[ ! -z `cat /etc/issue | grep -i "debian" | grep -v grep` ]] || [[ ! -z `cat /proc/version | grep -i "debian" | grep -v grep` ]]
    then
		release="debian"
		installType='apt -y install'
		upgrade="apt update -y"
		removeType='apt -y autoremove'
	elif [[ ! -z `cat /etc/issue | grep -i "ubuntu" | grep -v grep` ]] || [[ ! -z `cat /proc/version | grep -i "ubuntu" | grep -v grep` ]]
	then
		release="ubuntu"
		installType='apt -y install'
		upgrade="apt update -y"
		removeType='apt --purge remove'
    fi
    if [[ -z ${release} ]]
    then
        echoContent red "本脚本不支持此系统，请将下方日志反馈给开发者"
        cat /etc/issue
        cat /proc/version
        exit 0;
    fi
}
# 安装工具包
installTools(){
    echoColor yellow "更新"
    ${upgrade}
    if [[ -z `find /usr/bin/ -executable -name "socat"` ]]
    then
        echoColor yellow "\nsocat未安装，安装中\n"
        ${installType} socat >/dev/null
        echoColor green "socat安装完毕"
    fi
    echoColor yellow "\n检测是否安装Nginx"
    if [[ -z `find /sbin/ -executable -name 'nginx'` ]]
    then
        echoColor yellow "nginx未安装，安装中\n"
        ${installType} nginx >/dev/null
        echoColor green "nginx安装完毕"
    else
        echoColor green "nginx已安装\n"
    fi
    echoColor yellow "检测是否安装acme.sh"
    if [[ -z `find ~/.acme.sh/ -name "acme.sh"` ]]
    then
        echoColor yellow "\nacme.sh未安装，安装中\n"
        curl -s https://get.acme.sh | sh >/dev/null
        echoColor green "acme.sh安装完毕\n"
    else
        echoColor green "acme.sh已安装\n"
    fi

}
# Only root-controlled, non-symlink directories may hold privileged backups.
tlsTrustedPath() {
    local path=$1 details owner mode
    [[ ! -L "$path" ]] || return 1
    details=$(stat -c '%u %a' -- "$path") || return 1
    read -r owner mode <<< "$details"
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 0022) == 0 ))
}

# A dedicated helper lock serializes temporary Nginx edits without blocking the
# port policy daemon. Keep its inode after release so waiters use the same lock.
tlsAcquireLock() {
    local lockPath=/etc/nginx/.v2ray-agent-tls.lock details
    command -v flock >/dev/null 2>&1 || {
        echoColor red "缺少 flock，无法安全锁定 TLS 配置操作"
        return 1
    }
    if [[ ! -e "$lockPath" && ! -L "$lockPath" ]]; then
        (umask 077; set -o noclobber; : > "$lockPath") 2>/dev/null || :
    fi
    if [[ ! -f "$lockPath" || -L "$lockPath" ]]; then
        echoColor red "拒绝使用不安全的 TLS 锁文件：$lockPath"
        return 1
    fi
    details=$(stat -c '%u %a %h' -- "$lockPath") || return 1
    if [[ "$details" != '0 600 1' ]]; then
        echoColor red "TLS 锁文件必须是 root 拥有、权限 600 的单链接普通文件"
        return 1
    fi
    exec 8<> "$lockPath" || return 1
    if ! flock -n -x 8; then
        exec 8>&-
        echoColor red "另一个 TLS 辅助脚本正在运行，请等待其完成后重试"
        return 1
    fi
    tlsLockHeld=1
}

# 恢复本次运行创建的备份；恢复失败时保留私有备份供管理员处理。
resetNginxConfig() {
    local status=0
    if [[ "$tlsRestoreNeeded" == 1 ]]; then
        if ! cp -p -- "$tlsBackupDir/nginx.conf" "$tlsBackupDir/restore.conf" ||
            ! mv -f -- "$tlsBackupDir/restore.conf" /etc/nginx/nginx.conf; then
            echoColor red "恢复 Nginx 配置失败，备份保留在：$tlsBackupDir"
            status=1
        else
            tlsRestoreNeeded=0
        fi
    fi
    if [[ -n "$tlsChallengeConfig" ]]; then
        if rm -f -- "$tlsChallengeConfig"; then
            tlsChallengeConfig=''
        else
            status=1
        fi
    fi
    return "$status"
}

tlsCleanup() {
    local status=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [[ "$tlsTemporaryNginxRunning" == 1 ]]; then
        nginx -s quit 8>&- || status=1
        tlsTemporaryNginxRunning=0
    fi
    if resetNginxConfig; then
        if [[ "$tlsNginxNeedsRestart" == 1 ]]; then
            nginx 8>&- || status=1
            tlsNginxNeedsRestart=0
        fi
        if [[ -n "$tlsBackupDir" ]]; then
            rm -rf -- "$tlsBackupDir" || status=1
        fi
    else
        status=1
    fi
    if [[ -n "$tlsCertificateDir" && "$tlsKeepCertificates" != 1 ]]; then
        rm -rf -- "$tlsCertificateDir" || status=1
    fi
    if [[ "$tlsLockHeld" == 1 ]]; then
        flock -u 8 || status=1
        exec 8>&-
        tlsLockHeld=0
    fi
    exit "$status"
}

# 备份目录不使用公共 /tmp，也不复用前一次运行的备份。
bakConfig() {
    local path
    if (( EUID != 0 )); then
        echoColor red "请使用 root 运行此脚本"
        return 1
    fi
    for path in /etc /etc/nginx /etc/nginx/conf.d; do
        if [[ ! -d "$path" ]] || ! tlsTrustedPath "$path"; then
            echoColor red "拒绝使用非 root 私有管理的目录：$path"
            return 1
        fi
    done
    if [[ ! -f /etc/nginx/nginx.conf ]] || ! tlsTrustedPath /etc/nginx/nginx.conf; then
        echoColor red "Nginx 主配置必须是 root 拥有且不可由其他用户写入的普通文件"
        return 1
    fi
    trap tlsCleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    tlsAcquireLock || return 1
    tlsBackupDir=$(mktemp -d /etc/nginx/.v2ray-agent-tls.XXXXXXXXXX) || return 1
    cp -p -- /etc/nginx/nginx.conf "$tlsBackupDir/nginx.conf" || return 1
    tlsRestoreNeeded=1
}
# 安装证书
installTLS(){
    echoColor yellow "请输入域名【例:blog.v2ray-agent.com】："
    read -r domain || return 1
    if [[ ! "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || ${#domain} -gt 253 ]]; then
        echoColor red "请填写有效的域名\n"
        return 1
    fi
    # 备份
    bakConfig || return 1
    # 替换原始文件中的域名
    sed -i "s/${domain//./\\.}/X655Y0M9UM9/g" /etc/nginx/nginx.conf || return 1
    tlsChallengeConfig=$(mktemp /etc/nginx/conf.d/v2ray-agent-acme.XXXXXXXXXX.conf) || return 1
    printf '%s\n' "server {listen 80;server_name ${domain};root /usr/share/nginx/html;location ~ /.well-known {allow all;}location /test {return 200 '5NX2O9XQKP';}}" > "$tlsChallengeConfig" || return 1
    if [[ ! -z `ps -ef|grep -v grep|grep nginx` ]]
    then
        tlsNginxNeedsRestart=1
        nginx -s quit 8>&- || return 1
        sleep 0.5
    fi
    tlsTemporaryNginxRunning=1
    nginx 8>&- || return 1
    echoColor yellow "\n验证域名以及服务器是否可用"
    if [[ ! -z $(curl -fsS -- "http://${domain}/test" 8>&- | grep 5NX2O9XQKP) ]]
    then
        nginx -s quit 8>&- || return 1
        tlsTemporaryNginxRunning=0
        sleep 0.5
        echoColor green "服务可用，生成TLS中，请等待\n"
    else
        echoColor red "服务不可用请检测dns配置是否正确"
        return 1
    fi
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 >/dev/null 8>&- || return 1
    tlsCertificateDir=$(mktemp -d /etc/nginx/v2ray-agent-tls-certificates.XXXXXXXXXX) || return 1
    ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath "$tlsCertificateDir/$domain.crt" --keypath "$tlsCertificateDir/$domain.key" --ecc >/dev/null 8>&- || return 1
    if [[ ! -s "$tlsCertificateDir/$domain.key" ]]; then
        echoColor red "证书key生成失败，请重新运行"
        return 1
    elif [[ ! -s "$tlsCertificateDir/$domain.crt" ]]; then
        echoColor red "证书crt生成失败，请重新运行"
        return 1
    fi
    chmod 600 -- "$tlsCertificateDir/$domain.key" "$tlsCertificateDir/$domain.crt" || return 1
    tlsKeepCertificates=1
    resetNginxConfig || return 1
    if [[ "$tlsNginxNeedsRestart" == 1 ]]; then
        nginx 8>&- || return 1
        tlsNginxNeedsRestart=0
    fi
    echoColor green "证书生成成功"
    echoColor green "证书目录：$tlsCertificateDir"
    ls -- "$tlsCertificateDir"
}

init(){
    echoColor red "\n=============================="
    echoColor yellow "此脚本注意事项"
    echoColor green "   1.会安装依赖所需依赖"
    echoColor green "   2.会把Nginx配置文件备份"
    echoColor green "   3.会安装Nginx、acme.sh，如果已安装则使用已经存在的"
    echoColor green "   4.安装完毕、失败或收到可捕获的退出信号时自动恢复备份"
    echoColor green "   5.执行期间请不要重启机器"
    echoColor green "   6.证书保留在 /etc/nginx 下本次运行的私有目录，请注意留存"
    echoColor green "   7.每次运行独立备份，恢复成功后清理临时备份；恢复失败时保留"
    echoColor green "   8.证书默认ec-256"
    echoColor green "   9.下个版本会加入通配符证书生成[todo]"
    echoColor green "   10.可以生成多个不同域名的证书[包含子域名]，具体速率请查看[https://letsencrypt.org/zh-cn/docs/rate-limits/]"
    echoColor green "   11.兼容Centos、Ubuntu、Debian"
    echoColor green "   12.Github[https://github.com/mack-a]"
    echoColor red "=============================="
    echoColor yellow "请输入[y]执行脚本，[任意]结束:"
    read isExecStatus
    if [[ ${isExecStatus} = "y" ]]
    then
        installTools
        installTLS
    else
        echoColor green "欢迎下次使用"
        exit
    fi
}
checkSystem
init
