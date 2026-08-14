#!/bin/bash
#===============================================================================
# Bobcares Smart Server Audit Script (v4 - Team Checklist Aligned)
#   - Includes all v3 improvements (IP reputation, kernel env, KernelCare, etc.)
#   - NEW: Report reorganized into the 6 official audit categories:
#       1. Threat Protection   2. Software Updates   3. Server Health
#       4. Backup              5. Software Life Time 6. Proactive Defence
#   - NEW checks: backup schedule (daily/weekly/monthly), remote backup
#     destinations, last backup age & size, PHP disable_functions,
#     PHP EOL versions, malware scan results, rootkit scan results,
#     rDNS status, reboot procedure info
#===============================================================================
SCRIPT_DIR="/root/scripts"

mkdir -p "$SCRIPT_DIR"

SUMMARY_FILE="$SCRIPT_DIR/audit-smart-summary.md"
DETAILED_FILE="$SCRIPT_DIR/report-detailed.log"
FINDINGS_FILE="$SCRIPT_DIR/audit-findings.log"
DEBUG_LOG="$SCRIPT_DIR/audit-debug.log"

STATE_DIR=$(mktemp -d /tmp/bc-audit.XXXXXX)
trap 'rm -rf "$STATE_DIR"' EXIT

if [ -f "$DEBUG_LOG" ]; then
    mv -f "$DEBUG_LOG" "${DEBUG_LOG}.prev" 2>/dev/null || rm -f "$DEBUG_LOG"
fi

# Keep the ESC byte (octal 033).  tput emits terminal escape sequences for
# colours; filtering out ESC leaves broken literal text such as "[32m".
exec > >(stdbuf -o0 tr -cd '\11\12\15\33\40-\176' | tee -a "$DEBUG_LOG") 2>&1

echo "=== Starting Bobcares Smart Audit at $(date) ==="
echo "Debug log: $DEBUG_LOG | State dir: $STATE_DIR"
echo

# Require root privileges
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This audit script must be run as root."
    echo
    echo "Please run the script again using one of the following:"
    echo
    echo "  sudo ./audit.sh"
    echo "  sudo bash audit.sh"
    echo
    exit 1
fi

# Ensure this script is executed ONLY on Non-Control-Panel (No Panel) servers
check_no_panel_only() {
    local detected_panel=""

    if [ -f /usr/local/cpanel/version ] || [ -d /usr/local/cpanel ]; then
        detected_panel="cPanel / WHM"
    elif [ -f /usr/local/psa/version ] || [ -d /usr/local/psa ] || command -v plesk >/dev/null 2>&1; then
        detected_panel="Plesk"
    elif [ -d /usr/local/directadmin ]; then
        detected_panel="DirectAdmin"
    elif [ -d /usr/local/CyberCP ]; then
        detected_panel="CyberPanel"
    elif [ -d /usr/local/hestia ]; then
        detected_panel="HestiaCP"
    elif [ -d /usr/local/vesta ]; then
        detected_panel="VestaCP"
    elif [ -d /www/server/panel ]; then
        detected_panel="aaPanel / BT-Panel"
    elif [ -d /usr/local/interworx ]; then
        detected_panel="InterWorx"
    elif [ -d /usr/local/ispconfig ]; then
        detected_panel="ISPConfig"
    elif [ -d /etc/webmin ] || [ -d /usr/libexec/webmin ]; then
        detected_panel="Webmin / Virtualmin"
    fi

    if [[ -n "$detected_panel" ]]; then
        echo "[ERROR] This script is for no panel server. This server has the panel '$detected_panel'. Exiting the script."
        echo
        exit 1
    fi
}
check_no_panel_only

# ====================== EOL DEFINITIONS ======================
UBUNTU_EOL_VERSIONS=(
    "14.04" "14.10" "15.04" "15.10" "16.04" "16.10" "17.04" "17.10"
    "18.04" "18.10" "19.04" "19.10" "20.04" "20.10" "21.04" "21.10"
    "22.10" "23.04" "23.10" "24.10" "25.04" "25.10"
)

declare -A EOL_VERSIONS=(
    [centos]="6 7 8"
    [rhel]="6 7"
    [cloudlinux]="6 7"
    [debian]="6 7 8 9 10 11"
    [rocky]="7"
    [almalinux]="7"
)

AMAZON_LINUX_EOL_VERSIONS=(
    "2010.11" "2011.09" "2012.03" "2012.09" "2013.03" "2013.09"
    "2014.03" "2014.09" "2015.03" "2015.09" "2016.03" "2016.09"
    "2017.03" "2017.09" "2018.03" "1"
)

# PHP versions no longer receiving security fixes from php.net
# (as of 2026: PHP <= 8.1 is EOL; 8.2 security-only until Dec 2026)
PHP_EOL_LIST=(
    "5.4"
    "5.5"
    "5.6"
    "7.0"
    "7.1"
    "7.2"
    "7.3"
    "7.4"
    "8.0"
    "8.1"
)

#-------------------------------------------------------------------------------
# State helpers
#-------------------------------------------------------------------------------

save_state_file() {
    printf '%s=%q\n' "$2" "$3" >> "$STATE_DIR/$1"
}

load_all_state() {
    local f
    for f in "$STATE_DIR"/*.env; do
        [ -f "$f" ] || continue
        source "$f"
    done
}


#-------------------------------------------------------------------------------
# Detection Functions
#-------------------------------------------------------------------------------

collect_os_details() {

    echo "[DEBUG] Collecting Operating System details..."

    OS_NAME=""
    OS_VERSION=""
    DISTRO_NAME=""

    if [ -f /etc/redhat-release ]; then

        DISTRO_NAME=$(cat /etc/redhat-release)

        if grep -iq "Rocky" /etc/redhat-release; then
            OS_NAME="rocky"
        elif grep -iq "AlmaLinux" /etc/redhat-release; then
            OS_NAME="almalinux"
        elif grep -iq "CloudLinux" /etc/redhat-release; then
            OS_NAME="cloudlinux"
        elif grep -iq "CentOS" /etc/redhat-release; then
            OS_NAME="centos"
        elif grep -iq "Red Hat" /etc/redhat-release; then
            OS_NAME="rhel"
        else
            OS_NAME=$(awk '{print tolower($1)}' /etc/redhat-release)
        fi

        OS_VERSION=$(grep -oE '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)

    elif [ -f /etc/os-release ]; then

        . /etc/os-release

        DISTRO_NAME="$PRETTY_NAME"
        OS_NAME="${ID,,}"
        OS_VERSION="$VERSION_ID"

    elif [ -f /etc/lsb-release ]; then

        DISTRO_NAME=$(awk -F= '/DISTRIB_DESCRIPTION/{print $2}' /etc/lsb-release | tr -d '"')
        OS_NAME=$(awk -F= '/DISTRIB_ID/{print tolower($2)}' /etc/lsb-release)
        OS_VERSION=$(awk -F= '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)

    elif [ -f /etc/debian_version ]; then

        DISTRO_NAME="Debian"
        OS_NAME="debian"
        OS_VERSION=$(cat /etc/debian_version)

    else

        DISTRO_NAME="Unknown"
        OS_NAME="unknown"
        OS_VERSION="unknown"

    fi

    [[ "$OS_NAME" == "amzn" ]] && OS_NAME="amazon_linux"

    detect_pkg_mgr

    echo "[DEBUG] Distribution : $DISTRO_NAME"
    echo "[DEBUG] OS           : $OS_NAME"
    echo "[DEBUG] Version      : $OS_VERSION"
    echo "[DEBUG] Package Mgr  : $PKG_MGR"

    export DISTRO_NAME
    export OS_NAME
    export OS_VERSION
}

check_eol_status() {
    EOL_STATUS="Supported"
    local n="${OS_NAME,,}"

    if [[ "$n" == "ubuntu" ]]; then
        for ver in "${UBUNTU_EOL_VERSIONS[@]}"; do [[ "$OS_VERSION" == "$ver" ]] && EOL_STATUS="End of Life" && break; done
    elif [[ "$n" == "amazon_linux" ]]; then
        for ver in "${AMAZON_LINUX_EOL_VERSIONS[@]}"; do [[ "$OS_VERSION" == "$ver" ]] && EOL_STATUS="End of Life" && break; done
        [[ "$OS_VERSION" == "2" ]] && EOL_STATUS="Supported"
    elif [[ -n "${EOL_VERSIONS[$n]}" ]]; then
        local major="${OS_VERSION%%.*}"
        for ver in ${EOL_VERSIONS[$n]}; do [[ "$major" == "$ver" ]] && EOL_STATUS="End of Life" && break; done
    fi
    export EOL_STATUS
}

detect_vm() {
    local virt=""
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt 2>/dev/null)
    fi
    if [[ -n "$virt" && "$virt" != "none" ]]; then
        VM_STATUS="Virtual Machine ($virt)"
    elif command -v hostnamectl >/dev/null 2>&1 && hostnamectl 2>/dev/null | grep -iq "virtualization"; then
        VM_STATUS="Virtual Machine"
    else
        VM_STATUS="Physical Machine"
    fi
    export VM_STATUS
}

detect_pkg_mgr() {
    PKG_MGR=""
    if command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then PKG_MGR="yum"
    elif command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
    fi
    echo "[DEBUG] Package manager: ${PKG_MGR:-none}"
    export PKG_MGR
}

get_public_ip() {
    local ip
    ip=$(dig +short +time=3 +tries=1 myip.opendns.com @resolver1.opendns.com 2>/dev/null | head -1)
    [[ -z "$ip" ]] && ip=$(dig +short +time=3 +tries=1 -4 TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"' | head -1)
    [[ -z "$ip" ]] && ip=$(curl -s --connect-timeout 5 http://whatismyip.akamai.com 2>/dev/null)
    [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    save_state_file "ip.env" MAIN_IP "$ip"
    echo "[DEBUG] Public IP: $ip"
}

check_rdns() {
    local ip="$1"
    local r=""

    if command -v dig >/dev/null 2>&1; then
        r=$(dig -x "$ip" +short 2>/dev/null | sed 's/\.$//' | head -1)

    elif command -v host >/dev/null 2>&1; then
        r=$(host "$ip" 2>/dev/null | awk '/pointer/ {print $NF}' | sed 's/\.$//')

    elif command -v nslookup >/dev/null 2>&1; then
        r=$(nslookup "$ip" 2>/dev/null | awk -F'= ' '/name =/ {print $2}' | sed 's/\.$//')

    else
        save_state_file "rdns.env" RDNS "UNKNOWN"
        return
    fi

    [[ -z "$r" ]] && r="None"
    save_state_file "rdns.env" RDNS "$r"
}

#-------------------------------------------------------------------------------
# IP Reputation Check (DNSBL)
#-------------------------------------------------------------------------------

check_ip_reputation() {
    echo "[DEBUG] Checking IP reputation..."
    IP_REPUTATION_STATUS="Good"
    IP_REPUTATION_DETAIL="Not listed on major DNSBLs"

    if [[ -z "$MAIN_IP" ]]; then
        IP_REPUTATION_STATUS="Unknown"
        IP_REPUTATION_DETAIL="Could not determine public IP"
        export IP_REPUTATION_STATUS IP_REPUTATION_DETAIL
        return
    fi

    local listed_on=()
    local dnsbls=(
        "zen.spamhaus.org"
        "b.barracudacentral.org"
        "bl.spamcop.net"
        "dnsbl.sorbs.net"
        "cbl.abuseat.org"
    )

    # Reverse IP for DNSBL query
    local rev_ip
    rev_ip=$(echo "$MAIN_IP" | awk -F. '{print $4"."$3"."$2"."$1}')

    for dnsbl in "${dnsbls[@]}"; do
        local result
        # Do not force @8.8.8.8 as Spamhaus blocks public DNS resolvers and returns 127.255.255.254
        result=$(dig +short +time=2 +tries=1 "$rev_ip.$dnsbl" 2>/dev/null | head -1)
        if [[ -n "$result" && "$result" != "127.0.0.1" && "$result" != 127.255.255.* ]]; then
            listed_on+=("$dnsbl")
        fi
    done

    if [[ ${#listed_on[@]} -gt 0 ]]; then
        IP_REPUTATION_STATUS="Listed"
        IP_REPUTATION_DETAIL="Listed on: ${listed_on[*]}"
    fi

    export IP_REPUTATION_STATUS IP_REPUTATION_DETAIL
}

#-------------------------------------------------------------------------------
# Security Tools Setup
#-------------------------------------------------------------------------------

setup_security_tools() {
    echo "[DEBUG] Checking security tools (read-only)..."

    if command -v chkrootkit >/dev/null 2>&1 || [ -x /usr/local/sbin/chkrootkit ]; then
        SECURITY_ACTIONS+="chkrootkit present; "
    else
        SECURITY_ACTIONS+="chkrootkit missing; "
    fi

    if command -v rkhunter >/dev/null 2>&1; then
        SECURITY_ACTIONS+="rkhunter present; "
    else
        SECURITY_ACTIONS+="rkhunter missing; "
    fi

    if command -v clamscan >/dev/null 2>&1; then
        SECURITY_ACTIONS+="ClamAV present; "
    else
        SECURITY_ACTIONS+="ClamAV missing; "
    fi

    if command -v clamav-unofficial-sigs >/dev/null 2>&1; then
        SECURITY_ACTIONS+="unofficial-sigs present; "
    else
        SECURITY_ACTIONS+="unofficial-sigs missing; "
    fi

    if command -v freshclam >/dev/null 2>&1; then
        SECURITY_ACTIONS+="freshclam present; "
    else
        SECURITY_ACTIONS+="freshclam missing; "
    fi

    MALWARE_SCRIPT_FRESHLY_INSTALLED="no"
    for script in bobcares-malware-scan.sh run-weekly-malware-scan.sh; do
        if [ -f "/root/scripts/$script" ]; then
            SECURITY_ACTIONS+="$script present; "
        else
            SECURITY_ACTIONS+="$script missing; "
        fi
    done
    export MALWARE_SCRIPT_FRESHLY_INSTALLED

    if [ -f /etc/cron.d/bc-malware-scan ]; then
        SECURITY_ACTIONS+="malware-scan cron present; "
    else
        SECURITY_ACTIONS+="malware-scan cron missing; "
    fi

    if [ -f /root/scripts/malware-whitelist.txt ]; then
        SECURITY_ACTIONS+="malware whitelist present; "
    else
        SECURITY_ACTIONS+="malware whitelist missing; "
    fi

    echo "[DEBUG] Security tools check finished."
    export SECURITY_ACTIONS
}

#-------------------------------------------------------------------------------
# System / resource checks
#-------------------------------------------------------------------------------

# Format raw ps etime (DD-HH:MM:SS / HH:MM:SS / MM:SS) into human-readable form
format_etime() {
    local raw="$1"
    [[ -z "$raw" ]] && return
    if [[ "$raw" =~ ^([0-9]+)-([0-9]+):([0-9]+):([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}d ${BASH_REMATCH[2]}h ${BASH_REMATCH[3]}m"
    elif [[ "$raw" =~ ^([0-9]+):([0-9]+):([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}h ${BASH_REMATCH[2]}m"
    elif [[ "$raw" =~ ^([0-9]+):([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}m"
    else
        echo "$raw"
    fi
}

collect_system_info() {
    echo "[DEBUG] Collecting system resource info..."
    HOSTNAME=$(hostname)
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p 2>/dev/null || uptime)
    LOAD=$(awk '{print $1}' /proc/loadavg)
    RAM_PCT=$(free | awk '/Mem:/ {print int($3/$2*100)}')
    DISK_PCT=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')

    # Detect web server status via systemctl & process check
    local _found_svc="" _found_name="" _ws_state=""
    local _svc_order=("lsws" "openlitespeed" "httpd" "apache2" "nginx" "caddy" "lighttpd")


    # Pass 1: Look for ACTIVE services first
    for _svc in "${_svc_order[@]}"; do
        if systemctl is-active --quiet "$_svc" 2>/dev/null; then
            _found_svc="$_svc"
            _ws_state="active"
            break
        fi
    done

    # Pass 2: If no active service found, check for FAILED services
    if [[ -z "$_found_svc" ]]; then
        for _svc in "${_svc_order[@]}"; do
            if [[ "$(systemctl is-active "$_svc" 2>/dev/null)" == "failed" ]]; then
                _found_svc="$_svc"
                _ws_state="failed"
                break
            fi
        done
    fi

    # Pass 3: If systemctl didn't match an active/failed unit, check for active processes (pgrep)
    local _proc="" _proc_name=""
    if [[ -z "$_found_svc" ]]; then
        for _pn in lshttpd litespeed httpd apache2 nginx caddy lighttpd; do
            _proc=$(pgrep -o -x "$_pn" 2>/dev/null)
            if [[ -n "$_proc" ]]; then
                _proc_name="$_pn"
                _ws_state="active_process"
                break
            fi
        done
    fi

    # Pass 4: If still nothing active/failed/running process, check for stopped (inactive) service unit
    if [[ -z "$_found_svc" && -z "$_proc" ]]; then
        for _svc in "${_svc_order[@]}"; do
            if systemctl cat "$_svc" &>/dev/null; then
                _found_svc="$_svc"
                _ws_state="inactive"
                break
            fi
        done
    fi

    # Determine display name
    local display_svc="${_found_svc:-$_proc_name}"
    case "$display_svc" in
        lsws|lshttpd|litespeed) _found_name="LiteSpeed" ;;
        openlitespeed)          _found_name="OpenLiteSpeed" ;;
        apache2|httpd)          _found_name="Apache" ;;
        nginx)                  _found_name="Nginx" ;;
        caddy)                  _found_name="Caddy" ;;
        lighttpd)               _found_name="lighttpd" ;;
        *)                      _found_name="${display_svc:-Web Server}" ;;
    esac

    # Calculate status and uptime based on state
    if [[ "$_ws_state" == "active" ]]; then
        local svc_start svc_elapsed=""
        svc_start=$(systemctl show "$_found_svc" --property=ActiveEnterTimestamp 2>/dev/null | awk -F= '{print $2}' | xargs)
        if [[ -n "$svc_start" && "$svc_start" != "n/a" ]]; then
            local svc_epoch elapsed_sec d h m
            svc_epoch=$(date -d "$svc_start" +%s 2>/dev/null)
            if [[ -n "$svc_epoch" && "$svc_epoch" -gt 0 ]]; then
                elapsed_sec=$(( $(date +%s) - svc_epoch ))
                d=$(( elapsed_sec / 86400 ))
                h=$(( (elapsed_sec % 86400) / 3600 ))
                m=$(( (elapsed_sec % 3600) / 60 ))
                if (( d > 0 )); then
                    svc_elapsed="${d}d ${h}h ${m}m"
                elif (( h > 0 )); then
                    svc_elapsed="${h}h ${m}m"
                else
                    svc_elapsed="${m}m"
                fi
            fi
        fi

        # Fallback to main process or pgrep process etime if ActiveEnterTimestamp is blank
        if [[ -z "$svc_elapsed" ]]; then
            local p_pid=""
            p_pid=$(systemctl show "$_found_svc" --property=MainPID 2>/dev/null | awk -F= '{print $2}')
            [[ -z "$p_pid" || "$p_pid" == "0" ]] && p_pid=$(pgrep -o -x "lshttpd|litespeed|httpd|apache2|nginx|caddy|lighttpd" 2>/dev/null)
            if [[ -n "$p_pid" && "$p_pid" != "0" ]]; then
                svc_elapsed=$(format_etime "$(ps -p "$p_pid" -o etime= 2>/dev/null | xargs)")
            fi
        fi

        HTTP_UPTIME="${svc_elapsed:-Running}"
        HTTP_STATUS="Running ($_found_name)"

    elif [[ "$_ws_state" == "active_process" ]]; then
        local raw_et
        raw_et=$(ps -p "$_proc" -o etime= 2>/dev/null | xargs)
        HTTP_UPTIME="$(format_etime "$raw_et")"
        HTTP_STATUS="Running ($_found_name)"

    elif [[ "$_ws_state" == "failed" ]]; then
        local fail_reason
        fail_reason=$(systemctl show "$_found_svc" --property=Result 2>/dev/null | awk -F= '{print $2}')
        HTTP_UPTIME="N/A"
        HTTP_STATUS="FAILED ($_found_name - ${fail_reason:-check logs})"

    elif [[ "$_ws_state" == "inactive" ]]; then
        HTTP_UPTIME="N/A"
        HTTP_STATUS="Stopped ($_found_name)"

    else
        HTTP_UPTIME="N/A"
        HTTP_STATUS="Not detected"
    fi

    UPTIME_STATUS="Good"
    [[ "$UPTIME" == *"minute"* && "$UPTIME" != *"hour"* && "$UPTIME" != *"day"* && "$UPTIME" != *"week"* ]] \
        && UPTIME_STATUS="Recently rebooted"

    EMAIL_QUEUE="N/A"
    if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
        local exim_cmd
        exim_cmd=$(command -v exim 2>/dev/null || command -v exim4 2>/dev/null)
        EMAIL_QUEUE=$("$exim_cmd" -bpc 2>/dev/null)
        [[ ! "$EMAIL_QUEUE" =~ ^[0-9]+$ ]] && EMAIL_QUEUE=""
    fi

    if [[ -z "$EMAIL_QUEUE" || "$EMAIL_QUEUE" == "N/A" ]]; then
        if command -v postqueue >/dev/null 2>&1; then
            local pq_out
            pq_out=$(postqueue -p 2>/dev/null)
            if grep -qE 'Mail queue is empty|0 Requests' <<<"$pq_out"; then
                EMAIL_QUEUE=0
            else
                EMAIL_QUEUE=$(grep -c '^[0-9A-F]' <<<"$pq_out" 2>/dev/null || echo 0)
            fi
        elif command -v mailq >/dev/null 2>&1; then
            local mq_out
            mq_out=$(mailq 2>/dev/null)
            if grep -qE 'Mail queue is empty|0 Requests|is empty' <<<"$mq_out"; then
                EMAIL_QUEUE=0
            elif grep -qE '[0-9]+ Requests' <<<"$mq_out"; then
                EMAIL_QUEUE=$(awk '/Requests\./{print $5}' <<<"$mq_out" | tr -d '.' 2>/dev/null)
            else
                EMAIL_QUEUE=$(grep -c '^[0-9A-F]' <<<"$mq_out" 2>/dev/null || echo 0)
            fi
        elif command -v qmail-qstat >/dev/null 2>&1; then
            EMAIL_QUEUE=$(qmail-qstat 2>/dev/null | awk '/messages in queue/{print $4}')
        elif [[ -d /var/spool/postfix/deferred ]]; then
            EMAIL_QUEUE=$(find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l)
        elif [[ -d /var/spool/mqueue ]]; then
            EMAIL_QUEUE=$(find /var/spool/mqueue -type f 2>/dev/null | wc -l)
        fi
    fi

    [[ ! "$EMAIL_QUEUE" =~ ^[0-9]+$ ]] && EMAIL_QUEUE="N/A"

    export HOSTNAME KERNEL UPTIME UPTIME_STATUS HTTP_UPTIME HTTP_STATUS LOAD RAM_PCT DISK_PCT EMAIL_QUEUE
}

check_ssh_config() {
    local sshd_out
    sshd_out=$(sshd -T 2>/dev/null)

    ROOT_LOGIN_RAW=$(awk '/^permitrootlogin/{print tolower($2)}' <<<"$sshd_out")
    SSH_PASSWORD_AUTH=$(awk '/^passwordauthentication/{print tolower($2)}' <<<"$sshd_out")
    SSH_PORT=$(awk '/^port /{print $2}' <<<"$sshd_out" | paste -sd, -)

    if [[ "$ROOT_LOGIN_RAW" =~ ^(no|prohibit-password|without-password|forced-commands-only)$ ]]; then
        ROOT_LOGIN_STATUS="Good (Disabled / Key Only)"
    elif [[ -z "$ROOT_LOGIN_RAW" ]]; then
        ROOT_LOGIN_STATUS="Unknown"; ROOT_LOGIN_RAW="sshd -T failed (run as root?)"
    else
        ROOT_LOGIN_STATUS="Enabled"
    fi

    if [[ "$SSH_PASSWORD_AUTH" == "no" ]]; then
        SSH_PASSAUTH_STATUS="Key-only"
    elif [[ -z "$SSH_PASSWORD_AUTH" ]]; then
        SSH_PASSAUTH_STATUS="Unknown"; SSH_PASSWORD_AUTH="unknown"
    else
        SSH_PASSAUTH_STATUS="Password auth enabled"
    fi

    [[ -z "$SSH_PORT" ]] && SSH_PORT="unknown"

    TMP_SEC=$(mount | grep -w /tmp | grep -q noexec && echo "yes" || echo "no")
    if [[ "$TMP_SEC" == "yes" ]]; then
        TMP_SEC_STATUS="Good"; TMP_SEC_DETAIL="/tmp is mounted with noexec"
    else
        TMP_SEC_STATUS="Warning"; TMP_SEC_DETAIL="/tmp is NOT mounted with noexec"
    fi

    export ROOT_LOGIN_RAW ROOT_LOGIN_STATUS SSH_PASSWORD_AUTH SSH_PASSAUTH_STATUS SSH_PORT TMP_SEC TMP_SEC_STATUS TMP_SEC_DETAIL
}

check_system_firewall() {
    local fw_active="no" fw_name=""

    if command -v csf >/dev/null 2>&1 && csf -l &>/dev/null; then
        fw_active="yes"; fw_name="CSF"
    elif systemctl is-active --quiet firewalld 2>/dev/null; then
        fw_active="yes"; fw_name="firewalld"
    elif systemctl is-active --quiet ufw 2>/dev/null; then
        fw_active="yes"; fw_name="ufw"
    elif iptables -n -L INPUT 2>/dev/null | grep -qvE '^(Chain|target|$)'; then
        fw_active="yes"; fw_name="iptables"
    elif systemctl is-active --quiet ipfw 2>/dev/null; then
        fw_active="yes"; fw_name="ipfw"
    fi

    if [[ "$fw_active" == "yes" ]]; then
        SYSTEM_FIREWALL_STATUS="Good"; SYSTEM_FIREWALL_ANALYSIS="Active ($fw_name)"
    else
        SYSTEM_FIREWALL_STATUS="Missing"; SYSTEM_FIREWALL_ANALYSIS="No active firewall detected; enable CSF, firewalld, or ufw"
    fi
    export SYSTEM_FIREWALL_STATUS SYSTEM_FIREWALL_ANALYSIS
}

check_brute_force_protection() {
    BRUTE_STATUS="Missing"; BRUTE_REASON="No active brute-force protection detected"

    if command -v imunify360-agent >/dev/null 2>&1 && systemctl is-active --quiet imunify360 2>/dev/null; then
        BRUTE_STATUS="Good"; BRUTE_REASON="Imunify360 active"
    elif command -v csf >/dev/null 2>&1 && systemctl is-active --quiet lfd 2>/dev/null \
         && grep -qE '^\s*LF_[A-Z0-9_]+\s*=\s*"?[1-9]' /etc/csf/csf.conf 2>/dev/null; then
        BRUTE_STATUS="Good"; BRUTE_REASON="CSF/LFD with Login Failure Detection"
    elif command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban 2>/dev/null; then
        local jails
        jails=$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{print $2}' | xargs)
        BRUTE_STATUS="Good"; BRUTE_REASON="Fail2Ban active${jails:+ (jails: $jails)}"
    elif command -v cscli >/dev/null 2>&1 && systemctl is-active --quiet crowdsec 2>/dev/null; then
        BRUTE_STATUS="Good"; BRUTE_REASON="CrowdSec active"
    elif systemctl is-active --quiet sshguard 2>/dev/null || command -v sshguard >/dev/null 2>&1; then
        BRUTE_STATUS="Good"; BRUTE_REASON="SSHGuard active"
    elif systemctl is-active --quiet denyhosts 2>/dev/null || { [ -f /etc/hosts.deny ] && grep -qs 'sshd' /etc/hosts.deny 2>/dev/null; }; then
        BRUTE_STATUS="Good"; BRUTE_REASON="DenyHosts active"
    fi

    export BRUTE_STATUS BRUTE_REASON
}

check_root_password_age() {
    local last epoch
    last=$(chage -l root 2>/dev/null | awk -F: '/Last password change/{print $2}' | xargs)
    DAYS_OLD=999

    if [[ -n "$last" && "$last" != "never" ]]; then
        epoch=$(date -d "$last" +%s 2>/dev/null)
        [[ -n "$epoch" ]] && DAYS_OLD=$(( ($(date +%s) - epoch) / 86400 ))
    fi

    [[ $DAYS_OLD -le 90 ]] && ROOT_PW_STATUS="Good" || ROOT_PW_STATUS="Warning"
    export DAYS_OLD ROOT_PW_STATUS
}

#-------------------------------------------------------------------------------
# NEW v4: Threat protection tool status (Malware Scanner / Rootkit Scanner)
#-------------------------------------------------------------------------------

install_malware_cron() {
    [[ $EUID -ne 0 ]] && return

    echo "[INFO] ClamAV is installed but malware scan cron is missing. Auto-configuring /etc/cron.d/bc-malware-scan..."
    mkdir -p /root/scripts

    curl -sSL -m 15 -o /root/scripts/run-weekly-malware-scan.sh http://ims.bobcares.com/run-weekly-malware-scan.sh 2>/dev/null || \
    wget -q -T 15 -O /root/scripts/run-weekly-malware-scan.sh http://ims.bobcares.com/run-weekly-malware-scan.sh 2>/dev/null

    curl -sSL -m 15 -o /root/scripts/bobcares-malware-scan.sh http://ims.bobcares.com/bobcares-malware-scan.sh 2>/dev/null || \
    wget -q -T 15 -O /root/scripts/bobcares-malware-scan.sh http://ims.bobcares.com/bobcares-malware-scan.sh 2>/dev/null

    curl -sSL -m 15 -o /etc/cron.d/bc-malware-scan http://ims.bobcares.com/bc-malware-scan.txt 2>/dev/null || \
    wget -q -T 15 -O /etc/cron.d/bc-malware-scan http://ims.bobcares.com/bc-malware-scan.txt 2>/dev/null

    chmod 755 /root/scripts/run-weekly-malware-scan.sh /root/scripts/bobcares-malware-scan.sh 2>/dev/null
}

check_threat_tools() {
    local clam="no" cron="no"
    command -v clamscan >/dev/null 2>&1 && clam="yes"
    if [[ -f /etc/cron.d/bc-malware-scan ]] \
        && grep -Eqv '^[[:space:]]*(#|$)' /etc/cron.d/bc-malware-scan \
        && grep -Eqi 'bobcares-malware-scan|run-weekly-malware-scan' /etc/cron.d/bc-malware-scan; then
        cron="yes"
    fi

    # Auto-install cron only if ClamAV is installed but the cron is missing
    if [[ "$clam" == "yes" && "$cron" == "no" ]]; then
        install_malware_cron
        if [[ -f /etc/cron.d/bc-malware-scan ]] \
            && grep -Eqv '^[[:space:]]*(#|$)' /etc/cron.d/bc-malware-scan \
            && grep -Eqi 'bobcares-malware-scan|run-weekly-malware-scan' /etc/cron.d/bc-malware-scan; then
            cron="yes"
        fi
    fi

    if [[ "$clam" == "yes" && "$cron" == "yes" ]]; then
        MALWARE_SCANNER_STATUS="Good"
        MALWARE_SCANNER_DETAIL="ClamAV installed; /etc/cron.d/bc-malware-scan is active"
    elif [[ "$clam" == "yes" ]]; then
        MALWARE_SCANNER_STATUS="Partial"
        MALWARE_SCANNER_DETAIL="ClamAV installed, but /etc/cron.d/bc-malware-scan is missing or inactive"
    else
        MALWARE_SCANNER_STATUS="Missing"
        MALWARE_SCANNER_DETAIL="No malware scanner detected"
    fi

    local tools=()
    { command -v chkrootkit >/dev/null 2>&1 || [ -x /usr/local/sbin/chkrootkit ]; } && tools+=("chkrootkit")
    command -v rkhunter >/dev/null 2>&1 && tools+=("rkhunter")

    if [[ ${#tools[@]} -gt 0 ]]; then
        ROOTKIT_SCANNER_STATUS="Good"
        ROOTKIT_SCANNER_DETAIL="Installed: ${tools[*]}"
    else
        ROOTKIT_SCANNER_STATUS="Missing"
        ROOTKIT_SCANNER_DETAIL="No rootkit scanner detected"
    fi

    export MALWARE_SCANNER_STATUS MALWARE_SCANNER_DETAIL ROOTKIT_SCANNER_STATUS ROOTKIT_SCANNER_DETAIL
}

#-------------------------------------------------------------------------------
# NEW v4: Malware / rootkit scan RESULTS (Proactive Defence)
#-------------------------------------------------------------------------------

check_malware_scan_results() {
    echo "[DEBUG] Checking malware scan results..."
    MALWARE_RESULT_STATUS="Unknown"
    MALWARE_RESULT_DETAIL="No scan report yet - run /root/scripts/bobcares-malware-scan.sh"

    local report="/root/scripts/malware-details-report.txt"
    local old_report="/root/scripts/malware-scan-report.txt"

    if [ -f "$report" ]; then
        local rdate
        rdate=$(date -r "$report" '+%Y-%m-%d %H:%M' 2>/dev/null)

        # Count actual malware entries (the new individual report uses "File: /path" lines)
        local malware_count
        malware_count=$(grep -c '^File: ' "$report" 2>/dev/null)
        [[ "$malware_count" =~ ^[0-9]+$ ]] || malware_count=0

        local age_days
        age_days=$(( ($(date +%s) - $(stat -c %Y "$report" 2>/dev/null || date +%s)) / 86400 ))
        local age_suffix=""
        (( age_days > 30 )) && age_suffix=", but report is $age_days day(s) old"

        if [[ $malware_count -gt 0 ]]; then
            MALWARE_RESULT_STATUS="Infected"
            MALWARE_RESULT_DETAIL="$malware_count suspicious file(s) found${age_suffix} (last scan: ${rdate:-unknown})"
        elif (( age_days > 30 )); then
            MALWARE_RESULT_STATUS="Review"
            MALWARE_RESULT_DETAIL="No malware found${age_suffix} (last scan: ${rdate:-unknown})"
        else
            MALWARE_RESULT_STATUS="Clean"
            MALWARE_RESULT_DETAIL="No malware found (last scan: ${rdate:-unknown})"
        fi
    elif [ -f "$old_report" ]; then
        # Fallback to old combined report if new individual file not present
        local rdate cnt=0
        rdate=$(date -r "$old_report" '+%Y-%m-%d %H:%M' 2>/dev/null)
        local files="/root/scripts/malware-files.txt"
        if [ -f "$files" ]; then
            cnt=$(grep -cvE '^[[:space:]]*(#|$)' "$files" 2>/dev/null)
            [[ ! "$cnt" =~ ^[0-9]+$ ]] && cnt=0
        fi
        local age_days
        age_days=$(( ($(date +%s) - $(stat -c %Y "$old_report" 2>/dev/null || date +%s)) / 86400 ))
        local age_suffix=""
        (( age_days > 30 )) && age_suffix=", but report is $age_days day(s) old"

        if [[ $cnt -gt 0 ]]; then
            MALWARE_RESULT_STATUS="Infected"
            MALWARE_RESULT_DETAIL="$cnt suspicious file(s) in $files${age_suffix} (last scan: ${rdate:-unknown})"
        elif (( age_days > 30 )); then
            MALWARE_RESULT_STATUS="Review"
            MALWARE_RESULT_DETAIL="No malware found${age_suffix} (last scan: ${rdate:-unknown})"
        else
            MALWARE_RESULT_STATUS="Clean"
            MALWARE_RESULT_DETAIL="No malware found (last scan: ${rdate:-unknown})"
        fi
    fi

    # Also parse the Outdated CMS report (check dedicated file first, fallback to combined report)
    OUTDATED_CMS_STATUS="Unknown"
    OUTDATED_CMS_DETAIL="No CMS version report available"

    local cms_report="/root/scripts/outdated-cms-report.txt"
    local combined_report="/root/scripts/malware-scan-report.txt"
    local active_cms_file=""

    if [ -f "$cms_report" ]; then
        active_cms_file="$cms_report"
    elif [ -f "$combined_report" ] && grep -qi "Outdated CMS" "$combined_report"; then
        active_cms_file="$combined_report"
    fi

    if [ -n "$active_cms_file" ]; then
        local cdate
        cdate=$(date -r "$active_cms_file" '+%Y-%m-%d %H:%M' 2>/dev/null)

        # Count lines that list CMS software (WordPress, Joomla, Drupal, etc.) with path/version info
        local outdated_count
        outdated_count=$(grep -E '^\s*(PHPMailer|WordPress|Joomla|Drupal|Magento|PrestaShop|OpenCart|Shopify|WooCommerce)[[:space:]]+[0-9]' "$active_cms_file" 2>/dev/null | wc -l)
        [[ "$outdated_count" =~ ^[0-9]+$ ]] || outdated_count=0

        if [[ $outdated_count -eq 0 ]]; then
            OUTDATED_CMS_STATUS="Good"
            OUTDATED_CMS_DETAIL="No outdated CMS or PHPMailer packages detected (last check: ${cdate:-unknown})"
        else
            OUTDATED_CMS_STATUS="Outdated"
            OUTDATED_CMS_DETAIL="$outdated_count outdated package(s) found (last check: ${cdate:-unknown})"
        fi
    fi

    export MALWARE_RESULT_STATUS MALWARE_RESULT_DETAIL OUTDATED_CMS_STATUS OUTDATED_CMS_DETAIL
}

check_rootkit_scan_results() {
    echo "[DEBUG] Checking rootkit scan results..."
    ROOTKIT_RESULT_STATUS="Review"
    ROOTKIT_RESULT_DETAIL="Rootkit summary is unavailable; check the latest scan log"

    local log rdate
    local chk_log="" rk_log=""

    # --- chkrootkit: find a non-empty log ---
    for log in /root/scripts/chkrootkit-report.txt /var/log/chkrootkit.log /var/log/chkrootkit/log /var/log/chkrootkit/chkrootkit.log; do
        [[ -f "$log" && -s "$log" ]] && { chk_log="$log"; break; }
    done

    # --- rkhunter: find a non-empty dedicated log ---
    for log in /var/log/rkhunter/rkhunter.log /var/log/rkhunter.log /root/scripts/rkhunter-report.txt; do
        [[ -f "$log" && -s "$log" ]] && { rk_log="$log"; break; }
    done

    # --- chkrootkit parsing ---
    if [[ -n "$chk_log" ]]; then
        rdate=$(date -r "$chk_log" '+%Y-%m-%d %H:%M' 2>/dev/null)
        local infected_lines
        infected_lines=$(grep -i 'INFECTED' "$chk_log" 2>/dev/null | grep -ivE 'not infected|not tested|0 infected' || true)
        local inf_count=0
        [[ -n "$infected_lines" ]] && inf_count=$(wc -l <<<"$infected_lines")

        if (( inf_count == 0 )); then
            ROOTKIT_RESULT_STATUS="Clean"
            ROOTKIT_RESULT_DETAIL="chkrootkit: 0 infected items found (last scan: ${rdate:-unknown})"
        else
            ROOTKIT_RESULT_STATUS="Infected"
            ROOTKIT_RESULT_DETAIL="chkrootkit: $inf_count suspicious INFECTED result(s) found (last scan: ${rdate:-unknown})"
        fi
        export ROOTKIT_RESULT_STATUS ROOTKIT_RESULT_DETAIL
        return
    fi

    # --- rkhunter dedicated log parsing ---
    if [[ -n "$rk_log" ]]; then
        local possible
        possible=$(awk 'tolower($0) ~ /possible rootkits[[:space:]]*:/ {
            sub(/.*possible rootkits[[:space:]]*:[[:space:]]*/,"",tolower($0))
            match($0,/[0-9]+/); print substr($0,RSTART,RLENGTH); exit
        }' "$rk_log" 2>/dev/null)
        if [[ "$possible" =~ ^[0-9]+$ ]]; then
            rdate=$(date -r "$rk_log" '+%Y-%m-%d %H:%M' 2>/dev/null)
            if (( possible <= 10 )); then
                ROOTKIT_RESULT_STATUS="Clean"
                ROOTKIT_RESULT_DETAIL="rkhunter: $possible possible rootkits (last scan: ${rdate:-unknown})"
            else
                ROOTKIT_RESULT_STATUS="Infected"
                ROOTKIT_RESULT_DETAIL="rkhunter: $possible possible rootkits detected (last scan: ${rdate:-unknown})"
            fi
            export ROOTKIT_RESULT_STATUS ROOTKIT_RESULT_DETAIL
            return
        fi
    fi

    # --- Fallback: parse combined malware-scan-report.txt ---
    local combined="/root/scripts/malware-scan-report.txt"
    if [[ -f "$combined" && -s "$combined" ]]; then
        rdate=$(date -r "$combined" '+%Y-%m-%d %H:%M' 2>/dev/null)

        # Extract the Rootkit Scan Report section
        local rk_section
        rk_section=$(awk '/^Rootkit Scan Report/{found=1; next} found && /^[A-Z].*Report/{exit} found{print}' "$combined" 2>/dev/null)

        # Check if the section exists but has no data lines
        if grep -qi "Rootkit Scan Report" "$combined" 2>/dev/null; then
            local possible
            possible=$(echo "$rk_section" | awk 'tolower($0) ~ /possible rootkits[[:space:]]*:/ {
                match($0,/[0-9]+/); print substr($0,RSTART,RLENGTH); exit
            }')
            local checked
            checked=$(echo "$rk_section" | awk 'tolower($0) ~ /rootkits checked[[:space:]]*:/ {
                match($0,/[0-9]+/); print substr($0,RSTART,RLENGTH); exit
            }')

            if [[ "$possible" =~ ^[0-9]+$ ]]; then
                if (( possible <= 10 )); then
                    ROOTKIT_RESULT_STATUS="Clean"
                    ROOTKIT_RESULT_DETAIL="rkhunter: $possible possible rootkits${checked:+, $checked checked} (last scan: ${rdate:-unknown})"
                else
                    ROOTKIT_RESULT_STATUS="Infected"
                    ROOTKIT_RESULT_DETAIL="rkhunter: $possible possible rootkits detected (last scan: ${rdate:-unknown})"
                fi
            else
                # Section header present but no data lines (empty section)
                ROOTKIT_RESULT_STATUS="Review"
                ROOTKIT_RESULT_DETAIL="No rootkit scan data in report; run rkhunter manually (last report: ${rdate:-unknown})"
            fi
        fi
    fi

    export ROOTKIT_RESULT_STATUS ROOTKIT_RESULT_DETAIL
}

#-------------------------------------------------------------------------------
# Kernel checks
#-------------------------------------------------------------------------------

check_kernel_status() {
    echo "[DEBUG] Checking kernel environment..."
    KERNEL_RUNNING=$(uname -r)
    KERNEL_ENV="standard"
    KC_STATUS="Not installed"
    KC_ACTIVE="no"
    KC_EFFECTIVE=""
    KERNEL_UPDATE_AVAILABLE="No"
    KERNEL_STATUS="Good"
    KERNEL_ANALYSIS=""

    local ctype=""
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        ctype=$(systemd-detect-virt -c 2>/dev/null)
        [[ "$ctype" == "none" ]] && ctype=""
    fi
    [[ -z "$ctype" && -f /proc/user_beancounters ]] && ctype="openvz/virtuozzo"
    [[ -z "$ctype" && -f /.dockerenv ]] && ctype="docker"
    [[ -z "$ctype" && -d /proc/vz && ! -d /proc/bc ]] && ctype="openvz-guest"

    if [[ -n "$ctype" ]]; then
        KERNEL_ENV="container ($ctype)"
        KERNEL_STATUS="Host-managed"
        KERNEL_ANALYSIS="Container guest: kernel belongs to the host node. Kernel upgrade must be done on the host."
    fi

    if [[ "$KERNEL_ENV" == "standard" ]]; then
        local pkg_owned="yes"
        if [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
            rpm -qf "/boot/vmlinuz-$KERNEL_RUNNING" >/dev/null 2>&1 || pkg_owned="no"
        elif [[ "$PKG_MGR" == "apt" ]]; then
            dpkg -S "/boot/vmlinuz-$KERNEL_RUNNING" >/dev/null 2>&1 || pkg_owned="no"
        fi

        if [[ "$KERNEL_RUNNING" =~ (ovh|xxxx|grs|mod-std) ]]; then
            KERNEL_ENV="network kernel (OVH-style)"
        elif [[ "$pkg_owned" == "no" && ! -f "/boot/vmlinuz-$KERNEL_RUNNING" ]]; then
            KERNEL_ENV="network/netboot kernel"
        elif [[ "$pkg_owned" == "no" ]]; then
            KERNEL_ENV="custom kernel"
        fi

        if [[ "$KERNEL_ENV" != "standard" ]]; then
            KERNEL_STATUS="Custom/Network"
            KERNEL_ANALYSIS="Running a custom/network kernel not managed by package manager."
        fi
    fi

    if command -v kcarectl >/dev/null 2>&1; then
        KC_STATUS="Installed but NOT working"
        local kc_uname
        kc_uname=$(kcarectl --uname 2>/dev/null | tr -d '[:space:]')
        if kcarectl --info >/dev/null 2>&1 && [[ -n "$kc_uname" ]]; then
            KC_ACTIVE="yes"
            KC_EFFECTIVE="$kc_uname"
            if [[ "$kc_uname" != "$KERNEL_RUNNING" ]]; then
                KC_STATUS="Active - live patches applied"
            else
                KC_STATUS="Active - no patches currently needed"
            fi
        fi
    fi

    if [[ "$KERNEL_ENV" == "standard" ]]; then
        local repo_kernel=""
        if [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
            repo_kernel=$($PKG_MGR check-update kernel --quiet 2>/dev/null | awk '/^kernel\./{print $2; exit}')
        elif [[ "$PKG_MGR" == "apt" ]]; then
            repo_kernel=$(apt list --upgradable 2>/dev/null | awk -F'[/ ]' '/^linux-image|^linux-generic/{print $3; exit}')
        fi
        [[ -n "$repo_kernel" ]] && KERNEL_UPDATE_AVAILABLE="Yes ($repo_kernel)"

        if [[ "$KERNEL_UPDATE_AVAILABLE" != "No" ]]; then
            if [[ "$KC_ACTIVE" == "yes" ]]; then
                KERNEL_STATUS="Covered by KernelCare"
                KERNEL_ANALYSIS="Update available but covered by KernelCare live-patching."
            else
                KERNEL_STATUS="Update Available"
                KERNEL_ANALYSIS="Kernel update available. Install and reboot, or deploy KernelCare."
            fi
        fi
    fi

    export KERNEL_RUNNING KERNEL_ENV KC_STATUS KC_ACTIVE KC_EFFECTIVE KERNEL_UPDATE_AVAILABLE KERNEL_STATUS KERNEL_ANALYSIS
}

check_reboot_required() {
    echo "[DEBUG] Checking reboot requirements..."
    REBOOT_REQUIRED="No"; REBOOT_REASON="No reboot needed"
    SVC_RESTART_LIST=""; SVC_RESTART_COUNT=0
    local kernel_pending="no" nonkernel_pending="no"

    if [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
        local newest
        newest=$(rpm -q --last kernel 2>/dev/null | head -1 | awk '{print $1}' | sed 's/^kernel-//')
        [[ -n "$newest" && "$newest" != "$KERNEL_RUNNING" ]] && kernel_pending="yes"

        if command -v needs-restarting >/dev/null 2>&1; then
            local nr_out
            nr_out=$(timeout 15 needs-restarting -r 2>/dev/null || true)
            if [[ -n "$nr_out" ]]; then
                REBOOT_REQUIRED="Yes"
                REBOOT_REASON="Core components updated since boot"
                if grep -E '^\s*\*' <<<"$nr_out" | grep -qiv 'kernel'; then
                    nonkernel_pending="yes"
                fi
                grep -E '^\s*\*' <<<"$nr_out" | grep -qi 'kernel' && kernel_pending="yes"
            fi
            SVC_RESTART_LIST=$(timeout 15 needs-restarting -s 2>/dev/null | grep -Ev '^\s*$' | sort -u | paste -sd ', ' - | head -c 400 || true)
            [[ -n "$SVC_RESTART_LIST" ]] && SVC_RESTART_COUNT=$(awk -F', ' '{print NF}' <<<"$SVC_RESTART_LIST")
        elif [[ "$kernel_pending" == "yes" ]]; then
            REBOOT_REQUIRED="Yes"
            REBOOT_REASON="Newer kernel installed than running"
        fi

    elif [[ "$PKG_MGR" == "apt" ]]; then
        if [ -f /var/run/reboot-required ]; then
            REBOOT_REQUIRED="Yes"
            REBOOT_REASON=$(head -1 /var/run/reboot-required 2>/dev/null)
            if [ -f /var/run/reboot-required.pkgs ]; then
                grep -q '^linux-' /var/run/reboot-required.pkgs 2>/dev/null && kernel_pending="yes"
                grep -qv '^linux-' /var/run/reboot-required.pkgs 2>/dev/null && nonkernel_pending="yes"
            else
                nonkernel_pending="yes"
            fi
        fi
        if command -v needrestart >/dev/null 2>&1; then
            SVC_RESTART_LIST=$(NEEDRESTART_MODE=a timeout 15 needrestart -b -r l 2>/dev/null | awk '/^NEEDRESTART-SVC:/{print $2}' | sed 's/\.service$//' | sort -u | paste -sd ', ' - | head -c 400 || true)
            [[ -n "$SVC_RESTART_LIST" ]] && SVC_RESTART_COUNT=$(awk -F', ' '{print NF}' <<<"$SVC_RESTART_LIST")
        fi
    fi

    if [[ "$KERNEL_ENV" == container* ]]; then
        if [[ "$REBOOT_REQUIRED" == "Yes" ]]; then
            REBOOT_REASON="$REBOOT_REASON (container guest - kernel is host-managed)"
        fi
    elif [[ "$KC_ACTIVE" == "yes" && "$kernel_pending" == "yes" && "$nonkernel_pending" == "no" ]]; then
        REBOOT_REQUIRED="No (kernel live-patched)"
        REBOOT_REASON="Newer kernel installed, but covered by KernelCare"
    fi

    if [[ "$REBOOT_REQUIRED" == No* && $SVC_RESTART_COUNT -gt 0 ]]; then
        REBOOT_REASON="$REBOOT_REASON. Recommend restarting services: $SVC_RESTART_LIST"
    fi

    case "$REBOOT_REQUIRED" in
        "Yes")                        REBOOT_STATUS="Reboot Required" ;;
        "No (kernel live-patched)")   REBOOT_STATUS="KernelCare Covered" ;;
        *)                            REBOOT_STATUS="Good" ;;
    esac
    export REBOOT_REQUIRED REBOOT_REASON REBOOT_STATUS SVC_RESTART_LIST SVC_RESTART_COUNT
}

check_package_updates() {
    echo "[DEBUG] Checking for package updates..."
    OS_UPDATE_COUNT=0; SEC_UPDATE_COUNT=0
    PHP_UPDATE_COUNT=0; HTTPD_UPDATE_COUNT=0; MYSQL_UPDATE_COUNT=0; KERNEL_UPDATE_COUNT=0
    OTHER_UPDATE_COUNT=0; OTHER_UPDATE_PKGS=""
    UPDATE_ALL_LIST=""; KERNEL_UPDATE_LIST=""; PHP_UPDATE_LIST=""
    HTTPD_UPDATE_LIST=""; MYSQL_UPDATE_LIST=""; OTHER_UPDATE_LIST=""
    local -a _pkg_updates=()

    if [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
        mapfile -t _pkg_updates < <($PKG_MGR check-update --quiet 2>/dev/null | grep -E '^\S+\.\S+\s+\S+\s+\S+' || true)
        OS_UPDATE_COUNT=${#_pkg_updates[@]}

        if [[ $OS_UPDATE_COUNT -gt 0 ]]; then
            PHP_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(ea-php|alt-php|lsphp|rh-php|php)' || true)
            HTTPD_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(httpd|ea-apache24|nginx|openlitespeed|litespeed|caddy|lighttpd)' || true)
            MYSQL_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Eci '^(MariaDB-|mysql|mariadb|percona|postgres|postgresql|mongodb|sqlite)' || true)
            KERNEL_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(kernel|linux-firmware)' || true)
            OTHER_UPDATE_PKGS=$(printf '%s\n' "${_pkg_updates[@]}" \
                | grep -Evi '^(ea-php|alt-php|lsphp|rh-php|php|httpd|ea-apache24|nginx|openlitespeed|litespeed|caddy|lighttpd|MariaDB-|mysql|mariadb|percona|postgres|postgresql|mongodb|sqlite|kernel|linux-firmware)' \
                | awk -F. '{print $1}' | sort -u | paste -sd ', ' - | head -c 300)
        fi

        if [[ "$PKG_MGR" == "dnf" ]]; then
            SEC_UPDATE_COUNT=$(dnf updateinfo list security --quiet 2>/dev/null | grep -cE '^\S+\s+\S+\s+\S+' 2>/dev/null)
            SEC_UPDATE_COUNT=${SEC_UPDATE_COUNT:-0}
        else
            SEC_UPDATE_COUNT=$(yum --security check-update --quiet 2>/dev/null | grep -cE '^\S+\.\S+\s+\S+\s+\S+' 2>/dev/null)
            SEC_UPDATE_COUNT=${SEC_UPDATE_COUNT:-0}
        fi

    elif [[ "$PKG_MGR" == "apt" ]]; then
        apt-get update -qq >/dev/null 2>&1
        mapfile -t _pkg_updates < <(apt list --upgradable 2>/dev/null | grep -E '^\S+/')
        OS_UPDATE_COUNT=${#_pkg_updates[@]}

        if [[ $OS_UPDATE_COUNT -gt 0 ]]; then
            PHP_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(ea-php|alt-php|lsphp|rh-php|php)' || true)
            HTTPD_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(apache2|httpd|nginx|openlitespeed|litespeed|caddy|lighttpd)' || true)
            MYSQL_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Eci '^(mariadb|mysql|percona|postgres|postgresql|redis|mongodb|sqlite)' || true)
            KERNEL_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^linux-(base|image|headers|modules|generic|tools|firmware)' || true)
            SEC_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -ci 'security' || true)
            OTHER_UPDATE_PKGS=$(printf '%s\n' "${_pkg_updates[@]}" \
                | grep -Evi '^(ea-php|alt-php|lsphp|rh-php|php|apache2|httpd|nginx|openlitespeed|litespeed|caddy|lighttpd|mariadb|mysql|percona|postgres|postgresql|redis|mongodb|sqlite|linux-(base|image|headers|modules|generic|tools|firmware))' \
                | awk -F/ '{print $1}' | sort -u | paste -sd ', ' - | head -c 300)
        fi
    fi

    OTHER_UPDATE_COUNT=$(( OS_UPDATE_COUNT - PHP_UPDATE_COUNT - HTTPD_UPDATE_COUNT - MYSQL_UPDATE_COUNT - KERNEL_UPDATE_COUNT ))
    (( OTHER_UPDATE_COUNT < 0 )) && OTHER_UPDATE_COUNT=0

    # Preserve the complete package-manager entries for audit-findings.log.
    # These lists include target and installed versions, not just package names.
    UPDATE_ALL_LIST=$(printf '%s\n' "${_pkg_updates[@]}")
    if [[ "$PKG_MGR" == "apt" ]]; then
        KERNEL_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -E '^linux-(base|image|headers|modules|generic|tools|firmware)' || true)
        PHP_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -E '^(ea-php|alt-php|lsphp|rh-php|php)' || true)
        HTTPD_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -E '^(apache2|httpd|nginx|openlitespeed|litespeed|caddy|lighttpd)' || true)
        MYSQL_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ei '^(mariadb|mysql|percona|postgres|postgresql|redis|mongodb|sqlite)' || true)
        OTHER_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Evi '^(ea-php|alt-php|lsphp|rh-php|php|apache2|httpd|nginx|openlitespeed|litespeed|caddy|lighttpd|mariadb|mysql|percona|postgres|postgresql|redis|mongodb|sqlite|linux-(base|image|headers|modules|generic|tools|firmware))' || true)
    else
        KERNEL_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -E '^(kernel|linux-firmware)' || true)
        PHP_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -E '^(ea-php|alt-php|lsphp|rh-php|php)' || true)
        HTTPD_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -E '^(httpd|ea-apache24|nginx|openlitespeed|litespeed|caddy|lighttpd)' || true)
        MYSQL_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ei '^(MariaDB-|mysql|mariadb|percona|postgres|postgresql|redis|mongodb|sqlite)' || true)
        OTHER_UPDATE_LIST=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Evi '^(ea-php|alt-php|lsphp|rh-php|php|httpd|ea-apache24|nginx|openlitespeed|litespeed|caddy|lighttpd|MariaDB-|mysql|mariadb|percona|postgres|postgresql|redis|mongodb|sqlite|kernel|linux-firmware)' || true)
    fi

    export OS_UPDATE_COUNT SEC_UPDATE_COUNT PHP_UPDATE_COUNT HTTPD_UPDATE_COUNT MYSQL_UPDATE_COUNT KERNEL_UPDATE_COUNT OTHER_UPDATE_COUNT OTHER_UPDATE_PKGS \
           UPDATE_ALL_LIST KERNEL_UPDATE_LIST PHP_UPDATE_LIST HTTPD_UPDATE_LIST MYSQL_UPDATE_LIST OTHER_UPDATE_LIST
}

#-------------------------------------------------------------------------------
# checks
#-------------------------------------------------------------------------------


check_system_version() {
    # The Operating System row represents kernel currency only.  Application
    # packages are reported separately as PHP, web server, database, or Other.
    SYSTEM_UPDATE_STATUS="$KERNEL_STATUS"
    SYSTEM_LATEST="Running kernel: $KERNEL_RUNNING; kernel packages pending: ${KERNEL_UPDATE_COUNT:-0}${KERNEL_ANALYSIS:+; $KERNEL_ANALYSIS}"
    SYSTEM_SOURCE="Kernel"

    export SYSTEM_UPDATE_STATUS SYSTEM_LATEST SYSTEM_SOURCE
}

check_modsecurity() {
    echo "[DEBUG] Checking Web Application Firewall (WAF)..."
    MODSEC_STATUS="Missing"
    MODSEC_REASON="No active Web Application Firewall (WAF) detected"

    local apache_conf=""
    local nginx_conf=""
    local module_loaded="no"

    # 1. Imunify360 WebShield / WAF Check
    if systemctl is-active --quiet imunify360-webshield 2>/dev/null || { command -v imunify360-agent >/dev/null 2>&1 && systemctl is-active --quiet imunify360 2>/dev/null; }; then
        MODSEC_STATUS="Good"
        MODSEC_REASON="Imunify360 WAF / WebShield active"
        export MODSEC_STATUS MODSEC_REASON
        return
    fi

    # 2. BitNinja WAF Check
    if systemctl is-active --quiet bitninja 2>/dev/null || command -v bitninjad >/dev/null 2>&1; then
        MODSEC_STATUS="Good"
        MODSEC_REASON="BitNinja WAF protection active"
        export MODSEC_STATUS MODSEC_REASON
        return
    fi

    # 3. LiteSpeed / OpenLiteSpeed WAF Check
    if command -v /usr/local/lsws/bin/litespeed >/dev/null 2>&1 || pgrep -x "litespeed" >/dev/null 2>&1 || pgrep -x "openlitespeed" >/dev/null 2>&1; then
        if [ -f /usr/local/lsws/conf/httpd_config.xml ] && grep -qE -i 'cpanel_wafs|modsecurity|SecRuleEngine' /usr/local/lsws/conf/httpd_config.xml 2>/dev/null; then
            MODSEC_STATUS="Good"
            MODSEC_REASON="LiteSpeed WAF / ModSecurity engine enabled"
            export MODSEC_STATUS MODSEC_REASON
            return
        elif grep -Riq "SecRuleEngine[[:space:]]\+On" /etc/httpd /etc/apache2 /usr/local/apache/conf /etc/cwaf 2>/dev/null; then
            MODSEC_STATUS="Good"
            MODSEC_REASON="LiteSpeed WAF active with ModSecurity rules"
            export MODSEC_STATUS MODSEC_REASON
            return
        fi
    fi

    # 4. Nginx + ModSecurity / NAXSI / Coraza Check
    if command -v nginx >/dev/null 2>&1; then
        nginx_conf=$(nginx -T 2>/dev/null)

        if echo "$nginx_conf" | grep -qiE 'modsecurity[[:space:]]+on'; then
            MODSEC_STATUS="Good"
            MODSEC_REASON="ModSecurity enabled for Nginx"
            export MODSEC_STATUS MODSEC_REASON
            return
        elif echo "$nginx_conf" | grep -qiE 'coraza_rules|coraza_module'; then
            MODSEC_STATUS="Good"
            MODSEC_REASON="Coraza WAF enabled for Nginx"
            export MODSEC_STATUS MODSEC_REASON
            return
        elif echo "$nginx_conf" | grep -qiE 'naxsi_main|SecRulesEnabled'; then
            MODSEC_STATUS="Good"
            MODSEC_REASON="NAXSI WAF enabled for Nginx"
            export MODSEC_STATUS MODSEC_REASON
            return
        fi
    fi

    # 5. Apache + ModSecurity Check
    if command -v httpd >/dev/null 2>&1; then
        httpd -M 2>/dev/null | grep -qiE 'security2_module|mod_security' && module_loaded="yes"
    elif command -v apache2 >/dev/null 2>&1; then
        apache2ctl -M 2>/dev/null | grep -qiE 'security2_module|mod_security' && module_loaded="yes"
    fi

    if [[ "$module_loaded" == "yes" ]]; then
        if grep -Riq "SecRuleEngine[[:space:]]\+On" \
            /etc/httpd /etc/apache2 /usr/local/apache/conf /etc/cwaf 2>/dev/null; then
            MODSEC_STATUS="Good"
            MODSEC_REASON="ModSecurity enabled for Apache"
        elif grep -Riq "SecRuleEngine[[:space:]]\+DetectionOnly" \
            /etc/httpd /etc/apache2 /usr/local/apache/conf /etc/cwaf 2>/dev/null; then
            MODSEC_STATUS="Review"
            MODSEC_REASON="ModSecurity in DetectionOnly mode"
        else
            MODSEC_STATUS="Missing"
            MODSEC_REASON="ModSecurity module loaded but rule engine disabled"
        fi
    fi

    export MODSEC_STATUS MODSEC_REASON
}

check_services() {
    echo "[DEBUG] Checking system services..."
    SERVICES_DOWN=""
    SERVICES_STATUS="N/A"

    command -v systemctl >/dev/null 2>&1 || {
        SERVICES_DOWN="systemctl not available"
        export SERVICES_DOWN SERVICES_STATUS
        return
    }

    local failed_svcs
    failed_svcs=$(systemctl list-units --type=service --state=failed --no-legend 2>/dev/null | awk '{print $1}')

    if [[ -n "$failed_svcs" ]]; then
        SERVICES_STATUS="Services Down"
        SERVICES_DOWN=$(echo "$failed_svcs" | sed 's/\.service//g' | paste -sd ', ' -)
    else
        SERVICES_STATUS="Good"
        SERVICES_DOWN="All enabled services operating normally (0 failed units)"
    fi

    export SERVICES_DOWN SERVICES_STATUS
}

check_ssl_expiry() {
    echo "[DEBUG] Checking SSL certificate expiry..."
    SSL_STATUS="N/A"
    SSL_EXPIRY="No SSL certificates found"

    command -v openssl >/dev/null 2>&1 || {
        export SSL_STATUS SSL_EXPIRY
        return
    }

    local cert
    local earliest_days=""
    local earliest_date=""

    while IFS= read -r cert; do
        [[ -f "$cert" && -s "$cert" ]] || continue
        local enddate end_epoch now_epoch days

        enddate=$(timeout 2 openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
        [[ -z "$enddate" ]] && continue

        end_epoch=$(date -d "$enddate" +%s 2>/dev/null)
        now_epoch=$(date +%s)
        days=$(( (end_epoch - now_epoch) / 86400 ))

        if [[ -z "$earliest_days" || "$days" -lt "$earliest_days" ]]; then
            earliest_days=$days
            earliest_date="$enddate"
        fi
    done < <(
        {
            # Standard system SSL paths — exclude CA bundles and trust anchors
            timeout 5 find /etc/ssl /etc/pki \
                -maxdepth 4 -type f \( -name "*.crt" -o -name "*.pem" \) \
                ! -path "*/ca-trust/*" ! -path "*ca-bundle*" ! -path "*cacert*" \
                ! -name "ca-certificates.crt" 2>/dev/null
            # Let's Encrypt live certificates (depth 3: live/<domain>/fullchain.pem)
            timeout 3 find /etc/letsencrypt/live -maxdepth 2 -type f \
                \( -name "fullchain.pem" -o -name "cert.pem" \) 2>/dev/null
            # nginx / apache vhost certs in common custom locations
            timeout 3 find /etc/nginx/ssl /etc/apache2/ssl /etc/httpd/ssl \
                -maxdepth 3 -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null
        } | sort -u
    )

    if [[ -n "$earliest_days" ]]; then
        SSL_EXPIRY="$earliest_date"

        if (( earliest_days < 0 )); then
            SSL_STATUS="Expired"
        elif (( earliest_days <= 30 )); then
            SSL_STATUS="Expiring Soon"
        else
            SSL_STATUS="Good"
        fi
    fi

    export SSL_STATUS SSL_EXPIRY
}

check_backups() {
    echo "[DEBUG] Checking backups..."
    BACKUP_STATUS="N/A"
    BACKUP_DETAILS="No backups detected"

    local backup_dirs=(
        /backup
        /backups
        /var/backups
        /home/backup
        /data/backup
        /mnt/backup
        /opt/backup
    )

    local latest=0
    local found=""
    local cron_found="No"

    for dir in "${backup_dirs[@]}"; do
        [[ -d "$dir" ]] || continue

        local ts
        ts=$(timeout 3 find "$dir" -maxdepth 2 -xdev -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -1)

        if [[ -n "$ts" ]]; then
            found="$dir"
            ts=${ts%.*}
            (( ts > latest )) && latest=$ts
        fi
    done

    if grep -RiqE 'backup|rsync|borg|restic|duplicity|rdiff|tar' \
        /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null; then
        cron_found="Yes"
    fi

    if (( latest > 0 )); then
        local now age
        now=$(date +%s)
        age=$(( (now - latest) / 86400 ))

        if (( age <= 1 )); then
            BACKUP_STATUS="Good"
        elif (( age <= 7 )); then
            BACKUP_STATUS="Old"
        else
            BACKUP_STATUS="Stale"
        fi

        BACKUP_DETAILS="Latest backup ${age} day(s) old (${found}) | Backup Cron: ${cron_found}"
    else
        if [[ "$cron_found" == "Yes" ]]; then
            BACKUP_STATUS="Warning"
            BACKUP_DETAILS="Backup cron found, but no backup files detected"
        fi
    fi

    export BACKUP_STATUS BACKUP_DETAILS
}

#-------------------------------------------------------------------------------
# NEW v4: Extended backup checks (schedule, remote destinations, last backup)
#-------------------------------------------------------------------------------

check_backup_extended() {
    echo "[DEBUG] Checking extended backup configuration..."
    # Only treat named backup locations and likely backup archives as backups.
    # Deliberately exclude scanning deep /home or network mounts.
    local backup_dirs=(/backup /backups /home/backup /home/backups /data/backup /data/backups /mnt/backup /mnt/backups /opt/backup /opt/backups)
    local dir file base mtime latest="" latest_time=0 size size_kb age_days backup_dir_count=0
    while IFS= read -r dir; do backup_dirs+=("$dir"); done < <(
        timeout 4 find /home /data /mnt -maxdepth 2 -xdev -type d \( -iname '*backup*' -o -iname 'cpbackup' \) 2>/dev/null
    )

    BACKUP_DAILY_STATUS="N/A"; BACKUP_DAILY_DETAIL="N/A - no backup cron found"
    BACKUP_WEEKLY_STATUS="N/A"; BACKUP_WEEKLY_DETAIL="N/A - no backup cron found"
    BACKUP_MONTHLY_STATUS="N/A"; BACKUP_MONTHLY_DETAIL="N/A - no backup cron found"
    BACKUP_RETENTION_STATUS="N/A"; BACKUP_RETENTION_DETAIL="N/A - retention cannot be determined from a cron schedule"
    BACKUP_REMOTE_STATUS="Not configured"; BACKUP_REMOTE_DETAIL="No scheduled remote-backup configuration found"
    BACKUP_LAST_STATUS="Unknown"; BACKUP_LAST_DETAIL="No qualifying backup archive found"
    BACKUP_SIZE_STATUS="Unknown"; BACKUP_SIZE_DETAIL="N/A"

    local cron_lines cron_schedule
    cron_lines=$({
        [[ -f /etc/crontab ]] && cat /etc/crontab
        find /etc/cron.d /var/spool/cron -maxdepth 2 -type f -exec cat {} + 2>/dev/null
        crontab -l 2>/dev/null
    } | awk '!/^[[:space:]]*#/ && tolower($0) ~ /backup|restic|borg|rclone|duplicity|rdiff-backup|rsnapshot|jetbackup|cpbackup|aws[[:space:]]+s3/')
    if [[ -n "$cron_lines" ]]; then
        BACKUP_DAILY_DETAIL="N/A - no daily backup schedule found"
        BACKUP_WEEKLY_DETAIL="N/A - no weekly backup schedule found"
        BACKUP_MONTHLY_DETAIL="N/A - no monthly backup schedule found"
        cron_schedule=$(awk '
            /^@daily|^@hourly|^@reboot/ { daily=1; next }
            /^@weekly/ { weekly=1; next }
            /^@monthly|^@yearly|^@annually/ { monthly=1; next }
            NF >= 5 {
                dom=$3; mon=$4; dow=$5
                if (dom == "*" && mon == "*" && dow == "*") daily=1
                if (dow != "*") weekly=1
                if (dom != "*" || mon != "*") monthly=1
            }
            END { printf "%d %d %d", daily, weekly, monthly }
        ' <<<"$cron_lines")
        read -r has_daily has_weekly has_monthly <<<"$cron_schedule"
        [[ "$has_daily" == 1 ]] && { BACKUP_DAILY_STATUS="Configured"; BACKUP_DAILY_DETAIL="Backup cron schedule detected"; }
        [[ "$has_weekly" == 1 ]] && { BACKUP_WEEKLY_STATUS="Configured"; BACKUP_WEEKLY_DETAIL="Backup cron schedule detected"; }
        [[ "$has_monthly" == 1 ]] && { BACKUP_MONTHLY_STATUS="Configured"; BACKUP_MONTHLY_DETAIL="Backup cron schedule detected"; }
    fi

    if grep -Eqi 'restic|borg|rclone|duplicity|rdiff-backup|aws[[:space:]]+s3|sftp:|rsync://|ssh://' <<<"$cron_lines" \
        || [[ -f /root/.config/rclone/rclone.conf || -f /root/.restic/config ]] \
        || find /etc/restic /etc/borg -maxdepth 2 -type f -print -quit 2>/dev/null | grep -q .; then
        BACKUP_REMOTE_STATUS="Configured"
        BACKUP_REMOTE_DETAIL="Remote backup configuration or scheduled command detected"
    fi

    for dir in "${backup_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        local has_archives=0
        while IFS= read -r file; do
            base=${file##*/}
            [[ "$base" =~ ^(dpkg|apt|alternatives|btmp|wtmp|lastlog|unattended-upgrades) ]] && continue
            [[ "$base" =~ (backup|cpbackup|jetbackup|full|daily|weekly|monthly|\.tar(\.(gz|bz2|xz|zst))?$|\.tgz$|\.zip$|\.sql(\.gz)?$) ]] || continue
            has_archives=1
            mtime=$(stat -c %Y "$file" 2>/dev/null) || continue
            (( mtime > latest_time )) && { latest_time=$mtime; latest="$file"; }
        done < <(timeout 4 find "$dir" -maxdepth 3 -xdev -type f -size +1M 2>/dev/null)
        (( has_archives == 1 )) && ((backup_dir_count++))
    done

    # Local backup is valid only when both a backup location and a scheduled
    # backup cron are present.  One without the other needs verification.
    if (( backup_dir_count > 0 )) && [[ -n "$cron_lines" ]]; then
        BACKUP_STATUS="Good"
        BACKUP_DETAIL="Backup directory detected ($backup_dir_count location(s)) and backup cron is present"
    elif (( backup_dir_count > 0 )); then
        BACKUP_STATUS="Review"
        BACKUP_DETAIL="Backup directory detected ($backup_dir_count location(s)), but no backup cron found"
    elif [[ -n "$cron_lines" ]]; then
        BACKUP_STATUS="Review"
        BACKUP_DETAIL="Backup cron found, but no backup directory detected"
    else
        BACKUP_STATUS="Missing"
        BACKUP_DETAIL="No backup directory and no backup cron found"
    fi

    if [[ -n "$latest" ]]; then
        age_days=$(( ($(date +%s) - latest_time) / 86400 ))
        if (( age_days <= 2 )); then BACKUP_LAST_STATUS="Recent"
        elif (( age_days <= 8 )); then BACKUP_LAST_STATUS="Aging"
        else BACKUP_LAST_STATUS="Stale"; fi
        BACKUP_LAST_DETAIL="$latest (${age_days} day(s) old)"
        size=$(du -sh "$latest" 2>/dev/null | awk '{print $1}')
        size_kb=$(du -sk "$latest" 2>/dev/null | awk '{print $1}')
        BACKUP_SIZE_STATUS="OK"; BACKUP_SIZE_DETAIL="$size"
    else
        BACKUP_LAST_DETAIL="No qualifying backup archive found"
    fi

    export BACKUP_STATUS BACKUP_DETAIL
    export BACKUP_DAILY_STATUS BACKUP_DAILY_DETAIL \
           BACKUP_WEEKLY_STATUS BACKUP_WEEKLY_DETAIL \
           BACKUP_MONTHLY_STATUS BACKUP_MONTHLY_DETAIL \
           BACKUP_RETENTION_STATUS BACKUP_RETENTION_DETAIL \
           BACKUP_REMOTE_STATUS BACKUP_REMOTE_DETAIL \
           BACKUP_LAST_STATUS BACKUP_LAST_DETAIL \
           BACKUP_SIZE_STATUS BACKUP_SIZE_DETAIL
}

check_php_and_users() {
    echo "[DEBUG] Checking PHP and user accounts..."
    PHP_VERSIONS="N/A"
    PHP_DEFAULT="N/A"
    ACCT_COUNT="N/A"
    ACCT_SUSPENDED="N/A"

    # Detect installed PHP and lsphp versions
    local versions
    versions=$({
        find /usr/bin /usr/local/bin /usr/local/lsws /opt/cpanel /opt/alt -maxdepth 4 -type f \( -name 'php[0-9]*' -o -name 'lsphp[0-9]*' \) 2>/dev/null | grep -oE '(php|lsphp)[0-9.]+' | sed -E 's/^(php|lsphp)//'
        command -v php >/dev/null 2>&1 && php -r 'echo PHP_VERSION;' 2>/dev/null
        command -v lsphp >/dev/null 2>&1 && lsphp -r 'echo PHP_VERSION;' 2>/dev/null
    } | grep -E '^[0-9]' | sort -Vu)

    if [[ -n "$versions" ]]; then
        PHP_VERSIONS=$(echo "$versions" | paste -sd ", " -)
    elif command -v php >/dev/null 2>&1; then
        PHP_VERSIONS=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
    elif command -v lsphp >/dev/null 2>&1; then
        PHP_VERSIONS=$(lsphp -r 'echo PHP_VERSION;' 2>/dev/null)
    else
        PHP_VERSIONS="Not Installed"
    fi

    # Default PHP version
    if command -v php >/dev/null 2>&1; then
        PHP_DEFAULT=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
    else
        PHP_DEFAULT="Not Installed"
    fi

    # Count normal user accounts (UID >=1000)
    ACCT_COUNT=$(awk -F: '$3>=1000 && $3<65534 {c++} END{print c+0}' /etc/passwd)

    # Count locked/suspended accounts efficiently without slow loops
    if [ -f /etc/shadow ] && [ -r /etc/shadow ]; then
        ACCT_SUSPENDED=$(awk -F: 'BEGIN{c=0} $3>=1000 && $3<65534 {if ($2 ~ /^!/ || $2 ~ /^\*/) c++} END{print c}' /etc/shadow 2>/dev/null || echo 0)
    else
        ACCT_SUSPENDED=0
    fi

    export PHP_VERSIONS PHP_DEFAULT ACCT_COUNT ACCT_SUSPENDED
}

#-------------------------------------------------------------------------------
# NEW v4: PHP EOL / disable_functions checks (Software Life Time / Proactive)
#-------------------------------------------------------------------------------

check_php_eol() {
    echo "[DEBUG] Checking PHP EOL status..."
    PHP_EOL_STATUS="Unknown"
    PHP_EOL_DETAIL="Could not determine installed PHP versions"

    [[ -z "$PHP_VERSIONS" || "$PHP_VERSIONS" == "N/A" || "$PHP_VERSIONS" == "Unknown" || "$PHP_VERSIONS" == "Not Installed" ]] && {
        export PHP_EOL_STATUS PHP_EOL_DETAIL
        return
    }

    local v e found=()

    for v in $(echo "$PHP_VERSIONS" | tr ',' ' '); do
        v=$(echo "$v" | xargs)
        [[ -z "$v" ]] && continue

        # If a full version is present (e.g. 8.2.29), reduce it to major.minor
        [[ "$v" =~ ^([0-9]+\.[0-9]+) ]] && v="${BASH_REMATCH[1]}"

        for e in "${PHP_EOL_LIST[@]}"; do
            if [[ "$v" == "$e" ]]; then
                found+=("$v")
                break
            fi
        done
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        PHP_EOL_STATUS="EOL versions present"
        PHP_EOL_DETAIL="No longer supported by vendor: $(printf '%s, ' "${found[@]}" | sed 's/, $//') (default: $PHP_DEFAULT)"
    else
        PHP_EOL_STATUS="Good"
        PHP_EOL_DETAIL="All installed PHP versions are vendor-supported"
    fi

    export PHP_EOL_STATUS PHP_EOL_DETAIL
}

check_php_functions_security() {
    echo "[DEBUG] Checking PHP functions security..."
    PHP_FUNC_STATUS="Unknown"
    PHP_FUNC_DETAIL="No php.ini files found"

    local inis=() ini
    # System-wide php.ini files
    for ini in \
        /etc/php.ini \
        /etc/php/*/cli/php.ini \
        /etc/php/*/fpm/php.ini \
        /etc/php/*/apache2/php.ini \
        /etc/php/*/cgi/php.ini; do
        [ -f "$ini" ] && inis+=("$ini")
    done
    # LiteSpeed PHP ini files
    for ini in /usr/local/lsws/lsphp*/etc/php.ini /usr/local/lsws/lsphp*/etc/php/*/php.ini; do
        [ -f "$ini" ] && inis+=("$ini")
    done
    # PHP-FPM pool configs that may override disable_functions
    while IFS= read -r ini; do
        [ -f "$ini" ] && inis+=("$ini")
    done < <(find /etc/php-fpm.d /etc/php /usr/local/etc/php-fpm.d \
        -maxdepth 4 -type f -name '*.conf' 2>/dev/null \
        | xargs grep -l 'disable_functions' 2>/dev/null)

    [[ ${#inis[@]} -eq 0 ]] && {
        export PHP_FUNC_STATUS PHP_FUNC_DETAIL
        return
    }

    local fully_secured=0 partial_secured=0 insecure=()
    local funcs=("exec" "shell_exec" "system" "passthru")

    for ini in "${inis[@]}"; do
        local df
        df=$(awk -F= '/^[[:space:]]*disable_functions[[:space:]]*=/{print $2}' "$ini" 2>/dev/null | tail -1 | tr -d ' "')

        if [[ -z "$df" ]]; then
            insecure+=("$ini")
            continue
        fi

        local missing=()
        local matched=0
        for f in "${funcs[@]}"; do
            if grep -qE "(^|,)${f}(,|$)" <<<"$df"; then
                ((matched++))
            else
                missing+=("$f")
            fi
        done

        if (( matched == ${#funcs[@]} )); then
            ((fully_secured++))
        elif (( matched > 0 )); then
            ((partial_secured++))
            insecure+=("$ini")
        else
            insecure+=("$ini")
        fi
    done

    if [[ ${#insecure[@]} -eq 0 ]]; then
        PHP_FUNC_STATUS="Good"
        PHP_FUNC_DETAIL="Dangerous functions (exec, shell_exec, system, passthru) disabled in all ${#inis[@]} php.ini file(s)"
    elif (( fully_secured > 0 || partial_secured > 0 )); then
        PHP_FUNC_STATUS="Partial"
        PHP_FUNC_DETAIL="disable_functions incomplete or missing exec/system in: ${insecure[*]}"
    else
        PHP_FUNC_STATUS="Not set"
        PHP_FUNC_DETAIL="Dangerous PHP functions (exec, shell_exec, system, passthru) are not disabled"
    fi

    export PHP_FUNC_STATUS PHP_FUNC_DETAIL
}

#-------------------------------------------------------------------------------
# NEW v4: rDNS status + reboot procedure info (Proactive Defence)
#-------------------------------------------------------------------------------

check_rdns_status() {
    if [[ "$RDNS" == "UNKNOWN" ]]; then
        RDNS_STATUS="N/A"
        RDNS_DETAIL="Unable to verify (dig/host/nslookup not installed)"
    elif [[ -n "$RDNS" && "$RDNS" != "None" ]]; then
        RDNS_STATUS="Good"
        RDNS_DETAIL="PTR record: $RDNS"
    else
        RDNS_STATUS="Missing"
        RDNS_DETAIL="No PTR record for $MAIN_IP - may affect email delivery"
    fi

    export RDNS_STATUS RDNS_DETAIL
}

check_reboot_procedure_info() {
    echo "[DEBUG] Checking reboot procedure info..."
    REBOOT_PROC_STATUS="Manual"
    if [[ "$VM_STATUS" == Physical* ]]; then
        REBOOT_PROC_DETAIL="Physical machine - confirm provider IPMI/KVM or rescue console access is documented"
    else
        REBOOT_PROC_DETAIL="$VM_STATUS - confirm hypervisor/provider console reboot access is documented"
    fi
    export REBOOT_PROC_STATUS REBOOT_PROC_DETAIL
}

check_resource_usage() {
    echo "[DEBUG] Checking resource usage..."
    (( $(echo "$LOAD > $(nproc 2>/dev/null || echo 4)" | bc 2>/dev/null || echo 0) )) && CPU_STATUS="High" || CPU_STATUS="Optimal"
    [[ $RAM_PCT -gt 80 ]] && RAM_STATUS="High" || RAM_STATUS="Good"
    [[ $DISK_PCT -gt 80 ]] && DISK_STATUS="Critical" || DISK_STATUS="Good"

    if [[ "$EMAIL_QUEUE" == "N/A" ]]; then
        EMAIL_STATUS="N/A"
    elif [[ $EMAIL_QUEUE -gt 100 ]]; then
        EMAIL_STATUS="High"
    else
        EMAIL_STATUS="Normal"
    fi

    [[ $RAM_PCT -lt 75 && $DISK_PCT -lt 80 ]] && OVERALL_HEALTH="Healthy" || OVERALL_HEALTH="Needs Attention"

    export CPU_STATUS RAM_STATUS DISK_STATUS EMAIL_STATUS OVERALL_HEALTH
}

#-------------------------------------------------------------------------------
# Reporting (v4 - organized by team audit categories)
#-------------------------------------------------------------------------------

# Emit a stable status token that a terminal reader and the audit portal can both
# understand.  Do not use emoji here: they are being stripped/mis-encoded on
# several target servers and cannot be mapped consistently by the portal.
portal_status() {
    local status="${1,,}"

    case "$status" in
        *"n/a"*|*"unknown"*|*"manual"*|*"host-managed"*) echo "N/A" ;;
        *"missing"*|*"not found"*|*"not detected"*|*"down"*|*"critical"*|*"enabled"*|*"end of life"*|*"eol"*|*"infected"*|*"stale"*|*"not set"*|*"not configured"*|*"expired"*|*"services down"*|*"listed"*|*"outdated"*|*"update available"*|*"reboot required"*|*"warning"*|*"partial"*|*"high"*|*"insecure"*) echo "RED" ;;
        *"review"*|*"aging"*|*"recently rebooted"*|*"suspicious"*|*"expiring soon"*|*"needs attention"*) echo "CHECK" ;;
        *) echo "GREEN" ;;
    esac
}

report_item() {
    # $1: audit item, $2: raw status, $3: human-readable details
    printf '  %-38s : %-6s - %s\n' "$1" "$(portal_status "$2")" "$3"
}

colorize_report() {
    # Keep report-detailed.log plain for the portal.  The audit has already
    # redirected stdout through tee, so -t cannot be used to detect a terminal.
    if [[ "${NO_COLOR:-}" == "1" ]]; then
        cat
        return
    fi

    local reset green red yellow grey
    reset=$(tput sgr0 2>/dev/null || printf '\033[0m')
    green=$(tput setaf 2 2>/dev/null || printf '\033[32m')
    red=$(tput setaf 1 2>/dev/null || printf '\033[31m')
    yellow=$(tput setaf 3 2>/dev/null || printf '\033[33m')
    grey=$(tput setaf 8 2>/dev/null || printf '\033[90m')
    [[ -n "$reset" ]] || reset=$'\033[0m'
    [[ -n "$green" ]] || green=$'\033[32m'
    [[ -n "$red" ]] || red=$'\033[31m'
    [[ -n "$yellow" ]] || yellow=$'\033[33m'
    [[ -n "$grey" ]] || grey=$'\033[90m'

    awk -v reset="$reset" -v green="$green" -v red="$red" -v yellow="$yellow" -v grey="$grey" '
        / : GREEN / { sub(/GREEN/, green "GREEN" reset) }
        / : RED /   { sub(/RED/, red "RED" reset) }
        / : CHECK / { sub(/CHECK/, yellow "CHECK" reset) }
        / : N\/A /   { sub(/N\/A/, grey "N/A" reset) }
        { print }
    '
}

generate_smart_summary() {
    local os_update_line other_line os_lifetime_line
    local stack_status stack_detail cp_lt_status cp_lt_detail
    os_update_line=$(portal_status "$KERNEL_STATUS")
    [[ $OTHER_UPDATE_COUNT -gt 0 ]]  && other_line="RED" || other_line="GREEN"

    [[ "$EOL_STATUS" == "Supported" ]] \
        && os_lifetime_line="GREEN" \
        || os_lifetime_line="RED"

    if [[ "$EOL_STATUS" == "Supported" && "$PHP_EOL_STATUS" == *"Good"* ]]; then
        stack_status="GREEN"
        stack_detail="OS and PHP stack are vendor-supported"
    else
        stack_status="CHECK"
        stack_detail="OS: $EOL_STATUS - PHP: $PHP_EOL_DETAIL"
    fi

    cp_lt_status="N/A"
    cp_lt_detail="No control panel detected"

    cat > "$SUMMARY_FILE" << EOF
# Bobcares Smart Analyzed Server Audit Summary

**Generated:** $(date)

=== System Information ===
Hostname          : $HOSTNAME
Main IP           : $MAIN_IP
rDNS              : $RDNS
OS / Version      : $OS_NAME $OS_VERSION ($EOL_STATUS)
Control Panel     : N/A
System Type       : $VM_STATUS
Kernel            : $KERNEL
System Uptime     : $UPTIME
Web Server Uptime : $HTTP_UPTIME

---

## 1. Threat Protection

| Audit Item | Status | Analysis / Recommendation |
|---|---|---|
| System Firewall | $(portal_status "$SYSTEM_FIREWALL_STATUS") | $SYSTEM_FIREWALL_ANALYSIS |
| Malware Scanner | $(portal_status "$MALWARE_SCANNER_STATUS") | $MALWARE_SCANNER_DETAIL |
| Failed Login Detection | $(portal_status "$BRUTE_STATUS") | $BRUTE_REASON |
| Web App Firewall | $(portal_status "$MODSEC_STATUS") | $MODSEC_REASON |
| Rootkit Scanner | $(portal_status "$ROOTKIT_SCANNER_STATUS") | $ROOTKIT_SCANNER_DETAIL |

## 2. Software Updates

| Audit Item | Status | Analysis / Recommendation |
|---|---|---|
| Operating System / Kernel | $os_update_line | $SYSTEM_LATEST |
| PHP | $([[ $PHP_UPDATE_COUNT -gt 0 ]] && echo "RED" || echo "GREEN") | $PHP_UPDATE_COUNT pending \| Installed: $PHP_VERSIONS \| Default: $PHP_DEFAULT |
| CMS | $(portal_status "$OUTDATED_CMS_STATUS") | $OUTDATED_CMS_DETAIL |
| Web Server | $([[ $HTTPD_UPDATE_COUNT -gt 0 ]] && echo "RED" || echo "GREEN") | $HTTPD_UPDATE_COUNT pending web server update(s) |
| Database Server | $([[ $MYSQL_UPDATE_COUNT -gt 0 ]] && echo "RED" || echo "GREEN") | $MYSQL_UPDATE_COUNT pending DB update(s) |
| Other Softwares | $other_line | $OTHER_UPDATE_COUNT other pending package(s)${OTHER_UPDATE_PKGS:+: $OTHER_UPDATE_PKGS} |
| Kernel | $(portal_status "$KERNEL_STATUS") | Running: $KERNEL_RUNNING \| Update: $KERNEL_UPDATE_AVAILABLE \| KernelCare: $KC_STATUS |
| Reboot Required | $(portal_status "$REBOOT_STATUS") | $REBOOT_REASON |

## 3. Server Health

| Audit Item | Status | Details |
|---|---|---|
| Server Uptime | $(portal_status "$UPTIME_STATUS") | $UPTIME |
| HTTP Uptime | $(portal_status "$HTTP_STATUS") | $HTTP_UPTIME |
| CPU Usage | $(portal_status "$CPU_STATUS") | Load average: $LOAD |
| RAM Usage | $(portal_status "$RAM_STATUS") | Used: ${RAM_PCT}% |
| Disc Space Usage | $(portal_status "$DISK_STATUS") | Used: ${DISK_PCT}% |
| Email Queue | $(portal_status "$EMAIL_STATUS") | Queued messages: $EMAIL_QUEUE |
| IP Reputation | $(portal_status "$IP_REPUTATION_STATUS") | $IP_REPUTATION_DETAIL |

**Overall Server Health:** $OVERALL_HEALTH

## 4. Backup

| Audit Item | Status | Details |
|---|---|---|
| Local Backup | $(portal_status "$BACKUP_STATUS") | $BACKUP_DETAIL |
| Remote Backup | $(portal_status "$BACKUP_REMOTE_STATUS") | $BACKUP_REMOTE_DETAIL |
| Daily Backup | $(portal_status "$BACKUP_DAILY_STATUS") | $BACKUP_DAILY_DETAIL |
| Weekly Backup | $(portal_status "$BACKUP_WEEKLY_STATUS") | $BACKUP_WEEKLY_DETAIL |
| Monthly Backup | $(portal_status "$BACKUP_MONTHLY_STATUS") | $BACKUP_MONTHLY_DETAIL |
| Backup Retention | $(portal_status "$BACKUP_RETENTION_STATUS") | $BACKUP_RETENTION_DETAIL |
| Recent Last Backup | $(portal_status "$BACKUP_LAST_STATUS") | $BACKUP_LAST_DETAIL |
| Size Of Last Backup | $(portal_status "$BACKUP_SIZE_STATUS") | $BACKUP_SIZE_DETAIL |

## 5. Software Life Time

| Audit Item | Status | Details |
|---|---|---|
| Control Panel | $cp_lt_status | $cp_lt_detail |
| Operating System | $os_lifetime_line | $OS_NAME $OS_VERSION - $EOL_STATUS by vendor |
| CMS | $(portal_status "$OUTDATED_CMS_STATUS") | $OUTDATED_CMS_DETAIL |
| Software Stack | $stack_status | $stack_detail |

## 6. Proactive Defence

| Audit Item | Status | Details |
|---|---|---|
| /tmp Security | $(portal_status "$TMP_SEC_STATUS") | $TMP_SEC_DETAIL |
| Reboot Procedure | $(portal_status "$REBOOT_PROC_STATUS") | $REBOOT_PROC_DETAIL |
| IP RDNS | $(portal_status "$RDNS_STATUS") | $RDNS_DETAIL |
| Malware Scan | $(portal_status "$MALWARE_RESULT_STATUS") | $MALWARE_RESULT_DETAIL |
| Rootkit Check | $(portal_status "$ROOTKIT_RESULT_STATUS") | $ROOTKIT_RESULT_DETAIL |
| SSH Root Access Security | $(portal_status "$ROOT_LOGIN_STATUS") | PermitRootLogin: $ROOT_LOGIN_RAW \| PasswordAuth: $SSH_PASSWORD_AUTH \| Port(s): $SSH_PORT |
| PHP Functions Security | $(portal_status "$PHP_FUNC_STATUS") | $PHP_FUNC_DETAIL |
| Root password health | $(portal_status "$ROOT_PW_STATUS") | Root password ~$DAYS_OLD days old (target: rotated within 90 days) |

---

### Additional System Checks

| Check | Status | Details |
|---|---|---|
| Services | $(portal_status "$SERVICES_STATUS") | $SERVICES_DOWN |
| SSL Certificates | $(portal_status "$SSL_STATUS") | $SSL_EXPIRY |
| User Accounts | N/A | Total: $ACCT_COUNT | Locked: $ACCT_SUSPENDED |
| Malware Scan Setup | N/A | $SECURITY_ACTIONS Scan: $MALWARE_SCAN_STARTED |

**Recommendation:** Review all RED and CHECK items above. Prioritise pending security updates, reboot if required, enable or verify backups, and investigate IP reputation if listed. N/A items need a manual check where applicable.
EOF
}

generate_detailed_log() {
    {
        echo "============================================================="
        echo " SYSTEM INFORMATION"
        echo "============================================================="
        printf '  %-38s : %s\n' "Hostname" "$HOSTNAME"
        printf '  %-38s : %s\n' "Audit Date" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        printf '  %-38s : %s\n' "OS" "$DISTRO_NAME"
        printf '  %-38s : %s\n' "Kernel" "$KERNEL"
        printf '  %-38s : %s\n' "Uptime" "$UPTIME"
        printf '  %-38s : %s\n' "Primary IP" "$MAIN_IP"
        echo
        echo "============================================================="
        echo " THREAT PROTECTION"
        echo "============================================================="
        report_item "System Firewall" "$SYSTEM_FIREWALL_STATUS" "$SYSTEM_FIREWALL_ANALYSIS"
        report_item "Malware Scanner" "$MALWARE_SCANNER_STATUS" "$MALWARE_SCANNER_DETAIL"
        report_item "Failed Login Detection" "$BRUTE_STATUS" "$BRUTE_REASON"
        report_item "Web Application Firewall" "$MODSEC_STATUS" "$MODSEC_REASON"
        report_item "Rootkit Scanner" "$ROOTKIT_SCANNER_STATUS" "$ROOTKIT_SCANNER_DETAIL"
        echo
        echo "============================================================="
        echo " SOFTWARE UPDATES"
        echo "============================================================="
        report_item "Control Panel" "N/A" "No control panel installed on this server"
        report_item "Operating System / Kernel" "$SYSTEM_UPDATE_STATUS" "$SYSTEM_LATEST"
        report_item "PHP" "$( [[ $PHP_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$PHP_UPDATE_COUNT pending update(s); installed: $PHP_VERSIONS; default: $PHP_DEFAULT"
        report_item "CMS" "$OUTDATED_CMS_STATUS" "$OUTDATED_CMS_DETAIL"
        report_item "Web Server" "$( [[ $HTTPD_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$HTTPD_UPDATE_COUNT pending web-server update(s)"
        report_item "Database Server" "$( [[ $MYSQL_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$MYSQL_UPDATE_COUNT pending database update(s)"
        report_item "Other Softwares" "$( [[ $OTHER_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$OTHER_UPDATE_COUNT other pending package(s)${OTHER_UPDATE_PKGS:+: $OTHER_UPDATE_PKGS}"
        echo
        echo "============================================================="
        echo " SERVER HEALTH"
        echo "============================================================="
        report_item "Server Uptime" "$UPTIME_STATUS" "$UPTIME"
        report_item "HTTP Uptime" "$HTTP_STATUS" "$HTTP_UPTIME"
        report_item "CPU Usage" "$CPU_STATUS" "Load average: $LOAD"
        report_item "RAM Usage" "$RAM_STATUS" "${RAM_PCT}% used"
        report_item "Disk Space Usage" "$DISK_STATUS" "${DISK_PCT}% used"
        report_item "Email Queue" "$EMAIL_STATUS" "Queued messages: $EMAIL_QUEUE"
        report_item "IP Reputation" "$IP_REPUTATION_STATUS" "$IP_REPUTATION_DETAIL"
        echo
        echo "============================================================="
        echo " BACKUP"
        echo "============================================================="
        report_item "Local Backup" "$BACKUP_STATUS" "$BACKUP_DETAIL"
        report_item "Remote Backup" "$BACKUP_REMOTE_STATUS" "$BACKUP_REMOTE_DETAIL"
        report_item "Daily Backup" "$BACKUP_DAILY_STATUS" "$BACKUP_DAILY_DETAIL"
        report_item "Weekly Backup" "$BACKUP_WEEKLY_STATUS" "$BACKUP_WEEKLY_DETAIL"
        report_item "Monthly Backup" "$BACKUP_MONTHLY_STATUS" "$BACKUP_MONTHLY_DETAIL"
        report_item "Backup Retention" "$BACKUP_RETENTION_STATUS" "$BACKUP_RETENTION_DETAIL"
        report_item "Recent Last Backup" "$BACKUP_LAST_STATUS" "$BACKUP_LAST_DETAIL"
        report_item "Size Of Last Backup" "$BACKUP_SIZE_STATUS" "$BACKUP_SIZE_DETAIL"
        echo
        echo "============================================================="
        echo " SOFTWARE LIFE TIME"
        echo "============================================================="
        report_item "Control Panel" "N/A" "No control panel installed on this server"
        report_item "Operating System" "$EOL_STATUS" "$DISTRO_NAME"
        report_item "Software Stack" "$PHP_EOL_STATUS" "$PHP_EOL_DETAIL"
        report_item "CMS Lifetime" "$OUTDATED_CMS_STATUS" "$OUTDATED_CMS_DETAIL"
        #report_item "Kernel Status" "$KERNEL_STATUS" "Kernel: $KERNEL_RUNNING; KernelCare: $KC_STATUS"
        echo
        echo "============================================================="
        echo " PROACTIVE DEFENCE"
        echo "============================================================="
        report_item "/tmp Security" "$TMP_SEC_STATUS" "$TMP_SEC_DETAIL"
        report_item "Reboot Procedure" "$REBOOT_PROC_STATUS" "$REBOOT_PROC_DETAIL"
        report_item "IP RDNS" "$RDNS_STATUS" "$RDNS_DETAIL"
        report_item "Malware Scan" "$MALWARE_RESULT_STATUS" "$MALWARE_RESULT_DETAIL"
        report_item "Rootkit Check" "$ROOTKIT_RESULT_STATUS" "$ROOTKIT_RESULT_DETAIL"
        report_item "SSH Root Access Security" "$ROOT_LOGIN_STATUS" "PermitRootLogin: $ROOT_LOGIN_RAW; PasswordAuth: $SSH_PASSWORD_AUTH; port(s): $SSH_PORT"
        report_item "PHP Functions Security" "$PHP_FUNC_STATUS" "$PHP_FUNC_DETAIL"
        report_item "Root Password Health" "$ROOT_PW_STATUS" "Changed approximately $DAYS_OLD day(s) ago"
    } > "$DETAILED_FILE"

    colorize_report < "$DETAILED_FILE"
}

generate_findings_log() {
    # Itemised hand-off log: retain each package/report entry under its category.
    findings_section() {
        local title="$1" entries="$2"
        printf '\n=============================================================\n%s\n=============================================================\n' "$title"
        if [[ -n "$entries" ]]; then
            printf '%s\n' "$entries"
        else
            echo "None"
        fi
    }

    {
        cat << EOF
BOBCARES AUDIT FINDINGS
Generated : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Hostname  : $HOSTNAME
Main IP   : $MAIN_IP
EOF
        findings_section "ALL PACKAGE UPDATES ($OS_UPDATE_COUNT)" "$UPDATE_ALL_LIST"
        findings_section "OPERATING SYSTEM / KERNEL UPDATES (${KERNEL_UPDATE_COUNT:-0})" "$KERNEL_UPDATE_LIST"
        findings_section "PHP UPDATES ($PHP_UPDATE_COUNT)" "$PHP_UPDATE_LIST"
        findings_section "WEB SERVER UPDATES ($HTTPD_UPDATE_COUNT)" "$HTTPD_UPDATE_LIST"
        findings_section "DATABASE UPDATES ($MYSQL_UPDATE_COUNT)" "$MYSQL_UPDATE_LIST"
        findings_section "OTHER SOFTWARE UPDATES ($OTHER_UPDATE_COUNT)" "$OTHER_UPDATE_LIST"
        findings_section "MALWARE SCAN ($(portal_status "$MALWARE_RESULT_STATUS"))" "$MALWARE_RESULT_DETAIL"
        if [[ -f /root/scripts/malware-details-report.txt ]]; then
            findings_section "MALWARE REPORT ENTRIES" "$(grep '^File: ' /root/scripts/malware-details-report.txt 2>/dev/null || true)"
        elif [[ -f /root/scripts/malware-files.txt ]]; then
            findings_section "MALWARE REPORT ENTRIES" "$(grep -vE '^[[:space:]]*(#|$)' /root/scripts/malware-files.txt 2>/dev/null || true)"
        fi
        findings_section "ROOTKIT CHECK ($(portal_status "$ROOTKIT_RESULT_STATUS"))" "$ROOTKIT_RESULT_DETAIL"
        if [[ -f /root/scripts/outdated-cms-report.txt ]]; then
            findings_section "CMS UPDATE REPORT ($(portal_status "$OUTDATED_CMS_STATUS"))" "$(cat /root/scripts/outdated-cms-report.txt)"
        elif [[ -f /root/scripts/malware-scan-report.txt ]] && grep -qi "Outdated CMS" /root/scripts/malware-scan-report.txt; then
            findings_section "CMS UPDATE REPORT ($(portal_status "$OUTDATED_CMS_STATUS"))" "$(grep -E '^\s*(PHPMailer|WordPress|Joomla|Drupal|Magento|PrestaShop|OpenCart|Shopify|WooCommerce)[[:space:]]+[0-9]' /root/scripts/malware-scan-report.txt 2>/dev/null || true)"
        else
            findings_section "CMS UPDATE REPORT (N/A)" "$OUTDATED_CMS_DETAIL"
        fi
    } > "$FINDINGS_FILE"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

main() {
    [[ $EUID -ne 0 ]] && echo "[WARN] Not running as root - several checks will be incomplete."

    SECURITY_ACTIONS=""
    export SECURITY_ACTIONS

    collect_os_details
    check_eol_status
    detect_vm
    detect_pkg_mgr

    echo "[DEBUG] Running parallel network lookups..."
    get_public_ip &
    wait $!
    load_all_state

    check_rdns "$MAIN_IP" &
    local rdns_pid=$!

    collect_system_info
    check_ssh_config
    check_system_firewall
    check_brute_force_protection
    check_root_password_age
    check_ip_reputation

    wait $rdns_pid
    load_all_state
    check_rdns_status

    setup_security_tools
    check_threat_tools
    check_package_updates
    check_kernel_status
    check_reboot_required
    check_reboot_procedure_info

    check_system_version
    check_modsecurity
    check_services
    check_ssl_expiry
    check_backups
    check_backup_extended
    check_php_and_users
    check_php_eol
    check_php_functions_security

    check_malware_scan_results
    check_rootkit_scan_results

    check_resource_usage

    # This audit is deliberately read-only: it never installs tools or starts scans.
    MALWARE_SCAN_STARTED="No (read-only audit)"
    export MALWARE_SCAN_STARTED

    generate_findings_log
    generate_smart_summary
    generate_detailed_log

    echo
    echo "Audit Complete!"
    echo "Findings Log  : $FINDINGS_FILE"
    echo "Smart Summary : $SUMMARY_FILE"
    echo "Detailed Log  : $DETAILED_FILE"
    echo "Debug Log     : $DEBUG_LOG"

    echo
    echo "===================== AUDIT SUMMARY ====================="
    echo
    echo "[INFO]    Audit report files are available in:"
    echo "          /root/scripts/"
    echo "          Please review them before submitting to the Bobcares portal."
    echo
    echo "[WARNING] System updates and malware scan results are read-only."
    echo "          Any issues found require manual intervention."
    echo
    echo "[WARNING] Backup status is based only on detected cron jobs and"
    echo "          backup directories. Please verify backup integrity manually."
    echo
    echo "[WARNING] External DC and offsite backups are NOT verified"
    echo "          by this audit. Please validate them separately."
    echo
    echo "[ACTION]  If no malware scanner is configured, install one"
    echo "          and perform a full malware scan."
    echo
    echo "========================================================="
}

main "$@"
