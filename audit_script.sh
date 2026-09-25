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
# Require root privileges (allow --view without root if reviewing existing reports)
is_view_mode=false
for arg in "$@"; do
    case "$arg" in
        --view|-v|view|--tui-only) is_view_mode=true ;;
    esac
done
if [[ $EUID -ne 0 && "$is_view_mode" != "true" ]]; then
    echo "[ERROR] This audit script must be run as root."
    echo
    echo "Please run the script again using one of the following:"
    echo
    echo "  curl -L https://tinyurl.com/genericaudit | bash"
    echo "  curl -fsSL https://tinyurl.com/genericaudit | bash"
    echo
    exit 1
fi

SCRIPT_DIR="/root/scripts"
SUMMARY_FILE="$SCRIPT_DIR/audit-smart-summary.md"
DETAILED_FILE="$SCRIPT_DIR/report-detailed.log"
FINDINGS_FILE="$SCRIPT_DIR/audit-findings.log"
RECOMMENDATIONS_FILE="$SCRIPT_DIR/audit-issues-recommendations.log"
DEBUG_LOG="$SCRIPT_DIR/audit-debug.log"

STATE_DIR=$(mktemp -d /tmp/bc-audit.XXXXXX)
TUI_OLD_STTY=""

cleanup_terminal() {
    # Reset terminal modes:
    # Disable mouse tracking (?1000l ?1002l ?1003l ?1006l ?1015l)
    # Disable alternate screen wheel translation (?1007l)
    # Re-enable line wrap (?7h), show cursor (?25h), reset colors (\033[0m), exit alternate screen (?1049l)
    local reset_seq=$'\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1015l\033[?1007l\033[?7h\033[?25h\033[0m\033[?1049l'
    if [ -n "${3+x}" ] && [ -w /dev/fd/3 ] 2>/dev/null; then
        printf '%s' "$reset_seq" >&3 2>/dev/null
    fi
    if [ -c /dev/tty ] && [ -w /dev/tty ]; then
        printf '%s' "$reset_seq" > /dev/tty 2>/dev/null
    fi
    printf '%s' "$reset_seq" 2>/dev/null

    if [[ -n "$TUI_OLD_STTY" ]]; then
        if [ -c /dev/tty ] && [ -r /dev/tty ]; then
            stty "$TUI_OLD_STTY" < /dev/tty 2>/dev/null
        fi
        stty "$TUI_OLD_STTY" 2>/dev/null
    fi

    # Failsafe: unconditionally restore standard healthy terminal discipline (echo, canonical, signals, newline conversion)
    for _dev in "/dev/tty" "/dev/stdin"; do
        if [ -r "$_dev" ]; then
            stty echo icanon iexten isig opost onlcr < "$_dev" 2>/dev/null
        fi
    done
    stty echo icanon iexten isig opost onlcr 2>/dev/null
    exec 3>&- 3<&- 2>/dev/null || true
}

full_cleanup() {
    cleanup_terminal
    if [[ -n "$STATE_DIR" && -d "$STATE_DIR" ]]; then
        rm -rf "$STATE_DIR" 2>/dev/null || true
    fi
}

trap 'full_cleanup; exit 130' INT
trap 'full_cleanup; exit 143' TERM
trap 'full_cleanup' EXIT


if [[ "$is_view_mode" != "true" ]]; then
    mkdir -p "$SCRIPT_DIR" 2>/dev/null || true
    if [ -f "$DEBUG_LOG" ]; then
        mv -f "$DEBUG_LOG" "${DEBUG_LOG}.prev" 2>/dev/null || rm -f "$DEBUG_LOG"
    fi
    exec > >(stdbuf -o0 tr -cd '\11\12\15\33\40-\176' | tee -a "$DEBUG_LOG") 2>&1
    echo "=== Starting Bobcares Smart Audit at $(date) ==="
    echo "Debug log: $DEBUG_LOG | State dir: $STATE_DIR"
    echo
else
    mkdir -p "$SCRIPT_DIR" 2>/dev/null || true
    if [[ ! -w "$SCRIPT_DIR" ]]; then
        DEBUG_LOG="/tmp/audit-debug.log"
    fi
fi

RUN_ANYWAY=false
if [[ "${RUNANYWAY:-0}" == "1" || "${RUN_ANYWAY:-0}" == "1" || "${RUNANYWAY}" == "true" || "${FORCE:-0}" == "1" ]]; then
    RUN_ANYWAY=true
fi
LAUNCH_TUI=false
NO_TUI=false
VIEW_ONLY=false
if [[ "${TUI:-0}" == "1" || "${TUI}" == "true" ]]; then
    LAUNCH_TUI=true
fi
for arg in "$@"; do
    case "$arg" in
        --runanyway|--run-anyway|-f|--force|runanyway|force)
            RUN_ANYWAY=true
            ;;
        --tui|-t|tui)
            LAUNCH_TUI=true
            ;;
        --no-tui|no-tui)
            NO_TUI=true
            ;;
        --view|-v|view|--tui-only)
            VIEW_ONLY=true
            LAUNCH_TUI=true
            ;;
    esac
done

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
    elif [ -d /usr/local/webuzo ] || [ -f /usr/local/webuzo/version ]; then
        detected_panel="Webuzo"
    elif [ -d /etc/webmin ] || [ -d /usr/libexec/webmin ]; then
        detected_panel="Webmin / Virtualmin"
    fi

    if [[ -n "$detected_panel" ]]; then
        if [[ "$RUN_ANYWAY" == "true" ]]; then
            echo "[WARNING] Detected control panel '$detected_panel', but runanyway option was supplied. Proceeding with audit..."
            echo
        else
            echo "[ERROR] This script is for no panel server. This server has the panel '$detected_panel'."
            echo "If you wish to run the audit anyway, execute the script using one of the following:"
            echo
            echo "  RUNANYWAY=1 curl -L https://tinyurl.com/genericaudit | bash"
            echo "  curl -L https://tinyurl.com/genericaudit | bash -s runanyway"
            echo
            exit 1
        fi
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
    PHP_FUNC_DETAIL="No php.ini files or PHP binaries found"

    local raw_inis=() ini
    # System-wide php.ini files search across common directories
    while IFS= read -r ini; do
        [[ -f "$ini" ]] && raw_inis+=("$ini")
    done < <(find /etc /usr/local /opt /usr -maxdepth 6 -type f -name 'php.ini' 2>/dev/null)

    # Query installed PHP executables for loaded php.ini
    local php_bins=()
    while IFS= read -r pbin; do
        [[ -x "$pbin" ]] && php_bins+=("$pbin")
        local loaded_ini
        loaded_ini=$("$pbin" --ini 2>/dev/null | awk -F: '/Loaded Configuration File:/{print $2}' | tr -d ' \t\r\n')
        if [[ -n "$loaded_ini" && -f "$loaded_ini" && "$loaded_ini" != "(none)" ]]; then
            raw_inis+=("$loaded_ini")
        fi
    done < <(find /usr /opt /usr/local -type f -name 'php*' -executable 2>/dev/null | grep -E '/bin/php[0-9.]*$' || true)

    # PHP-FPM pool configs that may override disable_functions
    while IFS= read -r ini; do
        [[ -f "$ini" ]] && raw_inis+=("$ini")
    done < <(find /etc /usr/local /opt -maxdepth 6 -type f -name '*.conf' 2>/dev/null | xargs grep -l 'disable_functions' 2>/dev/null || true)

    local inis=()
    if [[ ${#raw_inis[@]} -gt 0 ]]; then
        mapfile -t inis < <(printf '%s\n' "${raw_inis[@]}" | sort -u | grep -v '^$')
    fi

    if [[ ${#inis[@]} -eq 0 && ${#php_bins[@]} -eq 0 ]]; then
        export PHP_FUNC_STATUS PHP_FUNC_DETAIL
        return
    fi

    local fully_secured=0 partial_secured=0 insecure=()
    local funcs=("exec" "shell_exec" "system" "passthru")

    if [[ ${#inis[@]} -gt 0 ]]; then
        for ini in "${inis[@]}"; do
            local df
            df=$(grep -iE '^[[:space:]]*disable_functions[[:space:]]*=' "$ini" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d ' "')

            if [[ -z "$df" ]]; then
                insecure+=("$ini")
                continue
            fi

            local matched=0
            for f in "${funcs[@]}"; do
                if grep -qE "(^|,)${f}(,|$)" <<<"$df"; then
                    ((matched++))
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
    fi

    if [[ ${#php_bins[@]} -gt 0 ]]; then
        for pbin in "${php_bins[@]}"; do
            local runtime_df
            runtime_df=$("$pbin" -r "echo ini_get('disable_functions');" 2>/dev/null | tr -d ' ')
            if [[ -z "$runtime_df" ]]; then
                insecure+=("$pbin")
                continue
            fi

            local matched=0
            for f in "${funcs[@]}"; do
                if grep -qE "(^|,)${f}(,|$)" <<<"$runtime_df"; then
                    ((matched++))
                fi
            done

            if (( matched == ${#funcs[@]} )); then
                ((fully_secured++))
            elif (( matched > 0 )); then
                ((partial_secured++))
                insecure+=("$pbin")
            else
                insecure+=("$pbin")
            fi
        done
    fi

    local insecure_uniq=()
    if [[ ${#insecure[@]} -gt 0 ]]; then
        mapfile -t insecure_uniq < <(printf '%s\n' "${insecure[@]}" | sort -u | grep -v '^$')
    fi
    PHP_INSECURE_LIST=$(printf '%s, ' "${insecure_uniq[@]}" | sed 's/, $//')

    if [[ ${#insecure_uniq[@]} -eq 0 && fully_secured -gt 0 ]]; then
        PHP_FUNC_STATUS="Good"
        PHP_FUNC_DETAIL="Dangerous functions (exec, shell_exec, system, passthru) disabled in all PHP environments"
    else
        PHP_FUNC_STATUS="Not set"
        PHP_FUNC_DETAIL="Dangerous PHP functions (exec, shell_exec, system, passthru) are not disabled"
    fi

    export PHP_FUNC_STATUS PHP_FUNC_DETAIL PHP_INSECURE_LIST
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

get_formatted_eol_php() {
    local v e found=()
    for v in $(echo "$PHP_VERSIONS" | tr ',' ' '); do
        v=$(echo "$v" | xargs)
        [[ -z "$v" ]] && continue
        [[ "$v" =~ ^([0-9]+\.[0-9]+) ]] && v="${BASH_REMATCH[1]}"
        for e in "${PHP_EOL_LIST[@]}"; do
            if [[ "$v" == "$e" ]]; then
                local exists=0
                for f in "${found[@]}"; do [[ "$f" == "$v" ]] && exists=1 && break; done
                [[ $exists -eq 0 ]] && found+=("$v")
                break
            fi
        done
    done

    if [[ ${#found[@]} -eq 0 ]]; then
        echo "PHP"
        return
    fi

    local res=""
    local i
    for (( i=0; i<${#found[@]}; i++ )); do
        if (( i == 0 )); then
            res="PHP ${found[i]}"
        elif (( i == ${#found[@]} - 1 )); then
            res="${res} and PHP ${found[i]}"
        else
            res="${res}, PHP ${found[i]}"
        fi
    done
    echo "$res"
}

get_malware_findings_list() {
    local list=""
    if [[ -f /root/scripts/malware-details-report.txt ]]; then
        list=$(grep '^File: ' /root/scripts/malware-details-report.txt 2>/dev/null | head -20)
    elif [[ -f /root/scripts/malware-files.txt ]]; then
        list=$(grep -vE '^[[:space:]]*(#|$)' /root/scripts/malware-files.txt 2>/dev/null | head -20)
    fi
    if [[ -n "$list" ]]; then
        printf '\nFindings Log entries:\n%s' "$list"
    fi
}

get_cms_findings_list() {
    local list=""
    if [[ -f /root/scripts/outdated-cms-report.txt ]]; then
        list=$(cat /root/scripts/outdated-cms-report.txt 2>/dev/null | head -20)
    elif [[ -f /root/scripts/malware-scan-report.txt ]] && grep -qi "Outdated CMS" /root/scripts/malware-scan-report.txt; then
        list=$(grep -E '^\s*(PHPMailer|WordPress|Joomla|Drupal|Magento|PrestaShop|OpenCart|Shopify|WooCommerce)[[:space:]]+[0-9]' /root/scripts/malware-scan-report.txt 2>/dev/null | head -20)
    fi
    if [[ -n "$list" ]]; then
        printf '\nFindings Log entries:\n%s' "$list"
    fi
}

get_update_findings_list() {
    local input="$1"
    if [[ -n "$input" ]]; then
        local head_out
        head_out=$(echo "$input" | head -15)
        printf '\nFindings Log entries:\n%s' "$head_out"
    fi
}

get_red_issue_and_rec() {
    local key="$1"
    ITEM_ISSUE=""
    ITEM_RECOMMENDATION=""

    case "$key" in
        "system_firewall")
            ITEM_ISSUE="Firewall and CSF are not installed or active on the server (${SYSTEM_FIREWALL_ANALYSIS:-No active firewall detected})."
            ITEM_RECOMMENDATION="Firewall and CSF are not installed or active on the server. Kindly let us know if we can enable it."
            ;;
        "malware_scanner")
            ITEM_ISSUE="Automated malware scanner is missing or inactive on the server ($MALWARE_SCANNER_DETAIL)."
            ITEM_RECOMMENDATION="Automated malware scanner is missing or inactive on the server. We recommend installing ClamAV and setting up regular malware scanning."
            ;;
        "brute_force")
            ITEM_ISSUE="Failed login detection is not active on the server ($BRUTE_REASON)."
            ITEM_RECOMMENDATION="Failed login detection is not enabled on the server. We recommend enabling Fail2Ban to protect the server against brute-force login attempts."
            ;;
        "waf")
            ITEM_ISSUE="Web Application Firewall (ModSecurity) is disabled on your server ($MODSEC_REASON)."
            ITEM_RECOMMENDATION="Mod_Security is disabled. It is reccomended to enable mod_security to protect web applications from attacks. Web Application Firewall(ModSecurity) is disabled on your server. Web Application Firewall is used to protect web server from various types of attacks such as XSS, bots, SQL-injection, capture session, trojans, session hijacking, etc. Please confirm if you want this enabled."
            ;;
        "rootkit_scanner")
            ITEM_ISSUE="Rootkit scanner tools are missing on the server ($ROOTKIT_SCANNER_DETAIL)."
            ITEM_RECOMMENDATION="Rootkit scanner is missing on the server. We recommend installing rkhunter and chkrootkit to scan for potential rootkit infections."
            ;;
        "os_kernel_update")
            ITEM_ISSUE="Operating System / Kernel updates available (${KERNEL_UPDATE_COUNT:-0} pending package update(s))"
            ITEM_RECOMMENDATION="Kernel and OS updates are available. We recommend scheduling the upgrade in off-peak hours to minimize the impact on customers and website users. Please let us know your preferred date & time (time zone) to schedule the upgrade."
            ;;
        "php_update")
            ITEM_ISSUE="PHP package updates are available (${PHP_UPDATE_COUNT:-0} pending update(s))"
            ITEM_RECOMMENDATION="PHP updates are available. We recommend scheduling the upgrade in off-peak hours to minimize the impact on customers and website users. Please let us know your preferred date & time (time zone) to schedule the upgrade."
            ;;
        "cms_update")
            ITEM_ISSUE="Detected websites with outdated CMS installations"
            ITEM_RECOMMENDATION="Detected websites with outdated CMS installations. Please note that outdated CMS are always prone to hacking and attacks. You need to update the CMS to the latest version in order to avoid further attacks in the server."
            ;;
        "web_server_update")
            ITEM_ISSUE="Web server package updates are available (${HTTPD_UPDATE_COUNT:-0} pending update(s))"
            ITEM_RECOMMENDATION="Web server updates are available. We recommend scheduling the upgrade in off-peak hours to minimize the impact on customers and website users. Please let us know your preferred date & time (time zone) to schedule the upgrade."
            ;;
        "db_server_update")
            ITEM_ISSUE="Database server package updates are available (${MYSQL_UPDATE_COUNT:-0} pending update(s))"
            ITEM_RECOMMENDATION="Database updates are available. We recommend scheduling the upgrade in off-peak hours to minimize the impact on customers and website users. Please let us know your preferred date & time (time zone) to schedule the upgrade."
            ;;
        "other_update")
            ITEM_ISSUE="Other software updates are available (${OTHER_UPDATE_COUNT:-0} pending package(s))"
            ITEM_RECOMMENDATION="System package updates are available. We recommend scheduling the upgrade in off-peak hours to minimize the impact on customers and website users. Please let us know your preferred date & time (time zone) to schedule the upgrade."
            ;;
        "kernel_update")
            ITEM_ISSUE="Kernel updates are available ($KERNEL_ANALYSIS)"
            ITEM_RECOMMENDATION="Pending kernel updates are available. We recommend scheduling the kernel update during off-peak hours, as a reboot will be required."
            ;;
        "reboot_required")
            ITEM_ISSUE="Reboot required on server ($REBOOT_REASON)."
            ITEM_RECOMMENDATION="Pending system kernel or core package updates require a system reboot. We recommend scheduling the server reboot during off-peak hours to minimize service downtime."
            ;;
        "http_uptime")
            ITEM_ISSUE="Web server service is stopped or failed ($HTTP_STATUS)."
            ITEM_RECOMMENDATION="Web server service is down. We recommend checking web server error logs and restarting the web service."
            ;;
        "cpu_usage")
            ITEM_ISSUE="Server CPU load average is critical (Load: $LOAD)."
            ITEM_RECOMMENDATION="Server is generating large number of alerts, indicating serious health issues for the server."
            ;;
        "ram_usage")
            ITEM_ISSUE="Server RAM utilization is high (${RAM_PCT}% used)."
            ITEM_RECOMMENDATION="Server is generating large number of alerts, indicating serious health issues for the server."
            ;;
        "disk_space")
            ITEM_ISSUE="The disk space is critical on the server, it is reached ${DISK_PCT}% under '/' directory."
            ITEM_RECOMMENDATION="The disk space is critical on the server, it is reached ${DISK_PCT}% under '/' directory. We recommend clearing unnecessary files or extending disk space."
            ;;
        "email_queue")
            ITEM_ISSUE="Email queue backlog is high ($EMAIL_QUEUE messages)."
            ITEM_RECOMMENDATION="Email queue is generating large number of alerts. We recommend inspecting queue messages for potential spam script execution."
            ;;
        "ip_reputation")
            ITEM_ISSUE="IP address of the server ($MAIN_IP) is blocked in BARRACUDA and SORBS SPAM ($IP_REPUTATION_DETAIL)."
            ITEM_RECOMMENDATION="IP address of the server is blocked in BARRACUDA and SORBS SPAM. Kindly check mail logs and apply for delisting."
            ;;
        "local_backup")
            ITEM_ISSUE="Local backup not found on the server ($BACKUP_DETAIL)."
            ITEM_RECOMMENDATION="Backup is not configured in the server. We recommend regular backups to be taken for your account so that in case any critical issue arises, you can safely revert to an old copy of your account."
            ;;
        "remote_backup")
            ITEM_ISSUE="Remote backup not found on the server ($BACKUP_REMOTE_DETAIL)."
            ITEM_RECOMMENDATION="Remote backup is not configured on the server. We recommend configuring remote backups so that in case of complete server or hardware failure where local backups cannot be recovered, you can safely restore your accounts from an offsite copy."
            ;;
        "daily_backup")
            ITEM_ISSUE="Daily backup schedule is not configured on the server."
            ITEM_RECOMMENDATION="Backup is not configured in the server. We recommend regular backups to be taken for your account so that in case any critical issue arises, you can safely revert to an old copy of your account."
            ;;
        "weekly_backup")
            ITEM_ISSUE="Weekly backup schedule is not configured on the server."
            ITEM_RECOMMENDATION="Backup is not configured in the server. We recommend regular backups to be taken for your account so that in case any critical issue arises, you can safely revert to an old copy of your account."
            ;;
        "monthly_backup")
            ITEM_ISSUE="Monthly backup schedule is not configured on the server."
            ITEM_RECOMMENDATION="Backup is not configured in the server. We recommend regular backups to be taken for your account so that in case any critical issue arises, you can safely revert to an old copy of your account."
            ;;
        "backup_retention")
            ITEM_ISSUE="Backup retention schedule is not configured on the server."
            ITEM_RECOMMENDATION="We recommend defining a proper backup retention policy to keep safe recovery points."
            ;;
        "backup_last")
            ITEM_ISSUE="Recent backup archive is stale or missing ($BACKUP_LAST_DETAIL)."
            ITEM_RECOMMENDATION="Backup is not configured properly in the server. We recommend regular backups to be taken for your account so that in case any critical issue arises, you can safely revert to an old copy of your account."
            ;;
        "backup_size")
            ITEM_ISSUE="Size of last backup archive cannot be verified or is empty."
            ITEM_RECOMMENDATION="We recommend verifying backup archive files to ensure complete backup copies."
            ;;
        "os_eol")
            ITEM_ISSUE="Running End Of Life Operating system ($OS_NAME $OS_VERSION)."
            ITEM_RECOMMENDATION="Running End Of Life Operating system is a major security risk as it would contain unpatched vulnerabilities and exploits that could be used to hack your server and steal critical business data & personally identifiable information of your customers. We recommend arranging a migration of websites and services to a new server as soon as possible as it is not feasible to upgrade the End Of Life Operating system."
            ;;
        "software_stack")
            local eol_php
            eol_php=$(get_formatted_eol_php)
            ITEM_ISSUE="End of Life PHP version(s) detected: $eol_php"
            ITEM_RECOMMENDATION="$eol_php reached End of Life, and are no longer receiving any security patches from PHP. This means it will no longer have security support and could be exposed to unpatched security vulnerabilities. We recommend to update PHP version to 8.0 or higher."
            ;;
        "tmp_security")
            ITEM_ISSUE="/tmp directory is not mounted with noexec."
            ITEM_RECOMMENDATION="/tmp is not secure, which can lead to malicious scripts executing in it. Please confirm if we can secure /tmp."
            ;;
        "reboot_procedure")
            ITEM_ISSUE="Remote reboot portal access or reboot procedure details are not documented ($REBOOT_PROC_DETAIL)."
            ITEM_RECOMMENDATION="We do not have the remote reboot portal access or details. Please submit your Datacenter logins and reboot procedure securely from Bobcares Client Area: https://portal.bobcares.com/website-add , so that we can contact the DC or initiate a reboot in case any issues are noted with the server."
            ;;
        "ip_rdns")
            ITEM_ISSUE="IP RDNS is not configured properly in your server ($RDNS_DETAIL)."
            ITEM_RECOMMENDATION="IP RDNS is not configured properly in your server."
            ;;
        "malware_scan")
            ITEM_ISSUE="Malware scripts found in the server ($MALWARE_RESULT_DETAIL)."
            ITEM_RECOMMENDATION="Malware scripts found in the server. Please see the malware list in the report and let us know if we can go ahead and delete those."
            ;;
        "rootkit_check")
            ITEM_ISSUE="Rootkit scan flagged suspicious results ($ROOTKIT_RESULT_DETAIL)."
            ITEM_RECOMMENDATION="Rootkit scan found suspicious items on the server. Please inspect rootkit scan logs and verify server integrity."
            ;;
        "ssh_root")
            ITEM_ISSUE="Direct SSH root login is enabled in the server (PermitRootLogin: $ROOT_LOGIN_RAW)."
            ITEM_RECOMMENDATION="Root login is enabled in the server. It's always advisable to disable this feature to enhance server security."
            ;;
        "php_functions")
            local issue_detail="$PHP_FUNC_DETAIL"
            if [[ -n "${PHP_INSECURE_LIST:-}" ]]; then
                issue_detail="Dangerous PHP functions (exec, shell_exec, system, passthru) are not disabled in: $PHP_INSECURE_LIST"
            fi
            ITEM_ISSUE="PHP dangerous functions are found to be enabled on the server ($issue_detail)."
            ITEM_RECOMMENDATION="PHP dangerous functions are found to be enabled in the server. Dangerous PHP functions can cause security issues on the server. They must be disabled for preventing unauthorized execution of code on the server."
            ;;
        "root_password")
            ITEM_ISSUE="Root password has not been updated within 90 days (approximately ${DAYS_OLD:-999} days old)."
            ITEM_RECOMMENDATION="We recommend updating root password every 90 days to enhance server security."
            ;;
        "ssl_certificates")
            ITEM_ISSUE="SSL certificate is expired ($SSL_EXPIRY)."
            ITEM_RECOMMENDATION="SSL certificate has expired. We recommend renewing the SSL certificate to prevent browser warnings."
            ;;
        *)
            ITEM_ISSUE="Issue detected: $label ($det)"
            ITEM_RECOMMENDATION="Investigate and remediate $label to restore normal system operations."
            ;;
    esac
}



report_item() {
    # $1: audit item, $2: raw status, $3: human-readable details
    printf '  %-38s : %-6s - %s\n' "$1" "$(portal_status "$2")" "$3"
}

colorize_report() {
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

colorize_recommendations() {
    if [[ "${NO_COLOR:-}" == "1" ]]; then
        cat
        return
    fi

    local reset bold red green yellow cyan grey
    reset=$(tput sgr0 2>/dev/null || printf '\033[0m')
    bold=$(tput bold 2>/dev/null || printf '\033[1m')
    red=$(tput setaf 1 2>/dev/null || printf '\033[31m')
    green=$(tput setaf 2 2>/dev/null || printf '\033[32m')
    yellow=$(tput setaf 3 2>/dev/null || printf '\033[33m')
    cyan=$(tput setaf 6 2>/dev/null || printf '\033[36m')
    grey=$(tput setaf 8 2>/dev/null || printf '\033[90m')

    [[ -n "$reset" ]] || reset=$'\033[0m'
    [[ -n "$bold" ]] || bold=$'\033[1m'
    [[ -n "$red" ]] || red=$'\033[31m'
    [[ -n "$green" ]] || green=$'\033[32m'
    [[ -n "$yellow" ]] || yellow=$'\033[33m'
    [[ -n "$cyan" ]] || cyan=$'\033[36m'
    [[ -n "$grey" ]] || grey=$'\033[90m'

    awk -v reset="$reset" -v bold="$bold" -v red="$red" -v green="$green" -v yellow="$yellow" -v cyan="$cyan" -v grey="$grey" '
        /^=============================================================/ { print cyan bold $0 reset; next }
        /^[[:space:]]*\[[0-9]+\] Sub Category:/ { print bold yellow $0 reset; next }
        /^[[:space:]]*Issue:/ { print bold red $0 reset; next }
        /^[[:space:]]*Recommendation:/ { print bold green $0 reset; next }
        /^-------------------------------------------------------------/ { print grey $0 reset; next }
        { print $0 }
    '
}

generate_issues_and_recommendations_log() {
    local items=(
        "System Firewall|system_firewall|Threat Protection"
        "Malware Scanner|malware_scanner|Threat Protection"
        "Failed Login Detection|brute_force|Threat Protection"
        "Web App Firewall|waf|Threat Protection"
        "Rootkit Scanner|rootkit_scanner|Threat Protection"
        "Operating System / Kernel Updates|os_kernel_update|Software Updates"
        "PHP Updates|php_update|Software Updates"
        "CMS Updates|cms_update|Software Updates"
        "Web Server Updates|web_server_update|Software Updates"
        "Database Server Updates|db_server_update|Software Updates"
        "Other Software Updates|other_update|Software Updates"
        "Reboot Required|reboot_required|Software Updates"
        "HTTP Uptime|http_uptime|Server Health"
        "CPU Usage|cpu_usage|Server Health"
        "RAM Usage|ram_usage|Server Health"
        "Disk Space Usage|disk_space|Server Health"
        "Email Queue|email_queue|Server Health"
        "IP Reputation|ip_reputation|Server Health"
        "Local Backup|local_backup|Backup"
        "Remote Backup|remote_backup|Backup"
        "Daily Backup|daily_backup|Backup"
        "Weekly Backup|weekly_backup|Backup"
        "Monthly Backup|monthly_backup|Backup"
        "Backup Retention|backup_retention|Backup"
        "Recent Last Backup|backup_last|Backup"
        "Size Of Last Backup|backup_size|Backup"
        "Operating System EOL|os_eol|Software Life Time"
        "Software Stack (PHP EOL)|software_stack|Software Life Time"
        "/tmp Security|tmp_security|Proactive Defence"
        "Reboot Procedure|reboot_procedure|Proactive Defence"
        "IP RDNS|ip_rdns|Proactive Defence"
        "Malware Scan Results|malware_scan|Proactive Defence"
        "Rootkit Check Results|rootkit_check|Proactive Defence"
        "SSH Root Access Security|ssh_root|Proactive Defence"
        "PHP Functions Security|php_functions|Proactive Defence"
        "Root Password Health|root_password|Proactive Defence"
        "SSL Certificates|ssl_certificates|Additional Checks"
    )

    {
        echo "============================================================="
        echo " ISSUES & RECOMMENDATIONS (RED ITEMS)"
        echo "============================================================="
        printf '  %-38s : %s\n' "Hostname" "$HOSTNAME"
        printf '  %-38s : %s\n' "Audit Date" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        printf '  %-38s : %s\n' "Primary IP" "$MAIN_IP"
        echo

        local count=0
        local entry label key cat_name
        for entry in "${items[@]}"; do
            IFS='|' read -r label key cat_name <<< "$entry"
            get_red_issue_and_rec "$key"
            if [[ -n "$ITEM_ISSUE" && -n "$ITEM_RECOMMENDATION" ]]; then
                ((count++))
                echo "-------------------------------------------------------------"
                echo "  [$count] Sub Category: $label ($cat_name)"
                echo "-------------------------------------------------------------"
                echo "    Issue:"
                echo "$ITEM_ISSUE" | sed 's/^/      /'
                echo
                echo "    Recommendation:"
                echo "$ITEM_RECOMMENDATION" | sed 's/^/      /'
                echo
            fi
        done

        if (( count == 0 )); then
            echo "-------------------------------------------------------------"
            echo "  No RED issues detected during this audit."
            echo "-------------------------------------------------------------"
        else
            echo "-------------------------------------------------------------"
        fi
    } > "$RECOMMENDATIONS_FILE"
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

**Recommendation:** Review all RED items above. Prioritise pending security updates, reboot if required, enable or verify backups, and investigate IP reputation if listed. N/A items need a manual check where applicable.
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
        report_item "System Firewall" "$SYSTEM_FIREWALL_STATUS" "$SYSTEM_FIREWALL_ANALYSIS" "system_firewall"
        report_item "Malware Scanner" "$MALWARE_SCANNER_STATUS" "$MALWARE_SCANNER_DETAIL" "malware_scanner"
        report_item "Failed Login Detection" "$BRUTE_STATUS" "$BRUTE_REASON" "brute_force"
        report_item "Web Application Firewall" "$MODSEC_STATUS" "$MODSEC_REASON" "waf"
        report_item "Rootkit Scanner" "$ROOTKIT_SCANNER_STATUS" "$ROOTKIT_SCANNER_DETAIL" "rootkit_scanner"
        echo
        echo "============================================================="
        echo " SOFTWARE UPDATES"
        echo "============================================================="
        report_item "Control Panel" "N/A" "No control panel installed on this server"
        report_item "Operating System / Kernel" "$SYSTEM_UPDATE_STATUS" "$SYSTEM_LATEST" "os_kernel_update"
        report_item "PHP" "$( [[ $PHP_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$PHP_UPDATE_COUNT pending update(s); installed: $PHP_VERSIONS; default: $PHP_DEFAULT" "php_update"
        report_item "CMS" "$OUTDATED_CMS_STATUS" "$OUTDATED_CMS_DETAIL" "cms_update"
        report_item "Web Server" "$( [[ $HTTPD_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$HTTPD_UPDATE_COUNT pending web-server update(s)" "web_server_update"
        report_item "Database Server" "$( [[ $MYSQL_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$MYSQL_UPDATE_COUNT pending database update(s)" "db_server_update"
        report_item "Other Softwares" "$( [[ $OTHER_UPDATE_COUNT -gt 0 ]] && echo 'Update Available' || echo 'Good' )" "$OTHER_UPDATE_COUNT other pending package(s)${OTHER_UPDATE_PKGS:+: $OTHER_UPDATE_PKGS}" "other_update"
        echo
        echo "============================================================="
        echo " SERVER HEALTH"
        echo "============================================================="
        report_item "Server Uptime" "$UPTIME_STATUS" "$UPTIME"
        report_item "HTTP Uptime" "$HTTP_STATUS" "$HTTP_UPTIME" "http_uptime"
        report_item "CPU Usage" "$CPU_STATUS" "Load average: $LOAD" "cpu_usage"
        report_item "RAM Usage" "$RAM_STATUS" "${RAM_PCT}% used" "ram_usage"
        report_item "Disk Space Usage" "$DISK_STATUS" "${DISK_PCT}% used" "disk_space"
        report_item "Email Queue" "$EMAIL_STATUS" "Queued messages: $EMAIL_QUEUE" "email_queue"
        report_item "IP Reputation" "$IP_REPUTATION_STATUS" "$IP_REPUTATION_DETAIL" "ip_reputation"
        echo
        echo "============================================================="
        echo " BACKUP"
        echo "============================================================="
        report_item "Local Backup" "$BACKUP_STATUS" "$BACKUP_DETAIL" "local_backup"
        report_item "Remote Backup" "$BACKUP_REMOTE_STATUS" "$BACKUP_REMOTE_DETAIL" "remote_backup"
        report_item "Daily Backup" "$BACKUP_DAILY_STATUS" "$BACKUP_DAILY_DETAIL" "daily_backup"
        report_item "Weekly Backup" "$BACKUP_WEEKLY_STATUS" "$BACKUP_WEEKLY_DETAIL" "weekly_backup"
        report_item "Monthly Backup" "$BACKUP_MONTHLY_STATUS" "$BACKUP_MONTHLY_DETAIL" "monthly_backup"
        report_item "Backup Retention" "$BACKUP_RETENTION_STATUS" "$BACKUP_RETENTION_DETAIL" "backup_retention"
        report_item "Recent Last Backup" "$BACKUP_LAST_STATUS" "$BACKUP_LAST_DETAIL" "backup_last"
        report_item "Size Of Last Backup" "$BACKUP_SIZE_STATUS" "$BACKUP_SIZE_DETAIL" "backup_size"
        echo
        echo "============================================================="
        echo " SOFTWARE LIFE TIME"
        echo "============================================================="
        report_item "Control Panel" "N/A" "No control panel installed on this server"
        report_item "Operating System" "$EOL_STATUS" "$DISTRO_NAME" "os_eol"
        report_item "Software Stack" "$PHP_EOL_STATUS" "$PHP_EOL_DETAIL" "software_stack"
        report_item "CMS Lifetime" "$OUTDATED_CMS_STATUS" "$OUTDATED_CMS_DETAIL" "cms_update"
        echo
        echo "============================================================="
        echo " PROACTIVE DEFENCE"
        echo "============================================================="
        report_item "/tmp Security" "$TMP_SEC_STATUS" "$TMP_SEC_DETAIL" "tmp_security"
        report_item "Reboot Procedure" "$REBOOT_PROC_STATUS" "$REBOOT_PROC_DETAIL" "reboot_procedure"
        report_item "IP RDNS" "$RDNS_STATUS" "$RDNS_DETAIL" "ip_rdns"
        report_item "Malware Scan" "$MALWARE_RESULT_STATUS" "$MALWARE_RESULT_DETAIL" "malware_scan"
        report_item "Rootkit Check" "$ROOTKIT_RESULT_STATUS" "$ROOTKIT_RESULT_DETAIL" "rootkit_check"
        report_item "SSH Root Access Security" "$ROOT_LOGIN_STATUS" "PermitRootLogin: $ROOT_LOGIN_RAW; PasswordAuth: $SSH_PASSWORD_AUTH; port(s): $SSH_PORT" "ssh_root"
        report_item "PHP Functions Security" "$PHP_FUNC_STATUS" "$PHP_FUNC_DETAIL" "php_functions"
        report_item "Root Password Health" "$ROOT_PW_STATUS" "Changed approximately $DAYS_OLD day(s) ago" "root_password"
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
# GoAccess-Style Interactive Terminal UI (TUI) Dashboard
#-------------------------------------------------------------------------------

tui_fit_str() {
    local str="$1" max_len="$2"
    if (( ${#str} > max_len )); then
        if (( max_len > 3 )); then
            printf '%s…' "${str:0:$((max_len - 1))}"
        else
            printf '%.*s' "$max_len" "$str"
        fi
    else
        printf '%-*s' "$max_len" "$str"
    fi
}

tui_repeat_char() {
    local char="$1" count="$2"
    if (( count <= 0 )); then return; fi
    local v
    printf -v v '%*s' "$count" ''
    printf '%s' "${v// /$char}"
}

tui_get_cat_items() {
    local cat_idx="$1"
    case "$cat_idx" in
        0)
            echo "System Firewall|$(portal_status "$SYSTEM_FIREWALL_STATUS")|${SYSTEM_FIREWALL_ANALYSIS:-No firewall}|system_firewall"
            echo "Malware Scanner|$(portal_status "$MALWARE_SCANNER_STATUS")|${MALWARE_SCANNER_DETAIL:-Missing}|malware_scanner"
            echo "Failed Login Detection|$(portal_status "$BRUTE_STATUS")|${BRUTE_REASON:-None}|brute_force"
            echo "Web App Firewall|$(portal_status "$MODSEC_STATUS")|${MODSEC_REASON:-Disabled}|waf"
            echo "Rootkit Scanner|$(portal_status "$ROOTKIT_SCANNER_STATUS")|${ROOTKIT_SCANNER_DETAIL:-Missing}|rootkit_scanner"
            ;;
        1)
            echo "Operating System / Kernel|$(portal_status "$SYSTEM_UPDATE_STATUS")|${SYSTEM_LATEST:-Up to date}|os_kernel_update"
            echo "PHP Packages|$([[ ${PHP_UPDATE_COUNT:-0} -gt 0 ]] && echo 'RED' || echo 'GREEN')|${PHP_UPDATE_COUNT:-0} pending updates (Installed: ${PHP_VERSIONS:-None})|php_update"
            echo "CMS Installations|$(portal_status "$OUTDATED_CMS_STATUS")|${OUTDATED_CMS_DETAIL:-None}|cms_update"
            echo "Web Server|$([[ ${HTTPD_UPDATE_COUNT:-0} -gt 0 ]] && echo 'RED' || echo 'GREEN')|${HTTPD_UPDATE_COUNT:-0} pending web-server updates|web_server_update"
            echo "Database Server|$([[ ${MYSQL_UPDATE_COUNT:-0} -gt 0 ]] && echo 'RED' || echo 'GREEN')|${MYSQL_UPDATE_COUNT:-0} pending DB updates|db_server_update"
            echo "Other Software Packages|$([[ ${OTHER_UPDATE_COUNT:-0} -gt 0 ]] && echo 'RED' || echo 'GREEN')|${OTHER_UPDATE_COUNT:-0} pending other packages|other_update"
            echo "Kernel Update Status|$(portal_status "$KERNEL_STATUS")|Running: ${KERNEL_RUNNING:-unknown} (Update: ${KERNEL_UPDATE_AVAILABLE:-No})|kernel_update"
            echo "Reboot Required|$(portal_status "$REBOOT_STATUS")|${REBOOT_REASON:-No reboot needed}|reboot_required"
            ;;
        2)
            echo "Server Uptime|$(portal_status "$UPTIME_STATUS")|${UPTIME:-unknown}|uptime"
            echo "HTTP Web Server|$(portal_status "$HTTP_STATUS")|${HTTP_UPTIME:-N/A} (${HTTP_STATUS:-Not detected})|http_uptime"
            echo "CPU Usage|$(portal_status "$CPU_STATUS")|Load average: ${LOAD:-0}|cpu_usage"
            echo "RAM Usage|$(portal_status "$RAM_STATUS")|${RAM_PCT:-0}% used|ram_usage"
            echo "Disk Space Usage|$(portal_status "$DISK_STATUS")|${DISK_PCT:-0}% used on /|disk_space"
            echo "Email Queue|$(portal_status "$EMAIL_STATUS")|Queued messages: ${EMAIL_QUEUE:-N/A}|email_queue"
            echo "IP Reputation (DNSBL)|$(portal_status "$IP_REPUTATION_STATUS")|${IP_REPUTATION_DETAIL:-Good}|ip_reputation"
            ;;
        3)
            echo "Local Backup|$(portal_status "$BACKUP_STATUS")|${BACKUP_DETAIL:-None}|local_backup"
            echo "Remote Backup|$(portal_status "$BACKUP_REMOTE_STATUS")|${BACKUP_REMOTE_DETAIL:-Not configured}|remote_backup"
            echo "Daily Backup|$(portal_status "$BACKUP_DAILY_STATUS")|${BACKUP_DAILY_DETAIL:-N/A}|daily_backup"
            echo "Weekly Backup|$(portal_status "$BACKUP_WEEKLY_STATUS")|${BACKUP_WEEKLY_DETAIL:-N/A}|weekly_backup"
            echo "Monthly Backup|$(portal_status "$BACKUP_MONTHLY_STATUS")|${BACKUP_MONTHLY_DETAIL:-N/A}|monthly_backup"
            echo "Backup Retention|$(portal_status "$BACKUP_RETENTION_STATUS")|${BACKUP_RETENTION_DETAIL:-N/A}|backup_retention"
            echo "Recent Last Backup|$(portal_status "$BACKUP_LAST_STATUS")|${BACKUP_LAST_DETAIL:-None}|backup_last"
            echo "Size Of Last Backup|$(portal_status "$BACKUP_SIZE_STATUS")|${BACKUP_SIZE_DETAIL:-N/A}|backup_size"
            ;;
        4)
            echo "Control Panel|N/A|No control panel installed on this server|control_panel"
            echo "Operating System EOL|$(portal_status "$EOL_STATUS")|${DISTRO_NAME:-Linux} ${OS_VERSION:-} (${EOL_STATUS:-Supported})|os_eol"
            echo "Software Stack (PHP)|$(portal_status "$PHP_EOL_STATUS")|${PHP_EOL_DETAIL:-All versions supported}|software_stack"
            echo "CMS Lifetime|$(portal_status "$OUTDATED_CMS_STATUS")|${OUTDATED_CMS_DETAIL:-None}|cms_update"
            ;;
        5)
            echo "/tmp Security|$(portal_status "$TMP_SEC_STATUS")|${TMP_SEC_DETAIL:-Warning}|tmp_security"
            echo "Reboot Procedure|$(portal_status "$REBOOT_PROC_STATUS")|${REBOOT_PROC_DETAIL:-Manual}|reboot_procedure"
            echo "IP RDNS (PTR)|$(portal_status "$RDNS_STATUS")|${RDNS_DETAIL:-Missing}|ip_rdns"
            echo "Malware Scan Results|$(portal_status "$MALWARE_RESULT_STATUS")|${MALWARE_RESULT_DETAIL:-No report}|malware_scan"
            echo "Rootkit Check Results|$(portal_status "$ROOTKIT_RESULT_STATUS")|${ROOTKIT_RESULT_DETAIL:-Review}|rootkit_check"
            echo "SSH Root Access Security|$(portal_status "$ROOT_LOGIN_STATUS")|PermitRoot: ${ROOT_LOGIN_RAW:-unknown}; PassAuth: ${SSH_PASSWORD_AUTH:-unknown}; Port: ${SSH_PORT:-22}|ssh_root"
            echo "PHP Functions Security|$(portal_status "$PHP_FUNC_STATUS")|${PHP_FUNC_DETAIL:-Not set}|php_functions"
            echo "Root Password Health|$(portal_status "$ROOT_PW_STATUS")|Root password changed ~${DAYS_OLD:-999} days ago|root_password"
            echo "SSL Certificates|$(portal_status "$SSL_STATUS")|${SSL_EXPIRY:-None}|ssl_certificates"
            ;;
    esac
}

tui_get_all_red_items() {
    local c line label st det key
    for (( c=0; c<=5; c++ )); do
        while IFS='|' read -r label st det key; do
            [[ -z "$label" ]] && continue
            if [[ "$st" == "RED" ]]; then
                echo "$label|$st|$det|$key"
            fi
        done < <(tui_get_cat_items "$c")
    done
}

tui_get_item_details() {
    local key="$1" label="$2" st="$3" det="$4"
    ITEM_ISSUE=""
    ITEM_FINDINGS=""
    ITEM_RECOMMENDATION=""
    local NL=$'\n'

    # If item is RED, load canonical Bobcares issue and recommendation
    if [[ "$st" == "RED" ]]; then
        get_red_issue_and_rec "$key"
    fi

    case "$key" in
        "other_update")
            if [[ "$st" == "RED" ]]; then
                local pkgs=""
                if [[ -n "$OTHER_UPDATE_LIST" ]]; then
                    pkgs="$OTHER_UPDATE_LIST"
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "OTHER SOFTWARE UPDATES" "$FINDINGS_FILE" 2>/dev/null; then
                    pkgs=$(awk '/^OTHER SOFTWARE UPDATES/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
                elif command -v apt >/dev/null 2>&1; then
                    pkgs=$(apt list --upgradable 2>/dev/null | grep -E '^\S+/' | grep -Evi '^(ea-php|alt-php|lsphp|rh-php|php|apache2|httpd|nginx|mariadb|mysql|linux-)' || true)
                elif command -v dnf >/dev/null 2>&1; then
                    pkgs=$(dnf check-update -q 2>/dev/null | grep -v '^\s*$' | grep -Evi '(kernel|linux-firmware|php|httpd|nginx|mariadb|mysql)' || true)
                elif command -v yum >/dev/null 2>&1; then
                    pkgs=$(yum check-update -q 2>/dev/null | grep -v '^\s*$' | grep -Evi '(kernel|linux-firmware|php|httpd|nginx|mariadb|mysql)' || true)
                fi
                if [[ -z "$OTHER_UPDATE_COUNT" || "$OTHER_UPDATE_COUNT" -eq 0 ]] && [[ -n "$pkgs" ]]; then
                    OTHER_UPDATE_COUNT=$(printf '%s\n' "$pkgs" | grep -c . || echo 0)
                fi
                ITEM_ISSUE="Other software updates are available (${OTHER_UPDATE_COUNT:-0} pending package(s))"
                ITEM_FINDINGS="$pkgs"
            else
                ITEM_FINDINGS="All general system software packages are up to date."
                ITEM_RECOMMENDATION="System package currency is optimal. No action required."
            fi
            ;;
        "os_kernel_update"|"kernel_update")
            if [[ "$st" == "RED" ]]; then
                local kpkgs=""
                if [[ -n "$KERNEL_UPDATE_LIST" ]]; then
                    kpkgs="$KERNEL_UPDATE_LIST"
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "OPERATING SYSTEM / KERNEL UPDATES" "$FINDINGS_FILE" 2>/dev/null; then
                    kpkgs=$(awk '/^OPERATING SYSTEM \/ KERNEL UPDATES/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
                elif command -v apt >/dev/null 2>&1; then
                    kpkgs=$(apt list --upgradable 2>/dev/null | grep -E '^linux-(base|image|headers|modules|generic|tools|firmware)' || true)
                elif command -v dnf >/dev/null 2>&1; then
                    kpkgs=$(dnf check-update -q 2>/dev/null | grep -Ei 'kernel|linux-firmware' || true)
                elif command -v yum >/dev/null 2>&1; then
                    kpkgs=$(yum check-update -q 2>/dev/null | grep -Ei 'kernel|linux-firmware' || true)
                fi
                if [[ -z "$KERNEL_UPDATE_COUNT" || "$KERNEL_UPDATE_COUNT" -eq 0 ]] && [[ -n "$kpkgs" ]]; then
                    KERNEL_UPDATE_COUNT=$(printf '%s\n' "$kpkgs" | grep -c . || echo 0)
                fi
                ITEM_ISSUE="Operating System / Kernel updates available (${KERNEL_UPDATE_COUNT:-0} pending update(s))"
                ITEM_FINDINGS="Running Kernel: ${KERNEL_RUNNING:-$(uname -r)}${NL}${kpkgs:-Kernel update available}"
            else
                ITEM_FINDINGS="Running Kernel: ${KERNEL_RUNNING:-$(uname -r)}${NL}Kernel Packages: Up to date"
                ITEM_RECOMMENDATION="Kernel version is supported and current. No reboot or updates required."
            fi
            ;;
        "php_update")
            if [[ "$st" == "RED" ]]; then
                local php_pkgs=""
                if [[ -n "$PHP_UPDATE_LIST" ]]; then
                    php_pkgs="$PHP_UPDATE_LIST"
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "PHP UPDATES" "$FINDINGS_FILE" 2>/dev/null; then
                    php_pkgs=$(awk '/^PHP UPDATES/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
                elif command -v apt >/dev/null 2>&1; then
                    php_pkgs=$(apt list --upgradable 2>/dev/null | grep -Ei '(php[0-9.]*|ea-php|alt-php)' || true)
                elif command -v dnf >/dev/null 2>&1; then
                    php_pkgs=$(dnf check-update -q 2>/dev/null | grep -Ei '(php|ea-php|alt-php)' || true)
                fi
                if [[ -z "$PHP_UPDATE_COUNT" || "$PHP_UPDATE_COUNT" -eq 0 ]] && [[ -n "$php_pkgs" ]]; then
                    PHP_UPDATE_COUNT=$(printf '%s\n' "$php_pkgs" | grep -c . || echo 0)
                fi
                ITEM_ISSUE="PHP package updates are available (${PHP_UPDATE_COUNT:-0} pending update(s))"
                ITEM_FINDINGS="Installed PHP: ${PHP_VERSIONS:-None}${NL}${php_pkgs:-Pending PHP package updates detected}"
            else
                ITEM_FINDINGS="Installed PHP: ${PHP_VERSIONS:-None}${NL}Status: All installed PHP packages are up to date."
                ITEM_RECOMMENDATION="PHP stack packages are current. No action required."
            fi
            ;;
        "web_server_update")
            if [[ "$st" == "RED" ]]; then
                local http_pkgs=""
                if [[ -n "$HTTPD_UPDATE_LIST" ]]; then
                    http_pkgs="$HTTPD_UPDATE_LIST"
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "WEB SERVER UPDATES" "$FINDINGS_FILE" 2>/dev/null; then
                    http_pkgs=$(awk '/^WEB SERVER UPDATES/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
                elif command -v apt >/dev/null 2>&1; then
                    http_pkgs=$(apt list --upgradable 2>/dev/null | grep -Ei '(apache2|nginx|httpd|lighttpd)' || true)
                elif command -v dnf >/dev/null 2>&1; then
                    http_pkgs=$(dnf check-update -q 2>/dev/null | grep -Ei '(httpd|nginx|lighttpd)' || true)
                fi
                if [[ -z "$HTTPD_UPDATE_COUNT" || "$HTTPD_UPDATE_COUNT" -eq 0 ]] && [[ -n "$http_pkgs" ]]; then
                    HTTPD_UPDATE_COUNT=$(printf '%s\n' "$http_pkgs" | grep -c . || echo 0)
                fi
                ITEM_ISSUE="Web server package updates are available (${HTTPD_UPDATE_COUNT:-0} pending update(s))"
                ITEM_FINDINGS="${http_pkgs:-Web server package updates pending}"
            else
                ITEM_FINDINGS="Web server software packages are current."
                ITEM_RECOMMENDATION="Web server is running latest installed release."
            fi
            ;;
        "db_server_update")
            if [[ "$st" == "RED" ]]; then
                local db_pkgs=""
                if [[ -n "$MYSQL_UPDATE_LIST" ]]; then
                    db_pkgs="$MYSQL_UPDATE_LIST"
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "DATABASE UPDATES" "$FINDINGS_FILE" 2>/dev/null; then
                    db_pkgs=$(awk '/^DATABASE UPDATES/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
                elif command -v apt >/dev/null 2>&1; then
                    db_pkgs=$(apt list --upgradable 2>/dev/null | grep -Ei '(mariadb|mysql|postgresql|percona)' || true)
                elif command -v dnf >/dev/null 2>&1; then
                    db_pkgs=$(dnf check-update -q 2>/dev/null | grep -Ei '(mariadb|mysql|postgresql|percona)' || true)
                fi
                if [[ -z "$MYSQL_UPDATE_COUNT" || "$MYSQL_UPDATE_COUNT" -eq 0 ]] && [[ -n "$db_pkgs" ]]; then
                    MYSQL_UPDATE_COUNT=$(printf '%s\n' "$db_pkgs" | grep -c . || echo 0)
                fi
                ITEM_ISSUE="Database server package updates are available (${MYSQL_UPDATE_COUNT:-0} pending update(s))"
                ITEM_FINDINGS="${db_pkgs:-Database package updates pending}"
            else
                ITEM_FINDINGS="Database server packages are current."
                ITEM_RECOMMENDATION="Database packages are up to date."
            fi
            ;;
        "cms_update")
            if [[ "$st" == "RED" ]]; then
                local cms_out=""
                if [[ -f /root/scripts/outdated-cms-report.txt ]]; then
                    cms_out=$(cat /root/scripts/outdated-cms-report.txt 2>/dev/null || true)
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "CMS UPDATE REPORT" "$FINDINGS_FILE" 2>/dev/null; then
                    cms_out=$(awk '/^CMS UPDATE REPORT/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
                fi
                ITEM_FINDINGS="${cms_out:-$OUTDATED_CMS_DETAIL}"
            else
                ITEM_FINDINGS="${OUTDATED_CMS_DETAIL:-No outdated CMS installations detected on this server.}"
                ITEM_RECOMMENDATION="CMS versions are current or no CMS installations detected."
            fi
            ;;
        "reboot_required")
            if [[ "$st" == "RED" ]]; then
                local r_pkgs=""
                if [[ -f /var/run/reboot-required.pkgs ]]; then
                    r_pkgs=$(cat /var/run/reboot-required.pkgs 2>/dev/null || true)
                fi
                ITEM_FINDINGS="${r_pkgs:-$REBOOT_REASON}"
            else
                ITEM_FINDINGS="No reboot required. Kernel and core libraries are active."
                ITEM_RECOMMENDATION="System does not require a reboot."
            fi
            ;;
        "system_firewall")
            local fw_ports=""
            if command -v ss >/dev/null 2>&1; then
                fw_ports=$(ss -tlpn 2>/dev/null | grep -E 'LISTEN\s+[0-9]' | awk '{print $4}' | awk -F: '{print $NF}' | sort -un | paste -sd ', ' - || true)
            elif command -v netstat >/dev/null 2>&1; then
                fw_ports=$(netstat -tlpn 2>/dev/null | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}' | sort -un | paste -sd ', ' - || true)
            fi
            local ufw_st=""
            if command -v ufw >/dev/null 2>&1; then
                ufw_st=$(ufw status 2>/dev/null | head -1 || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Firewall Status: Inactive / Missing (${ufw_st:-ufw inactive})${NL}Open Listening Ports: ${fw_ports:-unknown}${NL}Analysis: ${SYSTEM_FIREWALL_ANALYSIS:-None}"
            else
                ITEM_FINDINGS="Firewall Status: ${SYSTEM_FIREWALL_ANALYSIS:-Active} (${ufw_st:-Active})${NL}Open Listening Ports: ${fw_ports:-None}"
                ITEM_RECOMMENDATION="Firewall is active and filtering incoming traffic."
            fi
            ;;
        "malware_scanner"|"malware_scan")
            if [[ "$st" == "RED" ]]; then
                local m_files=""
                if [[ -f /root/scripts/malware-details-report.txt ]]; then
                    m_files=$(grep -E '^(File|Infection|FOUND):' /root/scripts/malware-details-report.txt 2>/dev/null | head -20 || true)
                elif [[ -f /root/scripts/malware-files.txt ]]; then
                    m_files=$(head -20 /root/scripts/malware-files.txt 2>/dev/null || true)
                elif [[ -f "$FINDINGS_FILE" ]] && grep -q "MALWARE" "$FINDINGS_FILE" 2>/dev/null; then
                    m_files=$(awk '/^MALWARE/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' | head -20 || true)
                fi
                ITEM_FINDINGS="${m_files:-$MALWARE_RESULT_DETAIL}"
            else
                ITEM_FINDINGS="Scanner: ${MALWARE_SCANNER_DETAIL:-Active}${NL}Scan Results: Clean, no malware signatures detected."
                ITEM_RECOMMENDATION="Malware scanning protection is operating normally."
            fi
            ;;
        "brute_force")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Brute Force Status: Inactive${NL}Reason: ${BRUTE_REASON:-Fail2Ban service not running}"
            else
                ITEM_FINDINGS="Service: Fail2Ban / Brute force daemon is active.${NL}Jails: Monitoring active authentication logs."
                ITEM_RECOMMENDATION="Brute-force protection is operating normally."
            fi
            ;;
        "waf")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="ModSecurity: Disabled or missing in web server configuration."
            else
                ITEM_FINDINGS="ModSecurity / WAF is enabled and actively filtering HTTP traffic."
                ITEM_RECOMMENDATION="Web Application Firewall is active."
            fi
            ;;
        "rootkit_scanner"|"rootkit_check")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Status: ${ROOTKIT_RESULT_DETAIL:-Rootkit tools missing}${NL}Recommended Tools: rkhunter, chkrootkit"
            else
                ITEM_FINDINGS="Rootkit Scanner: ${ROOTKIT_SCANNER_DETAIL:-Installed}${NL}Scan Status: Clean"
                ITEM_RECOMMENDATION="Rootkit scanner is in place and verified."
            fi
            ;;
        "uptime")
            ITEM_FINDINGS="Uptime: ${UPTIME:-$(uptime -p 2>/dev/null || uptime)}${NL}Load Averages: ${LOAD:-$(uptime | awk -F'load average:' '{print $2}')}"
            ITEM_RECOMMENDATION="Server availability and uptime are normal."
            ;;
        "http_uptime")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="HTTP Service: ${HTTP_STATUS:-Down}${NL}Ports 80/443: Not responding"
            else
                ITEM_FINDINGS="Web Server Service: Active${NL}Uptime: ${HTTP_UPTIME:-Normal}${NL}Ports: 80 / 443 listening"
                ITEM_RECOMMENDATION="Web server is operating normally."
            fi
            ;;
        "cpu_usage")
            local top_cpu=""
            if command -v ps >/dev/null 2>&1; then
                top_cpu=$(ps -eo pid,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -6 || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Current Load: ${LOAD:-0}${NL}Top CPU Consumers:${NL}${top_cpu:-N/A}"
            else
                ITEM_FINDINGS="Load Average: ${LOAD:-0}${NL}Top Processes:${NL}${top_cpu:-N/A}"
                ITEM_RECOMMENDATION="CPU load is within healthy operating limits."
            fi
            ;;
        "ram_usage")
            local mem_summary="" top_mem=""
            if command -v free >/dev/null 2>&1; then
                mem_summary=$(free -h 2>/dev/null || true)
            fi
            if command -v ps >/dev/null 2>&1; then
                top_mem=$(ps -eo pid,pmem,pcpu,comm --sort=-pmem 2>/dev/null | head -6 || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Memory Summary:${NL}${mem_summary:-${RAM_PCT}% used}${NL}Top Memory Consumers:${NL}${top_mem:-N/A}"
            else
                ITEM_FINDINGS="Memory Summary:${NL}${mem_summary:-${RAM_PCT}% used}${NL}Top Memory Consumers:${NL}${top_mem:-N/A}"
                ITEM_RECOMMENDATION="RAM usage is within healthy thresholds."
            fi
            ;;
        "disk_space")
            local df_summary=""
            if command -v df >/dev/null 2>&1; then
                df_summary=$(df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Filesystem Breakdown:${NL}${df_summary:-${DISK_PCT}% used on /}"
            else
                ITEM_FINDINGS="Filesystem Breakdown:${NL}${df_summary:-${DISK_PCT}% used on /}"
                ITEM_RECOMMENDATION="Disk utilization is within healthy limits."
            fi
            ;;
        "email_queue")
            local mq=""
            if command -v mailq >/dev/null 2>&1; then
                mq=$(mailq 2>/dev/null | tail -1 || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Queue Summary: ${mq:-${EMAIL_QUEUE:-0} messages queued}"
            else
                ITEM_FINDINGS="Queue Status: Clean (${mq:-${EMAIL_QUEUE:-0} messages})"
                ITEM_RECOMMENDATION="Email queue is normal."
            fi
            ;;
        "ip_reputation")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Blacklist Detail: ${IP_REPUTATION_DETAIL:-Listed in DNSBL}${NL}Server IP: $MAIN_IP"
            else
                ITEM_FINDINGS="Server IP ($MAIN_IP) checked against Spamhaus, Barracuda, SORBS, SpamCop.${NL}Status: Clean, not blacklisted."
                ITEM_RECOMMENDATION="IP reputation is healthy."
            fi
            ;;
        "local_backup"|"remote_backup"|"daily_backup"|"weekly_backup"|"monthly_backup"|"backup_retention"|"backup_last"|"backup_size")
            local cron_backups=""
            if command -v crontab >/dev/null 2>&1; then
                cron_backups=$(crontab -l 2>/dev/null | grep -Ei 'backup|dump|tar|rsync|rclone|s3' || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Backup Status: $det${NL}Detected Crontab Backups:${NL}${cron_backups:-None detected in crontab}"
            else
                ITEM_FINDINGS="Backup Configuration: $det${NL}Crontab Backups:${NL}${cron_backups:-Configured or managed externally}"
                ITEM_RECOMMENDATION="Backup configuration verified."
            fi
            ;;
        "control_panel")
            ITEM_FINDINGS="Control Panel: None (Standard Linux server)${NL}Package Management: ${PKG_MGR:-apt/dnf}"
            ITEM_RECOMMENDATION="Server is configured as a standalone Linux installation."
            ;;
        "os_eol")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Distribution: $DISTRO_NAME${NL}Version: $OS_VERSION${NL}EOL Status: Expired"
            else
                ITEM_FINDINGS="Distribution: $DISTRO_NAME${NL}Version: $OS_VERSION${NL}Support Status: Actively supported"
                ITEM_RECOMMENDATION="OS release is supported."
            fi
            ;;
        "software_stack")
            local eol_php=""
            if command -v get_formatted_eol_php >/dev/null 2>&1; then
                eol_php=$(get_formatted_eol_php 2>/dev/null || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Installed PHP: ${PHP_VERSIONS:-None}${NL}EOL Versions: ${eol_php:-$PHP_EOL_DETAIL}"
            else
                ITEM_FINDINGS="Installed PHP: ${PHP_VERSIONS:-None}${NL}Status: All versions are actively supported."
                ITEM_RECOMMENDATION="PHP stack is current."
            fi
            ;;
        "tmp_security")
            local tmp_mnt=""
            if command -v findmnt >/dev/null 2>&1; then
                tmp_mnt=$(findmnt /tmp 2>/dev/null || true)
            fi
            if [[ -z "$tmp_mnt" ]]; then
                tmp_mnt=$(grep -E '\s+/tmp\s+' /proc/mounts 2>/dev/null || echo "/tmp on root filesystem")
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Mount Info:${NL}${tmp_mnt:-/tmp on root filesystem}${NL}Required Options: noexec, nosuid, nodev"
            else
                ITEM_FINDINGS="Mount Info:${NL}${tmp_mnt:-Mounted with secure options}${NL}Status: Secured"
                ITEM_RECOMMENDATION="/tmp filesystem is securely mounted."
            fi
            ;;
        "reboot_procedure")
            ITEM_FINDINGS="Procedure: ${REBOOT_PROC_DETAIL:-Manual reboot required}"
            if [[ "$st" != "RED" ]]; then
                ITEM_RECOMMENDATION="Document remote reboot portal access securely in client area."
            fi
            ;;
        "ip_rdns")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="IP: $MAIN_IP${NL}PTR Record: ${RDNS_DETAIL:-None}"
            else
                ITEM_FINDINGS="IP: $MAIN_IP${NL}PTR Record: ${RDNS_DETAIL:-Valid}"
                ITEM_RECOMMENDATION="Reverse DNS is configured properly."
            fi
            ;;
        "ssh_root")
            local ssh_details="PermitRootLogin: ${ROOT_LOGIN_RAW:-unknown}${NL}PasswordAuthentication: ${SSH_PASSWORD_AUTH:-unknown}${NL}SSH Port: ${SSH_PORT:-22}${NL}Config File: /etc/ssh/sshd_config"
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="$ssh_details"
            else
                ITEM_FINDINGS="$ssh_details"
                ITEM_RECOMMENDATION="SSH daemon security configuration is optimal."
            fi
            ;;
        "php_functions")
            local php_fn_details="${PHP_INSECURE_LIST:-$PHP_FUNC_DETAIL}"
            if [[ -z "$php_fn_details" && -f "$FINDINGS_FILE" ]] && grep -q "DANGEROUS PHP FUNCTIONS" "$FINDINGS_FILE" 2>/dev/null; then
                php_fn_details=$(awk '/^DANGEROUS PHP FUNCTIONS/{flag=1; next} flag && /^===/{if(seen){exit}else{seen=1; next}} flag && seen{print}' "$FINDINGS_FILE" 2>/dev/null | grep -v '^None$' || true)
            fi
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Insecure Directives:${NL}${php_fn_details:-Functions like exec, shell_exec, system are enabled}${NL}Target: disable_functions = exec,shell_exec,system,passthru,proc_open"
            else
                ITEM_FINDINGS="PHP Functions Security: Optimal${NL}Status: Dangerous functions are disabled."
                ITEM_RECOMMENDATION="PHP execution security is enforced."
            fi
            ;;
        "root_password")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Password Age: ~${DAYS_OLD:-999} days (Exceeds 90 days recommended threshold)"
            else
                ITEM_FINDINGS="Password Age: ~${DAYS_OLD:-0} days (Within healthy threshold)"
                ITEM_RECOMMENDATION="Root password age is healthy."
            fi
            ;;
        "ssl_certificates")
            if [[ "$st" == "RED" ]]; then
                ITEM_FINDINGS="Certificate Status: ${SSL_EXPIRY:-Expired}"
            else
                ITEM_FINDINGS="Certificate Status: ${SSL_EXPIRY:-Valid}"
                ITEM_RECOMMENDATION="SSL certificates are valid."
            fi
            ;;
        *)
            if [[ "$st" == "RED" ]]; then
                ITEM_ISSUE="Issue detected: $label ($det)"
                ITEM_RECOMMENDATION="Investigate and remediate $label to restore normal system operations."
            else
                ITEM_RECOMMENDATION="Component status verified."
            fi
            ITEM_FINDINGS="$det"
            ;;
    esac

    # Universal safety check: Guarantee Issue and Recommendation for any RED finding
    if [[ "$st" == "RED" ]]; then
        [[ -z "$ITEM_ISSUE" ]] && ITEM_ISSUE="Issue detected: $label ($det)"
        [[ -z "$ITEM_RECOMMENDATION" ]] && ITEM_RECOMMENDATION="Investigate and remediate $label to restore normal system operations."
    else
        ITEM_ISSUE=""
        ITEM_RECOMMENDATION=""
    fi
}

run_audit_tui() {
    local use_fd3=false

    if [ -c /dev/tty ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
        exec 3<>/dev/tty
        use_fd3=true
    fi

    # Save original terminal settings and enter raw mode (keep isig so Ctrl+C raises SIGINT)
    if $use_fd3; then
        TUI_OLD_STTY=$(stty -g <&3 2>/dev/null || stty -g < /dev/tty 2>/dev/null || stty -g 2>/dev/null)
        stty raw -echo isig min 1 time 0 <&3 2>/dev/null
    fi


    local C_RESET=$'\033[0m'
    local C_BOLD=$'\033[1m'
    local C_DIM=$'\033[2m'
    local C_RED=$'\033[1;31m'
    local C_GREEN=$'\033[1;32m'
    local C_YELLOW=$'\033[1;33m'
    local C_BLUE=$'\033[1;34m'
    local C_MAGENTA=$'\033[1;35m'
    local C_CYAN=$'\033[1;36m'
    local C_WHITE=$'\033[1;37m'
    local C_GREY=$'\033[90m'
    local C_DARKGREY=$'\033[38;5;240m'

    local BG_HEADER=$'\033[48;5;24;1;37m'
    local BG_SUBHDR=$'\033[48;5;236;37m'
    local BG_ACTIVE=$'\033[48;5;31;1;37m'
    local BG_INACTIVE_SEL=$'\033[48;5;238;1;37m'
    local BG_FOOTER=$'\033[48;5;235;37m'
    local BG_RED=$'\033[41;1;37m'
    local BG_GREEN=$'\033[42;1;30m'
    local BG_YELLOW=$'\033[43;1;30m'
    local BG_GREY=$'\033[100;1;37m'
    local BG_SCROLL_HINT=$'\033[48;5;214;1;30m'  # bright amber bg, bold black text

    tui_badge() {
        case "$1" in
            "GREEN") printf '%b[  OK  ]%b' "$C_GREEN" "$C_RESET" ;;
            "RED")   printf '%b[ RED  ]%b' "$BG_RED" "$C_RESET" ;;
            "CHECK") printf '%b[ WARN ]%b' "$C_YELLOW" "$C_RESET" ;;
            *)       printf '%b[ N/A  ]%b' "$C_GREY" "$C_RESET" ;;
        esac
    }

    tui_cleanup() {
        cleanup_terminal
    }
    trap 'full_cleanup; exit 130' INT
    trap 'full_cleanup; exit 143' TERM
    trap 'full_cleanup' EXIT


    if $use_fd3; then
        # Enter alternate screen, hide cursor, disable line wrap (?7l), enable alternate screen mouse wheel translation (?1007h)
        # Keep click reporting OFF (?1000l ?1002l ?1003l ?1006l) so clicks and text selection stay native
        printf '\033[?1049h\033[?25l\033[?7l\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1007h' >&3
    fi

    local cat_names=(
        "Threat Protection"
        "Software Updates"
        "Server Health"
        "Backup"
        "Software Life Time"
        "Proactive Defence"
        "Critical Issues (RED)"
        "Findings Log"
        "Smart Summary (MD)"
    )

    # Pre-cache all items, issues, detailed findings, and recommendations in memory
    local -a cat_items_0=() cat_items_1=() cat_items_2=() cat_items_3=() cat_items_4=() cat_items_5=() cat_items_6=()
    local -a cat_issues_0=() cat_issues_1=() cat_issues_2=() cat_issues_3=() cat_issues_4=() cat_issues_5=() cat_issues_6=()
    local -a cat_findings_0=() cat_findings_1=() cat_findings_2=() cat_findings_3=() cat_findings_4=() cat_findings_5=() cat_findings_6=()
    local -a cat_recs_0=() cat_recs_1=() cat_recs_2=() cat_recs_3=() cat_recs_4=() cat_recs_5=() cat_recs_6=()
    local -a cat_red_counts=(0 0 0 0 0 0 0 0 0)
    local total_red=0

    local c raw_items=() line label st det key
    for (( c=0; c<=5; c++ )); do
        mapfile -t raw_items < <(tui_get_cat_items "$c")
        for line in "${raw_items[@]}"; do
            [[ -z "$line" ]] && continue
            IFS='|' read -r label st det key <<< "$line"
            ITEM_ISSUE=""
            ITEM_FINDINGS=""
            ITEM_RECOMMENDATION=""
            tui_get_item_details "$key" "$label" "$st" "$det"
            case "$c" in
                0) cat_items_0+=("$line"); cat_issues_0+=("$ITEM_ISSUE"); cat_findings_0+=("$ITEM_FINDINGS"); cat_recs_0+=("$ITEM_RECOMMENDATION") ;;
                1) cat_items_1+=("$line"); cat_issues_1+=("$ITEM_ISSUE"); cat_findings_1+=("$ITEM_FINDINGS"); cat_recs_1+=("$ITEM_RECOMMENDATION") ;;
                2) cat_items_2+=("$line"); cat_issues_2+=("$ITEM_ISSUE"); cat_findings_2+=("$ITEM_FINDINGS"); cat_recs_2+=("$ITEM_RECOMMENDATION") ;;
                3) cat_items_3+=("$line"); cat_issues_3+=("$ITEM_ISSUE"); cat_findings_3+=("$ITEM_FINDINGS"); cat_recs_3+=("$ITEM_RECOMMENDATION") ;;
                4) cat_items_4+=("$line"); cat_issues_4+=("$ITEM_ISSUE"); cat_findings_4+=("$ITEM_FINDINGS"); cat_recs_4+=("$ITEM_RECOMMENDATION") ;;
                5) cat_items_5+=("$line"); cat_issues_5+=("$ITEM_ISSUE"); cat_findings_5+=("$ITEM_FINDINGS"); cat_recs_5+=("$ITEM_RECOMMENDATION") ;;
            esac
            if [[ "$st" == "RED" ]]; then
                (( cat_red_counts[c]++ ))
                (( total_red++ ))
                cat_items_6+=("$line")
                cat_issues_6+=("$ITEM_ISSUE")
                cat_findings_6+=("$ITEM_FINDINGS")
                cat_recs_6+=("$ITEM_RECOMMENDATION")
            fi
        done
    done
    if (( ${#cat_items_6[@]} == 0 )); then
        cat_items_6+=("No Critical Issues|GREEN|No RED findings were detected during this audit.|")
        cat_issues_6+=("")
        cat_findings_6+=("All server components and configurations passed verification.")
        cat_recs_6+=("All systems and configurations checked are operating normally.")
    fi
    cat_red_counts[6]=$total_red
    cat_red_counts[7]=0
    cat_red_counts[8]=0

    # Pre-load logs into memory once
    local -a findings_lines=() summary_lines=()
    if [[ -f "$FINDINGS_FILE" ]]; then
        mapfile -t findings_lines < "$FINDINGS_FILE"
    else
        findings_lines=("Findings log not found at $FINDINGS_FILE")
    fi
    if [[ -f "$SUMMARY_FILE" ]]; then
        mapfile -t summary_lines < "$SUMMARY_FILE"
    else
        summary_lines=("Summary file not found at $SUMMARY_FILE")
    fi

    local cur_cat=0
    local cur_item=0
    local pane_focus=0
    local log_scroll=0
    local item_scroll=0
    local bot_scroll=0
    local status_msg=""
    local show_help=0
    local in_drilldown=0
    local drill_scroll=0
    local max_drill_scroll=0

    local term_lines=25 term_cols=80
    get_term_size() {
        if $use_fd3; then
            term_lines=$(tput lines <&3 2>/dev/null || echo "${LINES:-25}")
            term_cols=$(tput cols <&3 2>/dev/null || echo "${COLUMNS:-80}")
        else
            term_lines=${LINES:-25}
            term_cols=${COLUMNS:-80}
        fi
        (( term_lines < 15 )) && term_lines=15
        (( term_cols < 60 )) && term_cols=60
    }
    get_term_size
    trap 'get_term_size; render_tui' WINCH

    render_tui() {
        local left_w=34
        if (( term_cols < 76 )); then
            left_w=$(( term_cols * 40 / 100 ))
            (( left_w < 26 )) && left_w=26
        fi
        local div_col=$(( left_w + 1 ))
        local right_col=$(( div_col + 2 ))
        local right_w=$(( term_cols - right_col + 1 ))
        (( right_w < 10 )) && right_w=10
        local body_h=$(( term_lines - 3 ))

        local -n cur_items_ref="cat_items_${cur_cat}"
        local -n cur_issues_ref="cat_issues_${cur_cat}"
        local -n cur_findings_ref="cat_findings_${cur_cat}"
        local -n cur_recs_ref="cat_recs_${cur_cat}"

        # Clamp cur_item
        if (( cur_cat <= 6 )); then
            local count=${#cur_items_ref[@]}
            if (( count > 0 )); then
                (( cur_item >= count )) && cur_item=$(( count - 1 ))
                (( cur_item < 0 )) && cur_item=0
            fi
        fi

        # Height partition between Top (Dual Pane) and Bottom (Full Width Details)
        local top_h=13
        if (( cur_cat <= 6 )); then
            if (( body_h >= 20 )); then
                top_h=13
            elif (( body_h >= 16 )); then
                top_h=12
            else
                top_h=$(( body_h * 6 / 10 ))
                (( top_h < 8 )) && top_h=8
            fi
        else
            top_h=$body_h
        fi

        # Scroll item list in the top pane if needed
        local item_visible_h=$(( top_h - 2 ))
        (( item_visible_h < 2 )) && item_visible_h=2
        if (( cur_item >= item_scroll + item_visible_h )); then
            item_scroll=$(( cur_item - item_visible_h + 1 ))
        elif (( cur_item < item_scroll )); then
            item_scroll=$cur_item
        fi

        # Pre-parse findings and recommendation lines for current item
        local -a f_lines=() rec_lines=()
        if (( cur_cat <= 6 && ${#cur_items_ref[@]} > 0 )); then
            local raw_f="${cur_findings_ref[cur_item]}"
            raw_f="${raw_f//$'\r'/}"
            raw_f="${raw_f//\\n/$'\n'}"
            if [[ -n "$raw_f" ]]; then
                local tmp_f=()
                mapfile -t tmp_f <<< "$raw_f"
                for line in "${tmp_f[@]}"; do
                    [[ -n "$line" ]] && f_lines+=("$line")
                done
            fi
            local raw_r="${cur_recs_ref[cur_item]}"
            raw_r="${raw_r//$'\r'/}"
            raw_r="${raw_r//\\n/$'\n'}"
            if [[ -n "$raw_r" ]]; then
                local tmp_r=()
                mapfile -t tmp_r <<< "$raw_r"
                for line in "${tmp_r[@]}"; do
                    [[ -n "$line" ]] && rec_lines+=("$line")
                done
            fi
        fi

        local buf=""
        buf+=$'\033[H'

        # Line 1: Header
        local health_tag=""
        if [[ "$OVERALL_HEALTH" == *"Healthy"* ]]; then
            health_tag="${C_GREEN}● HEALTHY${C_RESET}"
        else
            health_tag="${C_RED}▲ NEEDS ATTENTION${C_RESET}"
        fi
        buf+="${BG_HEADER}$(tui_fit_str " BOBCARES SERVER AUDIT (GoAccess TUI) | Host: $HOSTNAME" $(( term_cols - 20 )) ) Health: ${health_tag}${C_RESET}"$'\033[K\n'

        # Line 2: Sub-header
        local sub_txt=" IP: ${MAIN_IP:-N/A} | OS: ${DISTRO_NAME:-Linux} | Load: ${LOAD:-0} | RAM: ${RAM_PCT:-0}% | Disk: ${DISK_PCT:-0}%"
        buf+="${BG_SUBHDR}$(tui_fit_str "$sub_txt" "$term_cols")${C_RESET}"$'\033[K\n'

        # Body Rows - TOP PANE ONLY (lines 3 to 3+top_h-1)
        local r screen_row
        for (( r=0; r<top_h; r++ )); do
            screen_row=$(( r + 3 ))

            # Left Pane content
            local left_txt=""
                if (( r == 0 )); then
                    left_txt="${C_BOLD}${C_CYAN} AUDIT CATEGORIES${C_RESET}"
                elif (( r == 1 )); then
                    left_txt="${C_DARKGREY}$(tui_repeat_char '─' "$left_w")${C_RESET}"
                elif (( r >= 2 && r <= 10 )); then
                    local c_idx=$(( r - 2 ))
                    local c_name="${cat_names[c_idx]}"
                    local c_num=$(( c_idx + 1 ))
                    local c_badge=""
                    if (( c_idx <= 5 )); then
                        if (( cat_red_counts[c_idx] == 0 )); then
                            c_badge="${C_GREEN}(✓)${C_RESET}"
                        else
                            c_badge="${C_RED}(${cat_red_counts[c_idx]})${C_RESET}"
                        fi
                    elif (( c_idx == 6 )); then
                        c_badge="${C_RED}($total_red)${C_RESET}"
                    elif (( c_idx == 7 )); then
                        c_badge="${C_CYAN}(LOG)${C_RESET}"
                    else
                        c_badge="${C_CYAN}(MD)${C_RESET}"
                    fi

                    local label_w=$(( left_w - 9 ))
                    local full_cat="[$c_num] $c_name"
                    local padded_label
                    if (( ${#full_cat} <= label_w )); then
                        printf -v padded_label "%-${label_w}s" "$full_cat"
                    else
                        padded_label=$(tui_fit_str "$full_cat" "$label_w")
                    fi
                    if (( c_idx == cur_cat )); then
                        if (( pane_focus == 0 )); then
                            left_txt="${BG_ACTIVE}▶ ${padded_label}${C_RESET} ${c_badge}"
                        else
                            left_txt="${BG_INACTIVE_SEL}• ${padded_label}${C_RESET} ${c_badge}"
                        fi
                    else
                        left_txt="  ${padded_label} ${c_badge}"
                    fi
                elif (( r == 11 )); then
                    left_txt="${C_DARKGREY}$(tui_repeat_char '─' "$left_w")${C_RESET}"
                elif (( r == 12 )); then
                    if (( total_red > 0 )); then
                        left_txt="  ${C_RED}${C_BOLD}RED Issues: $total_red${C_RESET}"
                    else
                        left_txt="  ${C_GREEN}No RED Issues!${C_RESET}"
                    fi
                elif (( r == 13 )); then
                    left_txt="  ${C_GREY}Tab: Switch Focus${C_RESET}"
                fi

                # Right Pane content
                local right_txt=""
                if (( cur_cat <= 6 )); then
                    if (( r == 0 )); then
                        local cat_title="${cat_names[cur_cat]}"
                        local cat_hdr=" CATEGORY: ${cat_title} (${#cur_items_ref[@]} items)"
                        right_txt="${C_BOLD}${C_CYAN}$(tui_fit_str "$cat_hdr" "$right_w")${C_RESET}"
                    elif (( r == 1 )); then
                        right_txt="${C_DARKGREY}$(tui_repeat_char '─' "$right_w")${C_RESET}"
                    elif (( r >= 2 )); then
                        local it_idx=$(( item_scroll + r - 2 ))
                        if (( it_idx < ${#cur_items_ref[@]} )); then
                            local it_entry="${cur_items_ref[it_idx]}"
                            local it_label it_st it_det it_key
                            IFS='|' read -r it_label it_st it_det it_key <<< "$it_entry"
                            local bge
                            bge=$(tui_badge "$it_st")
                            local lbl_w=24
                            (( lbl_w > right_w / 3 )) && lbl_w=$(( right_w / 3 ))
                            local lbl_fit
                            lbl_fit=$(tui_fit_str "$it_label" "$lbl_w")
                            local det_w=$(( right_w - lbl_w - 14 ))
                            local det_fit
                            det_fit=$(tui_fit_str "$it_det" "$det_w")
                            if (( it_idx == cur_item )); then
                                if (( pane_focus == 1 )); then
                                    right_txt="${BG_ACTIVE}▶ ${lbl_fit}${C_RESET} ${bge} ${det_fit}"
                                else
                                    right_txt="${BG_INACTIVE_SEL}• ${lbl_fit}${C_RESET} ${bge} ${det_fit}"
                                fi
                            else
                                right_txt="  ${lbl_fit} ${bge} ${det_fit}"
                            fi
                        fi
                    fi
                else
                    local log_name="" log_count=0
                    local -n active_log_ref
                    if (( cur_cat == 7 )); then
                        log_name="audit-findings.log"
                        active_log_ref="findings_lines"
                    else
                        log_name="audit-smart-summary.md"
                        active_log_ref="summary_lines"
                    fi
                    log_count=${#active_log_ref[@]}

                    if (( r == 0 )); then
                        local fl_hdr=" FILE: $log_name ($log_count lines)"
                        if (( right_w > 48 )); then
                            fl_hdr=" FILE: $log_name (Line $(( log_scroll + 1 )) of $log_count)  [↑/↓: Scroll, PgUp/PgDn]"
                        fi
                        right_txt="${C_BOLD}${C_CYAN}$(tui_fit_str "$fl_hdr" "$right_w")${C_RESET}"
                    elif (( r == 1 )); then
                        right_txt="${C_DARKGREY}$(tui_repeat_char '─' "$right_w")${C_RESET}"
                    else
                        local l_idx=$(( log_scroll + r - 2 ))
                        if (( l_idx < log_count )); then
                            right_txt="$(tui_fit_str "${active_log_ref[l_idx]}" "$right_w")"
                        fi
                    fi
                fi

            buf+=$'\033['"${screen_row};1H"$'\033[2K'"${left_txt}"
            buf+=$'\033['"${screen_row};${div_col}H${C_DARKGREY}│${C_RESET}"
            buf+=$'\033['"${screen_row};${right_col}H${right_txt}"
        done  # end top-pane loop

        # ── BOTTOM PANE ─────────────────────────────────────────────────────────
        # Build _blines content array (full sentences, no word-wrap needed)
        local sel_label="" sel_st="" sel_det="" sel_key=""
        if (( ${#cur_items_ref[@]} > 0 )); then
            IFS='|' read -r sel_label sel_st sel_det sel_key <<< "${cur_items_ref[cur_item]}"
        fi
        local is_red_item=0
        [[ "$sel_st" == "RED" ]] && is_red_item=1

        _blines=()

        # _blines_wrap[i]=1 means entry i should be printed with autowrap (full sentence)
        _blines_wrap=()

        # Row 0: divider
        local div_title
        if (( is_red_item == 1 )); then
            div_title="── [ DETAILS & RECOMMENDATIONS ] (Press ENTER to Drill Down) "
        else
            div_title="── [ DETAILS & FINDINGS ] (Press ENTER to Drill Down) "
        fi
        local pad_len=$(( term_cols - ${#div_title} ))
        (( pad_len < 0 )) && pad_len=0
        _blines+=("${C_DARKGREY}${div_title}$(tui_repeat_char '─' "$pad_len")${C_RESET}")
        _blines_wrap+=(0)

        # Row 1: item summary
        if [[ -n "$sel_label" ]]; then
            _blines+=("${C_BOLD}Item:${C_RESET} ${C_CYAN}${sel_label}${C_RESET}   ${C_BOLD}Status:${C_RESET} $(tui_badge "$sel_st")   ${C_BOLD}Summary:${C_RESET} $(tui_fit_str "$sel_det" $(( term_cols - 45 )))")
        else
            _blines+=("")
        fi
        _blines_wrap+=(0)

        if (( is_red_item == 1 )); then
            # Issue
            local issue_raw="${cur_issues_ref[cur_item]}"
            issue_raw="${issue_raw//$'\r'/}"
            issue_raw="${issue_raw//$'\n'/ }"
            issue_raw="${issue_raw//\\n/ }"
            issue_raw="${issue_raw#"${issue_raw%%[! ]*}"}"
            issue_raw="${issue_raw%"${issue_raw##*[! ]}"}"

            # Recommendation
            local rec_raw="${cur_recs_ref[cur_item]}"
            rec_raw="${rec_raw//$'\r'/}"
            rec_raw="${rec_raw//$'\n'/ }"
            rec_raw="${rec_raw//\\n/ }"
            rec_raw="${rec_raw#"${rec_raw%%[! ]*}"}"
            rec_raw="${rec_raw%"${rec_raw##*[! ]}"}"
            [[ -z "$rec_raw" ]] && rec_raw="Investigate and remediate $sel_label to restore normal system operations."

            _blines+=("${C_RED}${C_BOLD}Issue:${C_RESET}")
            _blines_wrap+=(0)
            _blines+=("$issue_raw")         # FULL sentence, autowrap will handle visuals
            _blines_wrap+=(1)
            _blines+=("${C_GREEN}${C_BOLD}Recommendation:${C_RESET}")
            _blines_wrap+=(0)
            _blines+=("$rec_raw")           # FULL sentence, autowrap will handle visuals
            _blines_wrap+=(1)

            if (( ${#f_lines[@]} > 0 )); then
                _blines+=("${C_YELLOW}${C_BOLD}Findings & Details (${#f_lines[@]} entries):${C_RESET}")
                _blines_wrap+=(0)
                local bfi
                for (( bfi=0; bfi<${#f_lines[@]}; bfi++ )); do
                    _blines+=("  ${C_WHITE}• $(tui_fit_str "${f_lines[bfi]}" $(( term_cols - 5 )))${C_RESET}")
                    _blines_wrap+=(0)
                done
            else
                _blines+=("${C_GREY}Findings & Details: Verified normal.${C_RESET}")
                _blines_wrap+=(0)
            fi
        else
            # GREEN/OK item: no Issue/Recommendation, show Findings directly
            if (( ${#f_lines[@]} > 0 )); then
                _blines+=("${C_YELLOW}${C_BOLD}Findings & Details (${#f_lines[@]} entries):${C_RESET}")
                _blines_wrap+=(0)
                local bfi
                for (( bfi=0; bfi<${#f_lines[@]}; bfi++ )); do
                    _blines+=("  ${C_WHITE}• $(tui_fit_str "${f_lines[bfi]}" $(( term_cols - 5 )))${C_RESET}")
                    _blines_wrap+=(0)
                done
            else
                _blines+=("${C_GREY}Findings & Details: Verified normal.${C_RESET}")
                _blines_wrap+=(0)
            fi
        fi

        # Clear ALL bottom rows first (prevents stale content when switching items)
        local bot_start=$(( top_h + 3 ))   # screen row of first bottom line
        local bot_end=$(( body_h + 2 ))    # screen row of last bottom line
        local avail_bot=$(( bot_end - bot_start + 1 ))
        local total_blines=${#_blines[@]}
        local max_bot_scroll=$(( total_blines - avail_bot ))
        (( max_bot_scroll < 0 )) && max_bot_scroll=0
        (( bot_scroll > max_bot_scroll )) && bot_scroll=$max_bot_scroll
        (( bot_scroll < 0 )) && bot_scroll=0

        local bot_r
        for (( bot_r=bot_start; bot_r<=bot_end; bot_r++ )); do
            buf+=$'\033['"${bot_r};1H"$'\033[2K'
        done

        # Render _blines starting from bot_scroll offset
        buf+=$'\033['"${bot_start};1H"
        local cur_screen_row=$bot_start
        local bi
        for (( bi=bot_scroll; bi<total_blines; bi++ )); do
            # Reserve last row for overflow hint if needed
            local rows_left=$(( bot_end - cur_screen_row + 1 ))
            local items_left=$(( total_blines - bi ))

            # Top scroll-up hint (when not at beginning)
            if (( bi == bot_scroll && bot_scroll > 0 && cur_screen_row == bot_start )); then
                local up_msg=" ▲  PgUp  │  ${bot_scroll} entries above — scroll up to view  ▲ "
                local up_pad=$(( term_cols - ${#up_msg} ))
                (( up_pad < 0 )) && up_pad=0
                buf+=$'\033['"${cur_screen_row};1H"$'\033[2K'
                buf+="${BG_SCROLL_HINT}${up_msg}$(printf '%*s' $up_pad '')${C_RESET}"
                (( cur_screen_row++ ))
                (( cur_screen_row > bot_end )) && break
            fi

            # Bottom overflow hint — fills last row with bright banner
            if (( cur_screen_row == bot_end && items_left > 1 )); then
                local dn_msg=" ▼  PgDn  │  ${items_left} more findings below — press PgDn to scroll  ▼ "
                local dn_pad=$(( term_cols - ${#dn_msg} ))
                (( dn_pad < 0 )) && dn_pad=0
                buf+=$'\033['"${cur_screen_row};1H"$'\033[2K'
                buf+="${BG_SCROLL_HINT}${dn_msg}$(printf '%*s' $dn_pad '')${C_RESET}"
                break
            fi

            local entry="${_blines[bi]}"
            local do_wrap=${_blines_wrap[bi]}

            if (( do_wrap == 1 )); then
                local vis_len=${#entry}
                local rows_used=$(( (vis_len + term_cols - 1) / term_cols ))
                (( rows_used < 1 )) && rows_used=1

                local rows_avail=$(( bot_end - cur_screen_row + 1 ))
                # Reserve last row for overflow hint if more entries follow
                (( bi + 1 < total_blines )) && (( rows_avail-- ))
                if (( rows_avail <= 0 )); then
                    local dn_msg2=" ▼  PgDn  │  $(( total_blines - bi )) more findings below — press PgDn to scroll  ▼ "
                    local dn_pad2=$(( term_cols - ${#dn_msg2} ))
                    (( dn_pad2 < 0 )) && dn_pad2=0
                    buf+=$'\033['"${cur_screen_row};1H"$'\033[2K'
                    buf+="${BG_SCROLL_HINT}${dn_msg2}$(printf '%*s' $dn_pad2 '')${C_RESET}"
                    break
                fi
                if (( rows_used > rows_avail )); then
                    rows_used=$rows_avail
                    local max_chars=$(( rows_avail * term_cols ))
                    entry="${entry:0:$max_chars}"
                fi

                buf+=$'\033[?7h'"${entry}"$'\033[?7l'
                cur_screen_row=$(( cur_screen_row + rows_used ))
                (( cur_screen_row <= bot_end )) && buf+=$'\033['"${cur_screen_row};1H"
            else
                buf+=$'\033['"${cur_screen_row};1H"$'\033[2K'"${entry}"
                (( cur_screen_row++ ))
                (( cur_screen_row <= bot_end )) && buf+=$'\033['"${cur_screen_row};1H"
            fi
        done

        # Blank remaining rows
        while (( cur_screen_row <= bot_end )); do
            buf+=$'\033['"${cur_screen_row};1H"$'\033[2K'
            (( cur_screen_row++ ))
        done

        # Footer row
        local footer_txt
        if [[ -n "$status_msg" ]]; then
            footer_txt=" $status_msg "
        elif (( pane_focus == 0 )); then
            if (( cur_cat >= 7 )); then
                footer_txt=" [↑/↓] Browse Categories  [ENTER/→] View Log  [1-9] Jump  [s] Save  [?] Help  [q] Quit "
            else
                footer_txt=" [↑/↓] Browse Categories  [ENTER/TAB] Open Category  [1-9] Jump  [s] Save  [?] Help  [q] Quit "
            fi
        else
            if (( cur_cat >= 7 )); then
                footer_txt=" [↑/↓/PgUp/PgDn] Scroll Log  [TAB/←] Categories  [s] Save  [?] Help  [q] Quit "
            else
                footer_txt=" [↑/↓] Browse Items  [PgDn/PgUp] Scroll Findings  [ENTER] Drill-down  [TAB/←] Categories  [s] Save  [?] Help  [q] Quit "
            fi
        fi
        buf+=$'\033['"${term_lines};1H${BG_FOOTER}$(tui_fit_str "$footer_txt" "$term_cols")${C_RESET}"$'\033[K'

        # Render Drill-Down Modal if active
        if (( in_drilldown == 1 && cur_cat <= 6 )); then
            local mw=$(( term_cols - 6 ))
            (( mw > 115 )) && mw=115
            (( mw < 60 )) && mw=60
            local mh=$(( term_lines - 4 ))
            (( mh < 14 )) && mh=14
            local mx=$(( (term_cols - mw) / 2 ))
            local my=$(( (term_lines - mh) / 2 ))

            local it_entry="${cur_items_ref[cur_item]}"
            local it_label it_st it_det it_key
            IFS='|' read -r it_label it_st it_det it_key <<< "$it_entry"
            local it_issue="${cur_issues_ref[cur_item]}"
            local it_badge
            it_badge=$(tui_badge "$it_st")

            local fit_lbl
            fit_lbl=$(tui_fit_str "$it_label" 25)
            local top_title="┌─ [ DRILL-DOWN: ${fit_lbl} ] "
            local top_pad=$(( mw - 1 - ${#top_title} ))
            (( top_pad < 0 )) && top_pad=0
            local box_top="${top_title}$(tui_repeat_char '─' "$top_pad")┐"
            local box_div="├$(tui_repeat_char '─' $(( mw - 2 )))┤"
            local box_bot="└$(tui_repeat_char '─' $(( mw - 2 )))┘"

            buf+=$'\033['"${my};${mx}H${BG_ACTIVE}${box_top}${C_RESET}"
            
            # Row 1: Category & Status
            local r1=" Category: ${cat_names[cur_cat]}    Status: ${it_badge}    Summary: $it_det"
            buf+=$'\033['"$(( my + 1 ));${mx}H${BG_ACTIVE}│$(tui_fit_str "$r1" $(( mw - 2 )))│${C_RESET}"

            if [[ "$it_st" == "RED" ]]; then
                # Row 2: Issue Description
                local r2=" Issue: ${it_issue}"
                buf+=$'\033['"$(( my + 2 ));${mx}H${BG_ACTIVE}│$(tui_fit_str "$r2" $(( mw - 2 )))│${C_RESET}"

                # Scrollable Findings Area
                local findings_area_h=$(( mh - 8 ))
                (( findings_area_h < 4 )) && findings_area_h=4
                max_drill_scroll=$(( ${#f_lines[@]} - findings_area_h ))
                (( max_drill_scroll < 0 )) && max_drill_scroll=0
                (( drill_scroll > max_drill_scroll )) && drill_scroll=$max_drill_scroll
                (( drill_scroll < 0 )) && drill_scroll=0

                # Row 3: Section Divider
                local scroll_info=""
                if (( ${#f_lines[@]} > findings_area_h )); then
                    local end_line=$(( drill_scroll + findings_area_h ))
                    (( end_line > ${#f_lines[@]} )) && end_line=${#f_lines[@]}
                    scroll_info=" [Showing $(( drill_scroll + 1 ))-${end_line} of ${#f_lines[@]}]"
                fi
                local r3_title=" ALL FINDINGS & DETAILS (${#f_lines[@]} items)${scroll_info} [↑/↓ Scroll, ESC/q Close] "
                local div_pad=$(( mw - 3 - ${#r3_title} ))
                (( div_pad < 0 )) && div_pad=0
                buf+=$'\033['"$(( my + 3 ));${mx}H${BG_ACTIVE}├─${r3_title}$(tui_repeat_char '─' "$div_pad")┤${C_RESET}"

                local fi screen_fi
                for (( fi=0; fi<findings_area_h; fi++ )); do
                    screen_fi=$(( my + 4 + fi ))
                    local line_idx=$(( drill_scroll + fi ))
                    local fl_txt=""
                    if (( line_idx < ${#f_lines[@]} )); then
                        local num_prefix
                        printf -v num_prefix "%2d. " "$(( line_idx + 1 ))"
                        fl_txt=" ${num_prefix}${f_lines[line_idx]}"
                    elif (( ${#f_lines[@]} == 0 && fi == 0 )); then
                        fl_txt=" No specific finding items reported. Component is verified."
                    fi
                    buf+=$'\033['"${screen_fi};${mx}H${BG_ACTIVE}│$(tui_fit_str "$fl_txt" $(( mw - 2 )))│${C_RESET}"
                done

                # Recommendation Divider & Section
                local rec_y=$(( my + 4 + findings_area_h ))
                buf+=$'\033['"${rec_y};${mx}H${BG_ACTIVE}${box_div}${C_RESET}"
                
                local rec_txt=" Recommendation: ${rec_lines[0]}"
                buf+=$'\033['"$(( rec_y + 1 ));${mx}H${BG_ACTIVE}│$(tui_fit_str "$rec_txt" $(( mw - 2 )))│${C_RESET}"
                local rec_txt2=""
                if (( ${#rec_lines[@]} > 1 )); then
                    rec_txt2=" ${rec_lines[1]}"
                elif (( ${#rec_lines[@]} > 0 && ${#rec_lines[0]} > mw - 20 )); then
                    rec_txt2=" ${rec_lines[0]:$(( mw - 20 ))}"
                fi
                buf+=$'\033['"$(( rec_y + 2 ));${mx}H${BG_ACTIVE}│$(tui_fit_str "$rec_txt2" $(( mw - 2 )))│${C_RESET}"

                # Fill any remaining rows up to my + mh - 1 with solid background
                local fill_y
                for (( fill_y = rec_y + 3; fill_y < my + mh; fill_y++ )); do
                    buf+=$'\033['"${fill_y};${mx}H${BG_ACTIVE}│$(tui_repeat_char ' ' $(( mw - 2 )))│${C_RESET}"
                done
            else
                # NON-RED ITEM: Findings area gets full height, no Issue / Recommendation
                local findings_area_h=$(( mh - 4 ))
                (( findings_area_h < 4 )) && findings_area_h=4
                max_drill_scroll=$(( ${#f_lines[@]} - findings_area_h ))
                (( max_drill_scroll < 0 )) && max_drill_scroll=0
                (( drill_scroll > max_drill_scroll )) && drill_scroll=$max_drill_scroll
                (( drill_scroll < 0 )) && drill_scroll=0

                # Row 2: Section Divider
                local scroll_info=""
                if (( ${#f_lines[@]} > findings_area_h )); then
                    local end_line=$(( drill_scroll + findings_area_h ))
                    (( end_line > ${#f_lines[@]} )) && end_line=${#f_lines[@]}
                    scroll_info=" [Showing $(( drill_scroll + 1 ))-${end_line} of ${#f_lines[@]}]"
                fi
                local r2_title=" ALL FINDINGS & DETAILS (${#f_lines[@]} items)${scroll_info} [↑/↓ Scroll, ESC/q Close] "
                local div_pad=$(( mw - 3 - ${#r2_title} ))
                (( div_pad < 0 )) && div_pad=0
                buf+=$'\033['"$(( my + 2 ));${mx}H${BG_ACTIVE}├─${r2_title}$(tui_repeat_char '─' "$div_pad")┤${C_RESET}"

                local fi screen_fi
                for (( fi=0; fi<findings_area_h; fi++ )); do
                    screen_fi=$(( my + 3 + fi ))
                    local line_idx=$(( drill_scroll + fi ))
                    local fl_txt=""
                    if (( line_idx < ${#f_lines[@]} )); then
                        local num_prefix
                        printf -v num_prefix "%2d. " "$(( line_idx + 1 ))"
                        fl_txt=" ${num_prefix}${f_lines[line_idx]}"
                    elif (( ${#f_lines[@]} == 0 && fi == 0 )); then
                        fl_txt=" No specific finding items reported. Component is verified normal."
                    fi
                    buf+=$'\033['"${screen_fi};${mx}H${BG_ACTIVE}│$(tui_fit_str "$fl_txt" $(( mw - 2 )))│${C_RESET}"
                done

                # Fill any remaining rows up to my + mh - 1 with solid background
                local fill_y
                for (( fill_y = my + 3 + findings_area_h; fill_y < my + mh; fill_y++ )); do
                    buf+=$'\033['"${fill_y};${mx}H${BG_ACTIVE}│$(tui_repeat_char ' ' $(( mw - 2 )))│${C_RESET}"
                done
            fi

            # Footer of Modal
            buf+=$'\033['"$(( my + mh ));${mx}H${BG_ACTIVE}${box_bot}${C_RESET}"
        fi

        # Render Help Overlay if requested
        if (( show_help == 1 )); then
            local hw=58 hh=14
            local hx=$(( (term_cols - hw) / 2 ))
            local hy=$(( (term_lines - hh) / 2 ))
            local box_top="┌$(tui_repeat_char '─' $(( hw - 2 )))┐"
            local box_bot="└$(tui_repeat_char '─' $(( hw - 2 )))┘"

            buf+=$'\033['"${hy};${hx}H${BG_ACTIVE}${box_top}${C_RESET}"
            local help_lines=(
                "  BOBCARES AUDIT TUI - QUICK HELP"
                "────────────────────────────────────────────────────────"
                "  ↑ / k , ↓ / j   : Move selection up / down"
                "  Tab             : Toggle focus between Panes"
                "  ← / h , → / l   : Switch pane"
                "  Enter / d       : Drill-down / View full details"
                "  1 - 9           : Direct jump to category 1 to 9"
                "  PgUp / PgDn     : Scroll logs or drill-down (10 lines)"
                "  s / S           : Show report export locations"
                "  ?               : Toggle this help overlay"
                "  q / Q / ESC     : Exit TUI or close modal"
                "────────────────────────────────────────────────────────"
                "               Press any key to dismiss"
            )
            local hl_idx
            for (( hl_idx=0; hl_idx<${#help_lines[@]}; hl_idx++ )); do
                local cur_hy=$(( hy + hl_idx + 1 ))
                local line_str="${help_lines[hl_idx]}"
                buf+=$'\033['"${cur_hy};${hx}H${BG_ACTIVE}│$(tui_fit_str "$line_str" $(( hw - 2 )))│${C_RESET}"
            done
            buf+=$'\033['"$(( hy + hh ));${hx}H${BG_ACTIVE}${box_bot}${C_RESET}"
        fi

        if $use_fd3; then
            printf '%s' "$buf" >&3
        else
            printf '%s' "$buf"
        fi
    }

    render_tui

    # Interactive input loop with exact escape-sequence handling
    local ESC
    printf -v ESC '\033'

    if $use_fd3; then
        while true; do
            status_msg=""
            local key="" seq="" seq2=""
            local key="" seq="" seq2="" wheel_ticks=1
            IFS= read -rsn1 key <&3 || break

            if [[ "$key" == "$ESC" ]]; then
                local c1="" c2=""
                if read -rsn1 -t 0.05 c1 <&3 2>/dev/null; then
                    key+="$c1"
                    if [[ "$c1" == "[" || "$c1" == "O" ]]; then
                        if read -rsn1 -t 0.05 c2 <&3 2>/dev/null; then
                            key+="$c2"
                            if [[ "$c1" == "[" && "$c2" == "<" ]]; then
                                # SGR mouse event (\033[<btn;x;yM or m)
                                local sgr_body="" m_term=""
                                while read -rsn1 -t 0.05 m_term <&3 2>/dev/null; do
                                    if [[ "$m_term" == "M" || "$m_term" == "m" ]]; then
                                        break
                                    fi
                                    sgr_body+="$m_term"
                                done
                                local sgr_btn="${sgr_body%%;*}"
                                if [[ "$sgr_btn" == "64" ]]; then
                                    # Mouse Wheel UP: drain burst and set WHEEL_UP
                                    wheel_ticks=1
                                    while read -rsn1 -t 0.005 peek_esc <&3 2>/dev/null; do
                                        if [[ "$peek_esc" == "$ESC" ]]; then
                                            read -rsn8 -t 0.005 _discard <&3 2>/dev/null
                                            (( wheel_ticks++ ))
                                        fi
                                        (( wheel_ticks >= 5 )) && break
                                    done
                                    key="WHEEL_UP"
                                elif [[ "$sgr_btn" == "65" ]]; then
                                    # Mouse Wheel DOWN: drain burst and set WHEEL_DOWN
                                    wheel_ticks=1
                                    while read -rsn1 -t 0.005 peek_esc <&3 2>/dev/null; do
                                        if [[ "$peek_esc" == "$ESC" ]]; then
                                            read -rsn8 -t 0.005 _discard <&3 2>/dev/null
                                            (( wheel_ticks++ ))
                                        fi
                                        (( wheel_ticks >= 5 )) && break
                                    done
                                    key="WHEEL_DOWN"
                                else
                                    # Clicks, drags, and releases are ignored so selection/pointer stays native
                                    while read -rsn1 -t 0.002 _discard <&3 2>/dev/null; do :; done
                                    continue
                                fi
                            elif [[ "$c1" == "[" && "$c2" == "M" ]]; then
                                # X10 mouse event (\033[M B x y)
                                local m_b=""
                                read -rsn1 -t 0.05 m_b <&3 2>/dev/null
                                read -rsn2 -t 0.05 _discard <&3 2>/dev/null
                                local m_code
                                printf -v m_code "%d" "'$m_b"
                                if (( m_code == 96 )); then
                                    key="WHEEL_UP"
                                    wheel_ticks=1
                                elif (( m_code == 97 )); then
                                    key="WHEEL_DOWN"
                                    wheel_ticks=1
                                else
                                    continue
                                fi
                            elif [[ "$c2" =~ [0-9] ]]; then
                                # Extended escape sequence (e.g. \033[5~, \033[1;2A)
                                local rest=""
                                while read -rsn1 -t 0.05 rest <&3 2>/dev/null; do
                                    key+="$rest"
                                    if [[ "$rest" == "M" || "$rest" == "m" ]]; then
                                        local rx_rxvt='^'$'\033''\[[0-9]+;[0-9]+;[0-9]+[Mm]$'
                                        if [[ "$key" =~ $rx_rxvt ]]; then
                                            key=""
                                            break
                                        fi
                                    fi
                                    [[ "$rest" =~ [a-zA-Z~] ]] && break
                                done
                                if [[ -z "$key" ]]; then
                                    while read -rsn1 -t 0.002 _discard <&3 2>/dev/null; do :; done
                                    continue
                                fi
                            fi
                        fi
                    fi
                fi
            fi

            # Prevent rapid arrow key bursts (e.g. from touchpad momentum or key hold) from freezing the script
            local rx_arrow='^'$'\033''(\[[AB]|O[AB])'
            local arrow_ticks=1
            if [[ "$key" =~ $rx_arrow ]]; then
                while (( arrow_ticks < 4 )) && read -rsn3 -t 0.005 _discard <&3 2>/dev/null; do
                    (( arrow_ticks++ ))
                done
            fi


            if (( show_help == 1 )); then
                show_help=0
                render_tui
                continue
            fi

            # Handle Drill-down modal interactions
            if (( in_drilldown == 1 )); then
                case "$key" in
                    q|Q|"$ESC"|""|$'\n'|$'\r'|d|D|" "|x|X|$'\x03')
                        in_drilldown=0
                        while IFS= read -rsn1 -t 0.05 _discard <&3 2>/dev/null; do :; done
                        ;;
                    "${ESC}[A"|"${ESC}OA"|"${ESC}[1;2A"|k|K) # UP
                        local step=$(( arrow_ticks * 2 ))
                        (( drill_scroll >= step )) && (( drill_scroll -= step )) || drill_scroll=0
                        ;;
                    "${ESC}[B"|"${ESC}OB"|"${ESC}[1;2B"|j|J) # DOWN
                        local step=$(( arrow_ticks * 2 ))
                        (( drill_scroll + step <= max_drill_scroll )) && (( drill_scroll += step )) || drill_scroll=$max_drill_scroll
                        ;;
                    WHEEL_UP) # Mouse wheel up
                        local step=$(( wheel_ticks * 3 ))
                        (( drill_scroll >= step )) && (( drill_scroll -= step )) || drill_scroll=0
                        ;;
                    WHEEL_DOWN) # Mouse wheel down
                        local step=$(( wheel_ticks * 3 ))
                        (( drill_scroll + step <= max_drill_scroll )) && (( drill_scroll += step )) || drill_scroll=$max_drill_scroll
                        ;;
                    "${ESC}[5~"|"${ESC}[5;2~") # PgUp
                        (( drill_scroll >= 10 )) && (( drill_scroll -= 10 )) || drill_scroll=0
                        ;;
                    "${ESC}[6~"|"${ESC}[6;2~") # PgDn
                        (( drill_scroll + 10 <= max_drill_scroll )) && (( drill_scroll += 10 )) || drill_scroll=$max_drill_scroll
                        ;;
                    "${ESC}[1~"|"${ESC}[7~"|"${ESC}[H"|"${ESC}OH") # Home
                        drill_scroll=0
                        ;;
                    "${ESC}[4~"|"${ESC}[8~"|"${ESC}[F"|"${ESC}OF") # End
                        drill_scroll=$max_drill_scroll
                        ;;
                esac
                render_tui
                continue
            fi

            case "$key" in
                q|Q|"$ESC"|$'\x03')
                    break
                    ;;
                "?"|H)
                    show_help=1
                    ;;
                h)
                    if (( pane_focus == 1 )); then
                        pane_focus=0
                    else
                        show_help=1
                    fi
                    ;;
                $'\t')
                    pane_focus=$(( 1 - pane_focus ))
                    ;;
                WHEEL_UP) # Mouse Wheel Up
                    if (( pane_focus == 0 )); then
                        if (( cur_cat > 0 )); then
                            (( cur_cat-- ))
                            cur_item=0
                            log_scroll=0
                            item_scroll=0
                            bot_scroll=0
                        fi
                    elif (( cur_cat >= 7 )); then
                        local step=$(( wheel_ticks * 3 ))
                        (( log_scroll >= step )) && (( log_scroll -= step )) || log_scroll=0
                    else
                        (( cur_item >= wheel_ticks )) && (( cur_item -= wheel_ticks )) || cur_item=0
                        bot_scroll=0
                    fi
                    ;;
                WHEEL_DOWN) # Mouse Wheel Down
                    if (( pane_focus == 0 )); then
                        if (( cur_cat < 8 )); then
                            (( cur_cat++ ))
                            cur_item=0
                            log_scroll=0
                            item_scroll=0
                            bot_scroll=0
                        fi
                    elif (( cur_cat >= 7 )); then
                        local -n cur_log_arr
                        (( cur_cat == 7 )) && cur_log_arr="findings_lines" || cur_log_arr="summary_lines"
                        local max_scroll=$(( ${#cur_log_arr[@]} - 5 ))
                        (( max_scroll < 0 )) && max_scroll=0
                        local step=$(( wheel_ticks * 3 ))
                        (( log_scroll + step <= max_scroll )) && (( log_scroll += step )) || log_scroll=$max_scroll
                    else
                        local -n cur_arr="cat_items_${cur_cat}"
                        local max_it=${#cur_arr[@]}
                        (( cur_item + wheel_ticks < max_it )) && (( cur_item += wheel_ticks )) || cur_item=$(( max_it - 1 ))
                        (( cur_item < 0 )) && cur_item=0
                        bot_scroll=0
                    fi
                    ;;
                "${ESC}[A"|"${ESC}OA"|"${ESC}[1;2A"|"${ESC}[1;5A"|k|K) # UP
                    if (( pane_focus == 0 )); then
                        if (( cur_cat > 0 )); then
                            (( cur_cat-- ))
                            cur_item=0
                            log_scroll=0
                            item_scroll=0
                            bot_scroll=0
                        fi
                    elif (( cur_cat >= 7 )); then
                        local step=$(( arrow_ticks * 3 ))
                        (( log_scroll >= step )) && (( log_scroll -= step )) || log_scroll=0
                    else
                        if (( cur_item >= arrow_ticks )); then
                            (( cur_item -= arrow_ticks ))
                        else
                            cur_item=0
                        fi
                        bot_scroll=0
                    fi
                    ;;
                "${ESC}[B"|"${ESC}OB"|"${ESC}[1;2B"|"${ESC}[1;5B"|j|J) # DOWN
                    if (( pane_focus == 0 )); then
                        if (( cur_cat < 8 )); then
                            (( cur_cat++ ))
                            cur_item=0
                            log_scroll=0
                            item_scroll=0
                            bot_scroll=0
                        fi
                    elif (( cur_cat >= 7 )); then
                        local -n cur_log_arr
                        (( cur_cat == 7 )) && cur_log_arr="findings_lines" || cur_log_arr="summary_lines"
                        local max_scroll=$(( ${#cur_log_arr[@]} - 5 ))
                        (( max_scroll < 0 )) && max_scroll=0
                        local step=$(( arrow_ticks * 3 ))
                        (( log_scroll + step <= max_scroll )) && (( log_scroll += step )) || log_scroll=$max_scroll
                    else
                        local -n cur_arr="cat_items_${cur_cat}"
                        local max_it=${#cur_arr[@]}
                        (( cur_item + arrow_ticks < max_it )) && (( cur_item += arrow_ticks )) || cur_item=$(( max_it - 1 ))
                        (( cur_item < 0 )) && cur_item=0
                        bot_scroll=0
                    fi
                    ;;
                "${ESC}[D"|"${ESC}OD") # LEFT
                    pane_focus=0
                    ;;
                "${ESC}[C"|"${ESC}OC"|l|L) # RIGHT
                    pane_focus=1
                    ;;
                ""|$'\n'|$'\r') # ENTER: Select category or drill-down into item
                    if (( pane_focus == 0 )); then
                        pane_focus=1
                    elif (( cur_cat <= 6 )); then
                        in_drilldown=1
                        drill_scroll=0
                        while IFS= read -rsn1 -t 0.05 _discard <&3 2>/dev/null; do :; done
                    fi
                    ;;
                d|D) # 'd': Drill-down modal
                    if (( cur_cat <= 6 )); then
                        in_drilldown=1
                        drill_scroll=0
                        while IFS= read -rsn1 -t 0.05 _discard <&3 2>/dev/null; do :; done
                    fi
                    ;;

                "${ESC}[5~"|"${ESC}[5;2~") # PgUp
                    if (( pane_focus == 0 )); then
                        cur_cat=0
                        cur_item=0
                        bot_scroll=0
                    elif (( cur_cat <= 6 )); then
                        # Scroll bot pane findings up
                        (( bot_scroll >= 5 )) && (( bot_scroll -= 5 )) || bot_scroll=0
                    else
                        (( log_scroll >= 10 )) && (( log_scroll -= 10 )) || log_scroll=0
                    fi
                    ;;
                "${ESC}[6~"|"${ESC}[6;2~") # PgDn
                    if (( pane_focus == 0 )); then
                        cur_cat=8
                        cur_item=0
                        bot_scroll=0
                    elif (( cur_cat <= 6 )); then
                        # Scroll bot pane findings down
                        local -n cur_arr_pg="cat_items_${cur_cat}"
                        local max_bot_pg=$(( ${#_blines[@]} - 1 ))
                        (( max_bot_pg < 0 )) && max_bot_pg=0
                        (( bot_scroll + 5 <= max_bot_pg )) && (( bot_scroll += 5 )) || bot_scroll=$max_bot_pg
                    else
                        local -n cur_log_arr_pg
                        (( cur_cat == 7 )) && cur_log_arr_pg="findings_lines" || cur_log_arr_pg="summary_lines"
                        local max_pg=$(( ${#cur_log_arr_pg[@]} - 5 ))
                        (( max_pg < 0 )) && max_pg=0
                        (( log_scroll + 10 <= max_pg )) && (( log_scroll += 10 )) || log_scroll=$max_pg
                    fi
                    ;;
                "${ESC}[1~"|"${ESC}[7~"|"${ESC}[H"|"${ESC}OH") # Home
                    if (( pane_focus == 0 )); then
                        cur_cat=0
                        cur_item=0
                        log_scroll=0
                        item_scroll=0
                    else
                        cur_item=0
                        log_scroll=0
                    fi
                    ;;
                "${ESC}[4~"|"${ESC}[8~"|"${ESC}[F"|"${ESC}OF") # End
                    if (( pane_focus == 0 )); then
                        cur_cat=8
                        cur_item=0
                        log_scroll=0
                        item_scroll=0
                    elif (( cur_cat >= 7 )); then
                        local -n cur_log_arr_end
                        (( cur_cat == 7 )) && cur_log_arr_end="findings_lines" || cur_log_arr_end="summary_lines"
                        local max_end=$(( ${#cur_log_arr_end[@]} - 5 ))
                        (( max_end < 0 )) && max_end=0
                        log_scroll=$max_end
                    else
                        local -n cur_arr_end="cat_items_${cur_cat}"
                        local max_it=${#cur_arr_end[@]}
                        (( max_it > 0 )) && cur_item=$(( max_it - 1 ))
                    fi
                    ;;
                1|2|3|4|5|6|7|8|9)
                    if [[ ${#key} -eq 1 ]]; then
                        cur_cat=$(( key - 1 ))
                        cur_item=0
                        log_scroll=0
                        item_scroll=0
                        pane_focus=0
                    fi
                    ;;
                s|S)
                    status_msg="[Saved] Reports ready in /root/scripts/ (Markdown, Findings, Recommendations, Detailed)"
                    ;;
            esac
            render_tui
        done
    fi
    trap - WINCH 2>/dev/null || true
    cleanup_terminal
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

main() {
    [[ $EUID -ne 0 ]] && echo "[WARN] Not running as root - several checks will be incomplete."

    if [[ "$VIEW_ONLY" == "true" ]]; then
        load_all_state >/dev/null 2>&1 || true
        collect_os_details >/dev/null 2>&1 || true
        collect_system_info >/dev/null 2>&1 || true
        check_resource_usage >/dev/null 2>&1 || true
        if [[ -z "$OTHER_UPDATE_COUNT" || "$OTHER_UPDATE_COUNT" -eq 0 ]] && [[ ! -f "$FINDINGS_FILE" ]]; then
            check_package_updates >/dev/null 2>&1 || true
        fi
        run_audit_tui
        return 0
    fi

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
    generate_issues_and_recommendations_log
    generate_smart_summary
    generate_detailed_log

    echo
    echo "Audit Complete!"
    echo "Findings Log         : $FINDINGS_FILE"
    echo "Recommendations Log  : $RECOMMENDATIONS_FILE"
    echo "Smart Summary        : $SUMMARY_FILE"
    echo "Detailed Log         : $DETAILED_FILE"
    echo "Malware Details Log  : /root/scripts/malware-details-report.txt"
    echo "Malware Scan Report  : /root/scripts/malware-scan-report.txt"
    echo "Debug Log            : $DEBUG_LOG"

    if [[ -s "$RECOMMENDATIONS_FILE" ]] && grep -q "Sub Category:" "$RECOMMENDATIONS_FILE"; then
        echo
        colorize_recommendations < "$RECOMMENDATIONS_FILE"
    fi

    echo
    echo "===================== AUDIT SUMMARY ====================="
    echo
    echo "[INFO]    Audit report files are available in:"
    echo "          /root/scripts/"
    echo "          Please review them before submitting to the Bobcares portal."
    echo
    echo "[INFO]    Malware scan reports can be found at:"
    echo "          - /root/scripts/malware-details-report.txt"
    echo "          - /root/scripts/malware-scan-report.txt"
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
    if [[ "$NO_TUI" != "true" ]]; then
        if [ -t 0 ] || [ -c /dev/tty ]; then
            sleep 1
            run_audit_tui
        fi
    fi
}

main "$@"

