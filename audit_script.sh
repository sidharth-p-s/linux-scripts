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


SUMMARY_FILE="audit-smart-summary.md"
DETAILED_FILE="report-detailed.log"
DEBUG_LOG="audit-debug.log"

STATE_DIR=$(mktemp -d /tmp/bc-audit.XXXXXX)
trap 'rm -rf "$STATE_DIR"' EXIT

if [ -f "$DEBUG_LOG" ]; then
    mv -f "$DEBUG_LOG" "${DEBUG_LOG}.prev" 2>/dev/null || rm -f "$DEBUG_LOG"
fi

exec > >(stdbuf -o0 tr -cd '\11\12\15\40-\176' | tee -a "$DEBUG_LOG") 2>&1

echo "=== Starting Bobcares Smart Audit at $(date) ==="
echo "Debug log: $DEBUG_LOG | State dir: $STATE_DIR"
echo

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

# ====================== EOL DEFINITIONS ======================
UBUNTU_EOL_VERSIONS=(
    "14.04" "14.10" "15.04" "15.10" "16.04" "16.10" "17.04" "17.10"
    "18.04" "18.10" "19.04" "19.10" "20.04" "20.10" "21.04" "21.10"
    "22.10" "23.04" "23.10" "24.10" "25.04" "25.10"
)

declare -A EOL_VERSIONS=(
    [centos]="6 7 8"
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
    local ip="$1" r
    r=$(dig @8.8.8.8 +time=3 +tries=1 -x "$ip" +short 2>/dev/null | sed 's/\.$//' | head -1)
    [[ -z "$r" ]] && r="None"
    save_state_file "rdns.env" RDNS "$r"
}

#-------------------------------------------------------------------------------
# IP Reputation Check (DNSBL)
#-------------------------------------------------------------------------------

check_ip_reputation() {
    echo "[DEBUG] Checking IP reputation..."
    IP_REPUTATION_STATUS="ðŸŸ¢ Good"
    IP_REPUTATION_DETAIL="Not listed on major DNSBLs"

    if [[ -z "$MAIN_IP" ]]; then
        IP_REPUTATION_STATUS="ðŸ”µ Unknown"
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
        result=$(dig @8.8.8.8 +short +time=2 +tries=1 "$rev_ip.$dnsbl" 2>/dev/null | head -1)
        if [[ -n "$result" && "$result" != "127.0.0.1" ]]; then  # Some return 127.0.0.1 for errors
            listed_on+=("$dnsbl")
        fi
    done

    if [[ ${#listed_on[@]} -gt 0 ]]; then
        IP_REPUTATION_STATUS="ðŸŸ¡ Listed"
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

collect_system_info() {
    echo "[DEBUG] Collecting system resource info..."
    HOSTNAME=$(hostname)
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p 2>/dev/null || uptime)
    LOAD=$(awk '{print $1}' /proc/loadavg)
    RAM_PCT=$(free | awk '/Mem:/ {print int($3/$2*100)}')
    DISK_PCT=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')

    local web_server_proc
    web_server_proc=$(pgrep -o -x 'httpd|apache2|nginx|lshttpd' 2>/dev/null)
    if [[ -n "$web_server_proc" ]]; then
        HTTP_UPTIME=$(ps -p "$web_server_proc" -o etime= 2>/dev/null | xargs)
        HTTP_STATUS="ðŸŸ¢ Running"
    else
        HTTP_UPTIME="Not running"
        HTTP_STATUS="ðŸ”´ Down"
    fi

    UPTIME_STATUS="ðŸŸ¢ Good"
    [[ "$UPTIME" == *"minute"* && "$UPTIME" != *"hour"* && "$UPTIME" != *"day"* && "$UPTIME" != *"week"* ]] \
        && UPTIME_STATUS="ðŸŸ¡ Recently rebooted"

    if command -v exim >/dev/null 2>&1; then
        EMAIL_QUEUE=$(exim -bpc 2>/dev/null)
        [[ ! "$EMAIL_QUEUE" =~ ^[0-9]+$ ]] && EMAIL_QUEUE=0
    else
        EMAIL_QUEUE="N/A"
    fi

    export HOSTNAME KERNEL UPTIME UPTIME_STATUS HTTP_UPTIME HTTP_STATUS LOAD RAM_PCT DISK_PCT EMAIL_QUEUE
}

check_ssh_config() {
    local sshd_out
    sshd_out=$(sshd -T 2>/dev/null)

    ROOT_LOGIN_RAW=$(awk '/^permitrootlogin/{print tolower($2)}' <<<"$sshd_out")
    SSH_PASSWORD_AUTH=$(awk '/^passwordauthentication/{print tolower($2)}' <<<"$sshd_out")
    SSH_PORT=$(awk '/^port /{print $2}' <<<"$sshd_out" | paste -sd, -)

    if [[ "$ROOT_LOGIN_RAW" =~ ^(no|prohibit-password|without-password|forced-commands-only)$ ]]; then
        ROOT_LOGIN_STATUS="ðŸŸ¢ Good (Disabled / Key Only)"
    elif [[ -z "$ROOT_LOGIN_RAW" ]]; then
        ROOT_LOGIN_STATUS="ðŸ”µ Unknown"; ROOT_LOGIN_RAW="sshd -T failed (run as root?)"
    else
        ROOT_LOGIN_STATUS="ðŸ”´ Enabled"
    fi

    if [[ "$SSH_PASSWORD_AUTH" == "no" ]]; then
        SSH_PASSAUTH_STATUS="ðŸŸ¢ Key-only"
    elif [[ -z "$SSH_PASSWORD_AUTH" ]]; then
        SSH_PASSAUTH_STATUS="ðŸ”µ Unknown"; SSH_PASSWORD_AUTH="unknown"
    else
        SSH_PASSAUTH_STATUS="ðŸŸ¡ Password auth enabled"
    fi

    [[ -z "$SSH_PORT" ]] && SSH_PORT="unknown"

    TMP_SEC=$(mount | grep -w /tmp | grep -q noexec && echo "yes" || echo "no")
    if [[ "$TMP_SEC" == "yes" ]]; then
        TMP_SEC_STATUS="ðŸŸ¢ Good"; TMP_SEC_DETAIL="/tmp is mounted with noexec"
    else
        TMP_SEC_STATUS="ðŸŸ¡ Warning"; TMP_SEC_DETAIL="/tmp is NOT mounted with noexec"
    fi

    export ROOT_LOGIN_RAW ROOT_LOGIN_STATUS SSH_PASSWORD_AUTH SSH_PASSAUTH_STATUS SSH_PORT TMP_SEC TMP_SEC_STATUS TMP_SEC_DETAIL
}

check_system_firewall() {
    if csf -l &>/dev/null || systemctl is-active --quiet firewalld 2>/dev/null || systemctl is-active --quiet ufw 2>/dev/null; then
        SYSTEM_FIREWALL_STATUS="ðŸŸ¢ Good"; SYSTEM_FIREWALL_ANALYSIS="Active"
    else
        SYSTEM_FIREWALL_STATUS="ðŸŸ¡ Warning"; SYSTEM_FIREWALL_ANALYSIS="Recommend enabling CSF or firewalld"
    fi
    export SYSTEM_FIREWALL_STATUS SYSTEM_FIREWALL_ANALYSIS
}

check_brute_force_protection() {
    BRUTE_STATUS="ðŸŸ¡ Warning"; BRUTE_REASON="No active brute force protection detected"

    if command -v imunify360-agent >/dev/null 2>&1 && systemctl is-active --quiet imunify360 2>/dev/null; then
        BRUTE_STATUS="ðŸŸ¢ Good"; BRUTE_REASON="Imunify360 active"
    elif command -v csf >/dev/null 2>&1 && systemctl is-active --quiet lfd 2>/dev/null \
         && grep -qE '^\s*LF_[A-Z0-9_]+\s*=\s*"?[1-9]' /etc/csf/csf.conf 2>/dev/null; then
        BRUTE_STATUS="ðŸŸ¢ Good"; BRUTE_REASON="CSF/LFD with Login Failure Detection"
    elif command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban 2>/dev/null; then
        local jails
        jails=$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{print $2}' | xargs)
        BRUTE_STATUS="ðŸŸ¢ Good"; BRUTE_REASON="Fail2Ban active${jails:+ (jails: $jails)}"
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

    [[ $DAYS_OLD -le 90 ]] && ROOT_PW_STATUS="ðŸŸ¢ Good" || ROOT_PW_STATUS="ðŸŸ¡ Warning"
    export DAYS_OLD ROOT_PW_STATUS
}

#-------------------------------------------------------------------------------
# NEW v4: Threat protection tool status (Malware Scanner / Rootkit Scanner)
#-------------------------------------------------------------------------------

check_threat_tools() {
    local clam="no" cron="no"
    command -v clamscan >/dev/null 2>&1 && clam="yes"
    [ -f /etc/cron.d/bc-malware-scan ] && cron="yes"

    if [[ "$clam" == "yes" && "$cron" == "yes" ]]; then
        MALWARE_SCANNER_STATUS="ðŸŸ¢ Good"
        MALWARE_SCANNER_DETAIL="ClamAV installed + weekly Bobcares scan cron active"
    elif [[ "$clam" == "yes" ]]; then
        MALWARE_SCANNER_STATUS="ðŸŸ¡ Partial"
        MALWARE_SCANNER_DETAIL="ClamAV installed but scheduled scan cron missing"
    else
        MALWARE_SCANNER_STATUS="ðŸ”´ Missing"
        MALWARE_SCANNER_DETAIL="No malware scanner detected"
    fi

    local tools=()
    { command -v chkrootkit >/dev/null 2>&1 || [ -x /usr/local/sbin/chkrootkit ]; } && tools+=("chkrootkit")
    command -v rkhunter >/dev/null 2>&1 && tools+=("rkhunter")

    if [[ ${#tools[@]} -gt 0 ]]; then
        ROOTKIT_SCANNER_STATUS="ðŸŸ¢ Good"
        ROOTKIT_SCANNER_DETAIL="Installed: ${tools[*]}"
    else
        ROOTKIT_SCANNER_STATUS="ðŸ”´ Missing"
        ROOTKIT_SCANNER_DETAIL="No rootkit scanner detected"
    fi

    export MALWARE_SCANNER_STATUS MALWARE_SCANNER_DETAIL ROOTKIT_SCANNER_STATUS ROOTKIT_SCANNER_DETAIL
}

#-------------------------------------------------------------------------------
# NEW v4: Malware / rootkit scan RESULTS (Proactive Defence)
#-------------------------------------------------------------------------------

check_malware_scan_results() {
    MALWARE_RESULT_STATUS="ðŸ”µ Unknown"
    MALWARE_RESULT_DETAIL="No scan report yet - run /root/scripts/bobcares-malware-scan.sh"

    local report="/root/scripts/malware-details-report.txt"
    local old_report="/root/scripts/malware-scan-report.txt"

    if [ -f "$report" ]; then
        local rdate
        rdate=$(date -r "$report" '+%Y-%m-%d %H:%M' 2>/dev/null)

        # Count actual malware entries (the new individual report uses "File: /path" lines)
        local malware_count
        malware_count=$(grep -c '^File: ' "$report" 2>/dev/null || echo 0)

        if [[ $malware_count -eq 0 ]]; then
            MALWARE_RESULT_STATUS="ðŸŸ¢ Clean"
            MALWARE_RESULT_DETAIL="No malware found (last scan: ${rdate:-unknown})"
        else
            MALWARE_RESULT_STATUS="ðŸ”´ Infected"
            MALWARE_RESULT_DETAIL="$malware_count suspicious file(s) found (last scan: ${rdate:-unknown})"
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
        if [[ $cnt -eq 0 ]]; then
            MALWARE_RESULT_STATUS="ðŸŸ¢ Clean"
            MALWARE_RESULT_DETAIL="No malware found (last scan: ${rdate:-unknown})"
        else
            MALWARE_RESULT_STATUS="ðŸ”´ Infected"
            MALWARE_RESULT_DETAIL="$cnt suspicious file(s) in $files (last scan: ${rdate:-unknown})"
        fi
    fi

    # Also parse the separate Outdated CMS report (produced by the same malware scan script)
    OUTDATED_CMS_STATUS="ðŸ”µ Unknown"
    OUTDATED_CMS_DETAIL="No CMS version report available"

    local cms_report="/root/scripts/outdated-cms-report.txt"
    if [ -f "$cms_report" ]; then
        local cdate
        cdate=$(date -r "$cms_report" '+%Y-%m-%d %H:%M' 2>/dev/null)

        # Count lines that indicate outdated packages (PHPMailer, WordPress, Joomla, etc.)
        local outdated_count
        outdated_count=$(grep -cE '^(PHPMailer|WordPress|Joomla|Drupal|Magento|PrestaShop|OpenCart|Shopify|WooCommerce)' "$cms_report" 2>/dev/null || echo 0)

        if [[ $outdated_count -eq 0 ]]; then
            OUTDATED_CMS_STATUS="ðŸŸ¢ Good"
            OUTDATED_CMS_DETAIL="No outdated CMS or PHPMailer packages detected (last check: ${cdate:-unknown})"
        else
            OUTDATED_CMS_STATUS="ðŸŸ¡ Outdated"
            OUTDATED_CMS_DETAIL="$outdated_count outdated package(s) found (last check: ${cdate:-unknown})"
        fi
    fi

    export MALWARE_RESULT_STATUS MALWARE_RESULT_DETAIL OUTDATED_CMS_STATUS OUTDATED_CMS_DETAIL
}

check_rootkit_scan_results() {
    ROOTKIT_RESULT_STATUS="ðŸ”µ Unknown"
    ROOTKIT_RESULT_DETAIL="No rootkit scan report found"

    local chkreport="/root/scripts/chkrootkit-report.txt"

    if [ -f "$chkreport" ]; then
        local rdate
        rdate=$(date -r "$chkreport" '+%Y-%m-%d %H:%M' 2>/dev/null)

        # The new individual chkrootkit-report.txt contains the raw output.
        # We look for lines that start with "/" after the "Searching for suspicious files" section.
        # Note: Some paths (build-id, debug, firmware) are often false positives.
        local suspicious
        suspicious=$(awk '/Searching for suspicious files and dirs/,0' "$chkreport" 2>/dev/null | grep -E '^/' | wc -l)

        if [[ $suspicious -eq 0 ]]; then
            ROOTKIT_RESULT_STATUS="ðŸŸ¢ Clean"
            ROOTKIT_RESULT_DETAIL="No suspicious files reported by chkrootkit (last scan: ${rdate:-unknown})"
        else
            ROOTKIT_RESULT_STATUS="ðŸŸ¡ Review"
            ROOTKIT_RESULT_DETAIL="$suspicious suspicious item(s) flagged by chkrootkit (last scan: ${rdate:-unknown}) - review manually (many are false positives)"
        fi
    else
        # Fallback to old rkhunter logic
        local log
        for log in /var/log/rkhunter/rkhunter.log /var/log/rkhunter.log; do
            [ -f "$log" ] || continue
            local w rdate
            w=$(grep -c 'Warning:' "$log" 2>/dev/null)
            [[ ! "$w" =~ ^[0-9]+$ ]] && w=0
            rdate=$(date -r "$log" '+%Y-%m-%d' 2>/dev/null)
            if [[ $w -eq 0 ]]; then
                ROOTKIT_RESULT_STATUS="ðŸŸ¢ Clean"
                ROOTKIT_RESULT_DETAIL="No warnings in rkhunter log (${rdate:-unknown})"
            else
                ROOTKIT_RESULT_STATUS="ðŸŸ¡ Review"
                ROOTKIT_RESULT_DETAIL="$w warning(s) in $log (${rdate:-unknown}) - review manually"
            fi
            break
        done
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
    KERNEL_STATUS="ðŸŸ¢ Good"
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
        KERNEL_STATUS="ðŸ”µ Host-managed"
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
            KERNEL_STATUS="ðŸŸ¡ Custom/Network"
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
                KERNEL_STATUS="ðŸŸ¢ Covered by KernelCare"
                KERNEL_ANALYSIS="Update available but covered by KernelCare live-patching."
            else
                KERNEL_STATUS="ðŸŸ¡ Update Available"
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
            nr_out=$(needs-restarting -r 2>/dev/null)
            if [[ $? -ne 0 ]]; then
                REBOOT_REQUIRED="Yes"
                REBOOT_REASON="Core components updated since boot"
                if grep -E '^\s*\*' <<<"$nr_out" | grep -qiv 'kernel'; then
                    nonkernel_pending="yes"
                fi
                grep -E '^\s*\*' <<<"$nr_out" | grep -qi 'kernel' && kernel_pending="yes"
            fi
            SVC_RESTART_LIST=$(needs-restarting -s 2>/dev/null | grep -Ev '^\s*$' | sort -u | paste -sd ', ' - | head -c 400)
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
            SVC_RESTART_LIST=$(needrestart -b -r l 2>/dev/null | awk '/^NEEDRESTART-SVC:/{print $2}' | sed 's/\.service$//' | sort -u | paste -sd ', ' - | head -c 400)
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
        "Yes")                        REBOOT_STATUS="ðŸŸ¡ Reboot Required" ;;
        "No (kernel live-patched)")   REBOOT_STATUS="ðŸŸ¢ KernelCare Covered" ;;
        *)                            REBOOT_STATUS="ðŸŸ¢ Good" ;;
    esac
    export REBOOT_REQUIRED REBOOT_REASON REBOOT_STATUS SVC_RESTART_LIST SVC_RESTART_COUNT
}

check_package_updates() {
    echo "[DEBUG] Checking for package updates..."
    OS_UPDATE_COUNT=0; SEC_UPDATE_COUNT=0
    PHP_UPDATE_COUNT=0; HTTPD_UPDATE_COUNT=0; MYSQL_UPDATE_COUNT=0
    OTHER_UPDATE_COUNT=0; OTHER_UPDATE_PKGS=""

    if [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
        mapfile -t _pkg_updates < <($PKG_MGR check-update --quiet 2>/dev/null | grep -E '^\S+\.\S+\s+\S+\s+\S+' || true)
        OS_UPDATE_COUNT=${#_pkg_updates[@]}

        if [[ $OS_UPDATE_COUNT -gt 0 ]]; then
            PHP_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(ea-php|alt-php|php)' || true)
            HTTPD_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(httpd|ea-apache24)' || true)
            MYSQL_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(MariaDB-|mysql-|mariadb-)' || true)
            OTHER_UPDATE_PKGS=$(printf '%s\n' "${_pkg_updates[@]}" \
                | grep -Ev '^(ea-php|alt-php|php|httpd|ea-apache24|MariaDB-|mysql-|mariadb-)' \
                | awk -F. '{print $1}' | sort -u | paste -sd ', ' - | head -c 300)
        fi

        if [[ "$PKG_MGR" == "dnf" ]]; then
            SEC_UPDATE_COUNT=$(dnf updateinfo list security --quiet 2>/dev/null | grep -cE '^\S+\s+\S+\s+\S+' || echo 0)
        else
            SEC_UPDATE_COUNT=$(yum --security check-update --quiet 2>/dev/null | grep -cE '^\S+\.\S+\s+\S+\s+\S+' || echo 0)
        fi

    elif [[ "$PKG_MGR" == "apt" ]]; then
        apt-get update -qq >/dev/null 2>&1
        mapfile -t _pkg_updates < <(apt list --upgradable 2>/dev/null | grep -E '^\S+/')
        OS_UPDATE_COUNT=${#_pkg_updates[@]}

        if [[ $OS_UPDATE_COUNT -gt 0 ]]; then
            PHP_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^php' || true)
            HTTPD_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(apache2|httpd)' || true)
            MYSQL_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -Ec '^(mariadb-server|mysql-server)' || true)
            SEC_UPDATE_COUNT=$(printf '%s\n' "${_pkg_updates[@]}" | grep -ci 'security' || true)
            OTHER_UPDATE_PKGS=$(printf '%s\n' "${_pkg_updates[@]}" \
                | grep -Ev '^(php|apache2|httpd|mariadb-server|mysql-server)' \
                | awk -F/ '{print $1}' | sort -u | paste -sd ', ' - | head -c 300)
        fi
    fi

    OTHER_UPDATE_COUNT=$(( OS_UPDATE_COUNT - PHP_UPDATE_COUNT - HTTPD_UPDATE_COUNT - MYSQL_UPDATE_COUNT ))
    (( OTHER_UPDATE_COUNT < 0 )) && OTHER_UPDATE_COUNT=0

    export OS_UPDATE_COUNT SEC_UPDATE_COUNT PHP_UPDATE_COUNT HTTPD_UPDATE_COUNT MYSQL_UPDATE_COUNT OTHER_UPDATE_COUNT OTHER_UPDATE_PKGS
}

#-------------------------------------------------------------------------------
# checks
#-------------------------------------------------------------------------------


check_system_version() {
    SYSTEM_UPDATE_STATUS="ðŸ”µ Unknown"
    SYSTEM_LATEST="Unknown"
    SYSTEM_SOURCE="Package Manager"

    local updates=0

    case "$PKG_MGR" in
        dnf)
            updates=$(dnf check-update -q 2>/dev/null | awk 'NF>=3' | wc -l)
            ;;
        yum)
            updates=$(yum check-update -q 2>/dev/null | awk 'NF>=3' | wc -l)
            ;;
        apt)
            apt-get update -qq >/dev/null 2>&1
            updates=$(apt list --upgradable 2>/dev/null | grep -vc "^Listing")
            ;;
        *)
            SYSTEM_UPDATE_STATUS="ðŸ”µ Unknown"
            export SYSTEM_UPDATE_STATUS SYSTEM_LATEST SYSTEM_SOURCE
            return
            ;;
    esac

    if [[ "$updates" =~ ^[0-9]+$ ]]; then
        SYSTEM_LATEST="$updates package update(s)"
        if [[ "$updates" -eq 0 ]]; then
            SYSTEM_UPDATE_STATUS="ðŸŸ¢ Up to Date"
        else
            SYSTEM_UPDATE_STATUS="ðŸŸ¡ Update Available"
        fi
    else
        SYSTEM_UPDATE_STATUS="ðŸ”µ Unknown"
    fi

    export SYSTEM_UPDATE_STATUS SYSTEM_LATEST SYSTEM_SOURCE
}

check_modsecurity() {
    MODSEC_STATUS="ðŸŸ¡ Warning"
    MODSEC_REASON="ModSecurity not detected"

    local apache_conf=""
    local nginx_conf=""
    local module_loaded="no"

    # Detect Apache
    if command -v httpd >/dev/null 2>&1; then
        apache_conf=$(httpd -V 2>/dev/null | awk -F'"' '/SERVER_CONFIG_FILE/{print $2}')
        httpd -M 2>/dev/null | grep -qi security2_module && module_loaded="yes"
    elif command -v apache2 >/dev/null 2>&1; then
        apache_conf=$(apache2 -V 2>/dev/null | awk -F'"' '/SERVER_CONFIG_FILE/{print $2}')
        apache2ctl -M 2>/dev/null | grep -qi security2_module && module_loaded="yes"
    fi

    # Detect Nginx + ModSecurity
    if command -v nginx >/dev/null 2>&1; then
        nginx_conf=$(nginx -T 2>/dev/null)

        if echo "$nginx_conf" | grep -qiE 'modsecurity[[:space:]]+on'; then
            MODSEC_STATUS="ðŸŸ¢ Good"
            MODSEC_REASON="ModSecurity enabled for Nginx"
            export MODSEC_STATUS MODSEC_REASON
            return
        fi
    fi

    # Apache checks
    if [[ "$module_loaded" == "yes" ]]; then

        if grep -Riq "SecRuleEngine[[:space:]]\+On" \
            /etc/httpd /etc/apache2 /usr/local/apache/conf 2>/dev/null; then

            MODSEC_STATUS="ðŸŸ¢ Good"
            MODSEC_REASON="ModSecurity enabled"

        elif grep -Riq "SecRuleEngine[[:space:]]\+DetectionOnly" \
            /etc/httpd /etc/apache2 /usr/local/apache/conf 2>/dev/null; then

            MODSEC_STATUS="ðŸŸ¡ Warning"
            MODSEC_REASON="ModSecurity in DetectionOnly mode"

        else

            MODSEC_STATUS="ðŸŸ¡ Warning"
            MODSEC_REASON="ModSecurity module loaded but rule engine disabled"

        fi
    fi

    export MODSEC_STATUS MODSEC_REASON
}

check_services() {
    SERVICES_DOWN=""
    SERVICES_STATUS="ðŸ”µ N/A"

    command -v systemctl >/dev/null 2>&1 || {
        SERVICES_DOWN="systemctl not available"
        export SERVICES_DOWN SERVICES_STATUS
        return
    }

    SERVICES_DOWN=$(
        systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null |
        awk '{print $1}' |
        while read -r svc; do
            systemctl is-active --quiet "$svc" || echo "${svc%.service}"
        done |
        paste -sd ", " -
    )

    if [[ -z "$SERVICES_DOWN" ]]; then
        SERVICES_STATUS="ðŸŸ¢ Good"
        SERVICES_DOWN="All enabled services running"
    else
        SERVICES_STATUS="ðŸ”´ Services Down"
    fi

    export SERVICES_DOWN SERVICES_STATUS
}

check_ssl_expiry() {
    SSL_STATUS="ðŸ”µ N/A"
    SSL_EXPIRY="No SSL certificates found"

    command -v openssl >/dev/null 2>&1 || {
        export SSL_STATUS SSL_EXPIRY
        return
    }

    local cert
    local earliest_days=""
    local earliest_date=""

    while IFS= read -r cert; do
        local enddate end_epoch now_epoch days

        enddate=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
        [[ -z "$enddate" ]] && continue

        end_epoch=$(date -d "$enddate" +%s 2>/dev/null)
        now_epoch=$(date +%s)
        days=$(( (end_epoch - now_epoch) / 86400 ))

        if [[ -z "$earliest_days" || "$days" -lt "$earliest_days" ]]; then
            earliest_days=$days
            earliest_date="$enddate"
        fi
    done < <(
        find /etc/ssl /etc/pki /etc/letsencrypt \
            -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null
    )

    if [[ -n "$earliest_days" ]]; then
        SSL_EXPIRY="$earliest_date"

        if (( earliest_days < 0 )); then
            SSL_STATUS="ðŸ”´ Expired"
        elif (( earliest_days <= 30 )); then
            SSL_STATUS="ðŸŸ¡ Expiring Soon"
        else
            SSL_STATUS="ðŸŸ¢ Good"
        fi
    fi

    export SSL_STATUS SSL_EXPIRY
}

check_backups() {
    BACKUP_STATUS="ðŸ”µ N/A"
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
        ts=$(find "$dir" -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -1)

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
            BACKUP_STATUS="ðŸŸ¢ Good"
        elif (( age <= 7 )); then
            BACKUP_STATUS="ðŸŸ¡ Old"
        else
            BACKUP_STATUS="ðŸ”´ Stale"
        fi

        BACKUP_DETAILS="Latest backup ${age} day(s) old (${found}) | Backup Cron: ${cron_found}"
    else
        if [[ "$cron_found" == "Yes" ]]; then
            BACKUP_STATUS="ðŸŸ¡ Warning"
            BACKUP_DETAILS="Backup cron found, but no backup files detected"
        fi
    fi

    export BACKUP_STATUS BACKUP_DETAILS
}

#-------------------------------------------------------------------------------
# NEW v4: Extended backup checks (schedule, remote destinations, last backup)
#-------------------------------------------------------------------------------

check_backup_extended() {
    BACKUP_DAILY_STATUS="ðŸ”µ Unknown";    BACKUP_DAILY_DETAIL="No backup schedule found"
    BACKUP_WEEKLY_STATUS="ðŸ”µ Unknown";   BACKUP_WEEKLY_DETAIL="No backup schedule found"
    BACKUP_MONTHLY_STATUS="ðŸ”µ Unknown";  BACKUP_MONTHLY_DETAIL="No backup schedule found"
    BACKUP_REMOTE_STATUS="ðŸ”´ Not configured"; BACKUP_REMOTE_DETAIL="No remote backup configuration found"
    BACKUP_LAST_STATUS="ðŸ”µ Unknown"; BACKUP_LAST_DETAIL="No backup found on disk"
    BACKUP_SIZE_STATUS="ðŸ”µ Unknown"; BACKUP_SIZE_DETAIL="N/A"

    local backup_dirs=(
        /backup
        /backups
        /var/backups
        /home/backup
        /data/backup
        /mnt/backup
        /opt/backup
    )

    local latest=""
    local latest_time=0

    # Check backup schedules
    if grep -RiqE 'backup|rsync|borg|restic|duplicity|rdiff|tar' \
        /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null; then

        BACKUP_DAILY_STATUS="ðŸŸ¢ Configured"
        BACKUP_DAILY_DETAIL="Backup cron job detected"

        BACKUP_WEEKLY_STATUS="ðŸŸ¢ Configured"
        BACKUP_WEEKLY_DETAIL="Verify cron schedule"

        BACKUP_MONTHLY_STATUS="ðŸŸ¢ Configured"
        BACKUP_MONTHLY_DETAIL="Verify cron schedule"
    fi

    # Detect remote backup tools/configuration
    if command -v restic >/dev/null 2>&1; then
        BACKUP_REMOTE_STATUS="ðŸŸ¢ Configured"
        BACKUP_REMOTE_DETAIL="Restic detected"
    elif command -v borg >/dev/null 2>&1; then
        BACKUP_REMOTE_STATUS="ðŸŸ¢ Configured"
        BACKUP_REMOTE_DETAIL="Borg detected"
    elif command -v rclone >/dev/null 2>&1; then
        BACKUP_REMOTE_STATUS="ðŸŸ¢ Configured"
        BACKUP_REMOTE_DETAIL="rclone detected"
    elif command -v duplicity >/dev/null 2>&1; then
        BACKUP_REMOTE_STATUS="ðŸŸ¢ Configured"
        BACKUP_REMOTE_DETAIL="Duplicity detected"
    fi

    # Locate newest backup
    for dir in "${backup_dirs[@]}"; do
        [[ -d "$dir" ]] || continue

        while IFS= read -r file; do
            local mtime
            mtime=$(stat -c %Y "$file" 2>/dev/null) || continue

            if (( mtime > latest_time )); then
                latest_time=$mtime
                latest="$file"
            fi
        done < <(find "$dir" -type f 2>/dev/null)
    done

    if [[ -n "$latest" ]]; then
        local age_days size size_kb
        age_days=$(( ( $(date +%s) - latest_time ) / 86400 ))

        if [[ $age_days -le 2 ]]; then
            BACKUP_LAST_STATUS="ðŸŸ¢ Recent"
        elif [[ $age_days -le 8 ]]; then
            BACKUP_LAST_STATUS="ðŸŸ¡ Aging"
        else
            BACKUP_LAST_STATUS="ðŸ”´ Stale"
        fi

        BACKUP_LAST_DETAIL="$latest (${age_days} day(s) old)"

        size=$(du -sh "$latest" 2>/dev/null | awk '{print $1}')
        size_kb=$(du -sk "$latest" 2>/dev/null | awk '{print $1}')

        if [[ -n "$size_kb" && "$size_kb" -lt 1024 ]]; then
            BACKUP_SIZE_STATUS="ðŸŸ¡ Suspicious"
            BACKUP_SIZE_DETAIL="$size - unusually small, verify backup contents"
        else
            BACKUP_SIZE_STATUS="ðŸŸ¢ OK"
            BACKUP_SIZE_DETAIL="$size"
        fi
    fi

    export BACKUP_DAILY_STATUS BACKUP_DAILY_DETAIL \
           BACKUP_WEEKLY_STATUS BACKUP_WEEKLY_DETAIL \
           BACKUP_MONTHLY_STATUS BACKUP_MONTHLY_DETAIL \
           BACKUP_REMOTE_STATUS BACKUP_REMOTE_DETAIL \
           BACKUP_LAST_STATUS BACKUP_LAST_DETAIL \
           BACKUP_SIZE_STATUS BACKUP_SIZE_DETAIL
}

check_php_and_users() {
    PHP_VERSIONS="N/A"
    PHP_DEFAULT="N/A"
    ACCT_COUNT="N/A"
    ACCT_SUSPENDED="N/A"

    # Detect installed PHP versions
    local versions
    versions=$(find /usr/bin -maxdepth 1 -type f -regex '.*/php[0-9.]*' -printf '%f\n' 2>/dev/null | \
        sed 's/^php//' | grep -E '^[0-9]' | sort -Vu)

    if [[ -n "$versions" ]]; then
        PHP_VERSIONS=$(echo "$versions" | paste -sd ", " -)
    elif command -v php >/dev/null 2>&1; then
        PHP_VERSIONS=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
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

    # Count locked/suspended accounts
    ACCT_SUSPENDED=$(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd | while read -r u; do
        passwd -S "$u" 2>/dev/null | awk '$2=="L"{c++} END{print c+0}'
    done)

    export PHP_VERSIONS PHP_DEFAULT ACCT_COUNT ACCT_SUSPENDED
}

#-------------------------------------------------------------------------------
# NEW v4: PHP EOL / disable_functions checks (Software Life Time / Proactive)
#-------------------------------------------------------------------------------

check_php_eol() {
    PHP_EOL_STATUS="ðŸ”µ Unknown"
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
        PHP_EOL_STATUS="ðŸŸ¡ EOL versions present"
        PHP_EOL_DETAIL="No longer supported by vendor: $(printf '%s, ' "${found[@]}" | sed 's/, $//') (default: $PHP_DEFAULT)"
    else
        PHP_EOL_STATUS="ðŸŸ¢ Good"
        PHP_EOL_DETAIL="All installed PHP versions are vendor-supported"
    fi

    export PHP_EOL_STATUS PHP_EOL_DETAIL
}

check_php_functions_security() {
    PHP_FUNC_STATUS="ðŸ”µ Unknown"
    PHP_FUNC_DETAIL="No php.ini files found"

    local inis=() ini
    for ini in \
        /etc/php.ini \
        /etc/php/*/cli/php.ini \
        /etc/php/*/fpm/php.ini \
        /etc/php/*/apache2/php.ini \
        /etc/php/*/cgi/php.ini; do
        [ -f "$ini" ] && inis+=("$ini")
    done

    [[ ${#inis[@]} -eq 0 ]] && {
        export PHP_FUNC_STATUS PHP_FUNC_DETAIL
        return
    }

    local secured=0 insecure=()

    for ini in "${inis[@]}"; do
        local df
        df=$(awk -F= '/^[[:space:]]*disable_functions[[:space:]]*=/{print $2}' "$ini" 2>/dev/null | tail -1 | tr -d ' "')

        if [[ -n "$df" ]] && grep -qE '(^|,)(exec|shell_exec|system|passthru)(,|$)' <<<"$df"; then
            secured=$((secured + 1))
        else
            insecure+=("$ini")
        fi
    done

    if [[ ${#insecure[@]} -eq 0 ]]; then
        PHP_FUNC_STATUS="ðŸŸ¢ Good"
        PHP_FUNC_DETAIL="Dangerous functions disabled in all ${#inis[@]} php.ini file(s)"
    elif [[ $secured -gt 0 ]]; then
        PHP_FUNC_STATUS="ðŸŸ¡ Partial"
        PHP_FUNC_DETAIL="disable_functions missing exec/system in: ${insecure[*]}"
    else
        PHP_FUNC_STATUS="ðŸ”´ Not set"
        PHP_FUNC_DETAIL="Dangerous PHP functions (exec, shell_exec, system, passthru...) are not disabled"
    fi

    export PHP_FUNC_STATUS PHP_FUNC_DETAIL
}

#-------------------------------------------------------------------------------
# NEW v4: rDNS status + reboot procedure info (Proactive Defence)
#-------------------------------------------------------------------------------

check_rdns_status() {
    if [[ -n "$RDNS" && "$RDNS" != "None" ]]; then
        RDNS_STATUS="ðŸŸ¢ Good"; RDNS_DETAIL="PTR record: $RDNS"
    else
        RDNS_STATUS="ðŸŸ¡ Missing"; RDNS_DETAIL="No PTR record for $MAIN_IP - may affect email delivery"
    fi
    export RDNS_STATUS RDNS_DETAIL
}

check_reboot_procedure_info() {
    REBOOT_PROC_STATUS="ðŸ”µ Manual"
    if [[ "$VM_STATUS" == Physical* ]]; then
        REBOOT_PROC_DETAIL="Physical machine - confirm provider IPMI/KVM or rescue console access is documented"
    else
        REBOOT_PROC_DETAIL="$VM_STATUS - confirm hypervisor/provider console reboot access is documented"
    fi
    export REBOOT_PROC_STATUS REBOOT_PROC_DETAIL
}

check_resource_usage() {
    (( $(echo "$LOAD > 5" | bc 2>/dev/null || echo 0) )) && CPU_STATUS="ðŸŸ¡ High" || CPU_STATUS="ðŸŸ¢ Optimal"
    [[ $RAM_PCT -gt 80 ]] && RAM_STATUS="ðŸŸ¡ High" || RAM_STATUS="ðŸŸ¢ Good"
    [[ $DISK_PCT -gt 80 ]] && DISK_STATUS="ðŸ”´ Critical" || DISK_STATUS="ðŸŸ¢ Good"

    if [[ "$EMAIL_QUEUE" == "N/A" ]]; then
        EMAIL_STATUS="ðŸ”µ N/A"
    elif [[ $EMAIL_QUEUE -gt 100 ]]; then
        EMAIL_STATUS="ðŸŸ¡ High"
    else
        EMAIL_STATUS="ðŸŸ¢ Normal"
    fi

    [[ $RAM_PCT -lt 75 && $DISK_PCT -lt 80 ]] && OVERALL_HEALTH="ðŸŸ¢ Healthy" || OVERALL_HEALTH="ðŸŸ¡ Needs Attention"

    export CPU_STATUS RAM_STATUS DISK_STATUS EMAIL_STATUS OVERALL_HEALTH
}

#-------------------------------------------------------------------------------
# Reporting (v4 - organized by team audit categories)
#-------------------------------------------------------------------------------

generate_smart_summary() {
    local os_update_line other_line os_lifetime_line
    local stack_status stack_detail cp_lt_status cp_lt_detail
    [[ $OS_UPDATE_COUNT -gt 0 ]]     && os_update_line="ðŸŸ¡ Updates Available"   || os_update_line="ðŸŸ¢ Up to Date"
    [[ $SEC_UPDATE_COUNT -gt 0 ]]    && os_update_line="ðŸ”´ Security Updates Pending"
    [[ $OTHER_UPDATE_COUNT -gt 0 ]]  && other_line="ðŸŸ¡ Updates Available"       || other_line="ðŸŸ¢ Up to Date"

    [[ "$EOL_STATUS" == "Supported" ]] \
        && os_lifetime_line="ðŸŸ¢ Supported" \
        || os_lifetime_line="ðŸ”´ End of Life"

    if [[ "$EOL_STATUS" == "Supported" && "$PHP_EOL_STATUS" == ðŸŸ¢* ]]; then
        stack_status="ðŸŸ¢ Good"
        stack_detail="OS and PHP stack are vendor-supported"
    else
        stack_status="ðŸŸ¡ Review"
        stack_detail="OS: $EOL_STATUS - PHP: $PHP_EOL_DETAIL"
    fi

    cp_lt_status="ðŸ”µ N/A"
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
| System Firewall | $SYSTEM_FIREWALL_STATUS | $SYSTEM_FIREWALL_ANALYSIS |
| Malware Scanner | $MALWARE_SCANNER_STATUS | $MALWARE_SCANNER_DETAIL |
| Failed Login Detection | $BRUTE_STATUS | $BRUTE_REASON |
| Web App Firewall | $MODSEC_STATUS | $MODSEC_REASON |
| Rootkit Scanner | $ROOTKIT_SCANNER_STATUS | $ROOTKIT_SCANNER_DETAIL |

## 2. Software Updates

| Audit Item | Status | Analysis / Recommendation |
|---|---|---|
| System Packages | $SYSTEM_UPDATE_STATUS | $SYSTEM_LATEST |
| Operating System | $os_update_line | $OS_NAME $OS_VERSION -> $OS_UPDATE_COUNT pending package(s), $SEC_UPDATE_COUNT security |
| PHP | $([[ $PHP_UPDATE_COUNT -gt 0 ]] && echo "ðŸŸ¡ Updates Available" || echo "ðŸŸ¢ Up to Date") | $PHP_UPDATE_COUNT pending \| Installed: $PHP_VERSIONS \| Default: $PHP_DEFAULT |
| CMS | ðŸ”µ Manual | Not auto-detected - verify WordPress/Joomla/etc. versions per account |
| Web Server | $([[ $HTTPD_UPDATE_COUNT -gt 0 ]] && echo "ðŸŸ¡ Updates Available" || echo "ðŸŸ¢ Up to Date") | $HTTPD_UPDATE_COUNT pending web server update(s) |
| Database Server | $([[ $MYSQL_UPDATE_COUNT -gt 0 ]] && echo "ðŸŸ¡ Updates Available" || echo "ðŸŸ¢ Up to Date") | $MYSQL_UPDATE_COUNT pending DB update(s) |
| Other Softwares | $other_line | $OTHER_UPDATE_COUNT other pending package(s)${OTHER_UPDATE_PKGS:+: $OTHER_UPDATE_PKGS} |
| Kernel | $KERNEL_STATUS | Running: $KERNEL_RUNNING \| Update: $KERNEL_UPDATE_AVAILABLE \| KernelCare: $KC_STATUS |
| Reboot Required | $REBOOT_STATUS | $REBOOT_REASON |

## 3. Server Health

| Audit Item | Status | Details |
|---|---|---|
| Server Uptime | $UPTIME_STATUS | $UPTIME |
| HTTP Uptime | $HTTP_STATUS | $HTTP_UPTIME |
| CPU Usage | $CPU_STATUS | Load average: $LOAD |
| RAM Usage | $RAM_STATUS | Used: ${RAM_PCT}% |
| Disc Space Usage | $DISK_STATUS | Used: ${DISK_PCT}% |
| Email Queue | $EMAIL_STATUS | Queued messages: $EMAIL_QUEUE |
| IP Reputation | $IP_REPUTATION_STATUS | $IP_REPUTATION_DETAIL |

**Overall Server Health:** $OVERALL_HEALTH

## 4. Backup

| Audit Item | Status | Details |
|---|---|---|
| Local Backup | $BACKUP_STATUS | $BACKUP_DETAILS |
| Remote Backup | $BACKUP_REMOTE_STATUS | $BACKUP_REMOTE_DETAIL |
| Daily Backup | $BACKUP_DAILY_STATUS | $BACKUP_DAILY_DETAIL |
| Weekly Backup | $BACKUP_WEEKLY_STATUS | $BACKUP_WEEKLY_DETAIL |
| Monthly Backup | $BACKUP_MONTHLY_STATUS | $BACKUP_MONTHLY_DETAIL |
| Recent Last Backup | $BACKUP_LAST_STATUS | $BACKUP_LAST_DETAIL |
| Size Of Last Backup | $BACKUP_SIZE_STATUS | $BACKUP_SIZE_DETAIL |

## 5. Software Life Time

| Audit Item | Status | Details |
|---|---|---|
| Control Panel | $cp_lt_status | $cp_lt_detail |
| Operating System | $os_lifetime_line | $OS_NAME $OS_VERSION - $EOL_STATUS by vendor |
| CMS | ðŸ”µ Manual | Not auto-detected - verify CMS versions per account are vendor-supported |
| Software Stack | $stack_status | $stack_detail |

## 6. Proactive Defence

| Audit Item | Status | Details |
|---|---|---|
| /tmp Security | $TMP_SEC_STATUS | $TMP_SEC_DETAIL |
| Reboot Procedure | $REBOOT_PROC_STATUS | $REBOOT_PROC_DETAIL |
| IP RDNS | $RDNS_STATUS | $RDNS_DETAIL |
| Malware Scan | $MALWARE_RESULT_STATUS | $MALWARE_RESULT_DETAIL |
| Rootkit Check | $ROOTKIT_RESULT_STATUS | $ROOTKIT_RESULT_DETAIL |
| Outdated CMS Check | $OUTDATED_CMS_STATUS | $OUTDATED_CMS_DETAIL |
| SSH Root Access Security | $ROOT_LOGIN_STATUS | PermitRootLogin: $ROOT_LOGIN_RAW \| PasswordAuth: $SSH_PASSWORD_AUTH \| Port(s): $SSH_PORT |
| PHP Functions Security | $PHP_FUNC_STATUS | $PHP_FUNC_DETAIL |
| Root password health | $ROOT_PW_STATUS | Root password ~$DAYS_OLD days old (target: rotated within 90 days) |

---

### Additional System Checks

| Check | Status | Details |
|---|---|---|
| Services | $SERVICES_STATUS | $SERVICES_DOWN |
| SSL Certificates | $SSL_STATUS | $SSL_EXPIRY |
| User Accounts | ðŸ”µ Info | Total: $ACCT_COUNT | Locked: $ACCT_SUSPENDED |
| Malware Scan Setup | ðŸŸ¢ Setup Checked | $SECURITY_ACTIONS$([[ "$MALWARE_SCAN_STARTED" != "No" ]] && echo " Scan: $MALWARE_SCAN_STARTED") |

**Recommendation:** Review any ðŸŸ¡ yellow / ðŸ”´ red items above. Prioritise pending security updates, reboot if required, enable/verify backups, and investigate IP reputation if listed. Items marked ðŸ”µ Manual require a human check.
EOF
}

generate_detailed_log() {
    {
        echo "DETAILED TECHNICAL LOG"
        echo "======================"
        echo "Generated: $(date)"
        echo
        echo "=== System Information ==="
        echo "Hostname              : $HOSTNAME"
        echo "Main IP               : $MAIN_IP"
        echo "rDNS                  : $RDNS"
        echo "OS / Version          : $OS_NAME $OS_VERSION ($EOL_STATUS)"
        echo "Control Panel         : N/A"
        echo "System Type           : $VM_STATUS"
        echo "Kernel                : $KERNEL"
        echo "System Uptime         : $UPTIME"
        echo "Web Server Uptime     : $HTTP_UPTIME"
        echo
        echo "=== 1. Threat Protection ==="
        echo "System Firewall        : $SYSTEM_FIREWALL_STATUS - $SYSTEM_FIREWALL_ANALYSIS"
        echo "Malware Scanner        : $MALWARE_SCANNER_STATUS - $MALWARE_SCANNER_DETAIL"
        echo "Failed Login Detection : $BRUTE_STATUS - $BRUTE_REASON"
        echo "Web App Firewall       : $MODSEC_STATUS - $MODSEC_REASON"
        echo "Rootkit Scanner        : $ROOTKIT_SCANNER_STATUS - $ROOTKIT_SCANNER_DETAIL"
        echo "chkrootkit             : $(command -v chkrootkit 2>/dev/null || echo 'Not found')"
        echo "rkhunter               : $(command -v rkhunter 2>/dev/null || echo 'Not found')"
        echo "ClamAV                 : $(command -v clamscan >/dev/null 2>&1 && echo 'Present' || echo 'Not found')"
        echo "Bobcares scripts       : $(ls /root/scripts/bobcares-malware-scan.sh /root/scripts/run-weekly-malware-scan.sh 2>/dev/null | wc -l) of 2 present"
        echo "Cron job               : $([ -f /etc/cron.d/bc-malware-scan ] && echo 'Present' || echo 'Missing')"
        echo "Whitelist file         : $([ -f /root/scripts/malware-whitelist.txt ] && echo 'Present' || echo 'Missing')"
        echo "Setup actions          : $SECURITY_ACTIONS"
        echo "Scan triggered         : $MALWARE_SCAN_STARTED"
        echo
        echo "=== 2. Software Updates ==="
        echo "Package Manager        : ${PKG_MGR:-unknown}"
        echo "OS packages pending    : $OS_UPDATE_COUNT"
        echo "Security updates       : $SEC_UPDATE_COUNT"
        echo "PHP pending            : $PHP_UPDATE_COUNT"
        echo "httpd/apache pending   : $HTTPD_UPDATE_COUNT"
        echo "MySQL/MariaDB pending  : $MYSQL_UPDATE_COUNT"
        echo "Other pending          : $OTHER_UPDATE_COUNT ${OTHER_UPDATE_PKGS:+($OTHER_UPDATE_PKGS)}"
        echo "System Packages        : $SYSTEM_UPDATE_STATUS ($SYSTEM_LATEST)"
        echo "Running kernel         : $KERNEL_RUNNING"
        echo "Kernel environment     : $KERNEL_ENV"
        echo "Kernel update in repo  : $KERNEL_UPDATE_AVAILABLE"
        echo "Kernel analysis        : $KERNEL_ANALYSIS"
        echo "KernelCare             : $KC_STATUS"
        echo "KernelCare effective   : ${KC_EFFECTIVE:-N/A}"
        echo "Reboot required        : $REBOOT_REQUIRED ($REBOOT_REASON)"
        echo "Services to restart    : ${SVC_RESTART_COUNT:-0} - ${SVC_RESTART_LIST:-none}"
        echo
        echo "=== 3. Server Health ==="
        echo "Server Uptime    : $UPTIME_STATUS ($UPTIME)"
        echo "HTTP Uptime      : $HTTP_STATUS ($HTTP_UPTIME)"
        echo "CPU Usage        : $CPU_STATUS (Load: $LOAD)"
        echo "RAM Usage        : $RAM_STATUS (${RAM_PCT}%)"
        echo "Disk Usage       : $DISK_STATUS (${DISK_PCT}%)"
        echo "Email Queue      : $EMAIL_STATUS (Queued: $EMAIL_QUEUE)"
        echo "IP Reputation    : $IP_REPUTATION_STATUS - $IP_REPUTATION_DETAIL"
        echo
        echo "=== 4. Backup ==="
        echo "Local Backup        : $BACKUP_STATUS - $BACKUP_DETAIL"
        echo "Remote Backup       : $BACKUP_REMOTE_STATUS - $BACKUP_REMOTE_DETAIL"
        echo "Daily Backup        : $BACKUP_DAILY_STATUS - $BACKUP_DAILY_DETAIL"
        echo "Weekly Backup       : $BACKUP_WEEKLY_STATUS - $BACKUP_WEEKLY_DETAIL"
        echo "Monthly Backup      : $BACKUP_MONTHLY_STATUS - $BACKUP_MONTHLY_DETAIL"
        echo "Recent Last Backup  : $BACKUP_LAST_STATUS - $BACKUP_LAST_DETAIL"
        echo "Size Of Last Backup : $BACKUP_SIZE_STATUS - $BACKUP_SIZE_DETAIL"
        echo
        echo "=== 5. Software Life Time ==="
        echo "Operating System : $OS_NAME $OS_VERSION - $EOL_STATUS"
        echo "Software Updates : $SYSTEM_UPDATE_STATUS ($SYSTEM_LATEST)"
        echo "PHP EOL          : $PHP_EOL_STATUS - $PHP_EOL_DETAIL"
        echo "CMS              : Manual check required"
        echo
        echo "=== 6. Proactive Defence ==="
        echo "/tmp noexec      : $TMP_SEC ($TMP_SEC_STATUS)"
        echo "Reboot Procedure : $REBOOT_PROC_STATUS - $REBOOT_PROC_DETAIL"
        echo "IP RDNS          : $RDNS_STATUS - $RDNS_DETAIL"
        echo "Malware Scan     : $MALWARE_RESULT_STATUS - $MALWARE_RESULT_DETAIL"
        echo "Rootkit Check    : $ROOTKIT_RESULT_STATUS - $ROOTKIT_RESULT_DETAIL"
        echo "Outdated CMS     : $OUTDATED_CMS_STATUS - $OUTDATED_CMS_DETAIL"
        echo "SSH Root Login   : $ROOT_LOGIN_STATUS ($ROOT_LOGIN_RAW)"
        echo "SSH Password Auth: $SSH_PASSAUTH_STATUS ($SSH_PASSWORD_AUTH)"
        echo "SSH Port(s)      : $SSH_PORT"
        echo "PHP Functions    : $PHP_FUNC_STATUS - $PHP_FUNC_DETAIL"
        echo "Root Password    : $ROOT_PW_STATUS (~$DAYS_OLD days old)"
        echo
        echo "=== Additional System Checks ==="
        echo "PHP versions      : $PHP_VERSIONS"
        echo "PHP default       : $PHP_DEFAULT"
        echo "Accounts total    : $ACCT_COUNT (locked: $ACCT_SUSPENDED)"
        echo "Services down     : $SERVICES_DOWN"
        echo "SSL expiring <30d : $SSL_EXPIRING_COUNT - $SSL_EXPIRING_LIST"
    } | tee "$DETAILED_FILE"
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

    MALWARE_SCAN_STARTED="No"
    if [[ "$MALWARE_SCRIPT_FRESHLY_INSTALLED" == "yes" ]] || [ ! -f /root/scripts/malware-scan-report.txt ]; then
        if [ -x /root/scripts/bobcares-malware-scan.sh ] && command -v screen >/dev/null 2>&1; then
            echo
            echo "-> Starting Bobcares malware scan in background screen session..."
            screen -S bobcares-malware-scan -X quit >/dev/null 2>&1 || true
            screen -dmS bobcares-malware-scan /root/scripts/bobcares-malware-scan.sh
            MALWARE_SCAN_STARTED="Yes (screen: bobcares-malware-scan)"
            echo "OK Started. Attach with: screen -r bobcares-malware-scan"
            echo
        else
            MALWARE_SCAN_STARTED="No (script or screen missing)"
        fi
    fi
    export MALWARE_SCAN_STARTED

    generate_smart_summary
    generate_detailed_log

    echo
    echo "Audit Complete!"
    echo "Smart Summary : $SUMMARY_FILE"
    echo "Detailed Log  : $DETAILED_FILE"
    echo "Debug Log     : $DEBUG_LOG"
}

main "$@"
