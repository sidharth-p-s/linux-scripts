#!/bin/bash

MAX_PARALLEL=20
FAILED_LOG="/tmp/ssh_failed_$$.txt"
SUCCESS_LOG="/tmp/ssh_success_$$.txt"

SSH2_BIN="/usr/bin/ssh2"
SSH2_KEY1="/root/ISMS/keys/installations/id_rsa_3072"
SSH2_KEY2="/root/ISMS/keys/installations/id_rsa_unicorns"

> "$FAILED_LOG"
> "$SUCCESS_LOG"

IPS=()

if [[ "$1" == "-f" && -f "$2" ]]; then
    while IFS= read -r line; do
        [[ -n "$line" ]] && IPS+=("$line")
    done < "$2"

elif [ $# -gt 0 ]; then
    IPS=("$@")

else
    echo "Enter IP addresses one by one. Type 'done' when finished."
    while true; do
        read -p "Enter IP: " ip
        [[ "$ip" == "done" ]] && break
        [[ -n "$ip" ]] && IPS+=("$ip")
    done
fi

TOTAL=${#IPS[@]}
CURRENT=0

echo ""
echo "========================================"
echo "   SSH ACCESS CHECK — $TOTAL IPs"
echo "========================================"

START_TIME=$(date +%s)

# --- Worker function ---
check_ip() {
    local ip="$1"
    local index="$2"

    output=$("$SSH2_BIN" -n -T \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        "$ip" true 2>&1)

    # If ANY failure-related message appears → FAIL
    if echo "$output" | grep -qiE \
        "Permission denied|Authentication failed|publickey,password|Connection timed out|Connection refused|No route to host|Could not resolve hostname"; then
        echo "[$index/$TOTAL] [✘] $ip --> No Access"
        echo "$ip" >> "$FAILED_LOG"
    else
        echo "[$index/$TOTAL] [✔] $ip --> Access Successful"
        echo "$ip" >> "$SUCCESS_LOG"
    fi
}

export -f check_ip
export FAILED_LOG SUCCESS_LOG SSH2_BIN SSH2_KEY1 SSH2_KEY2 TOTAL

# --- Run in parallel ---
running=0
for ip in "${IPS[@]}"; do
    ((CURRENT++))
    check_ip "$ip" "$CURRENT" &
    ((running++))
    if (( running >= MAX_PARALLEL )); then
        wait -n 2>/dev/null || wait
        ((running--))
    fi
done

wait

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "========================================"
echo ""

FAILED_COUNT=0
SUCCESS_COUNT=0

# Count success
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] && ((SUCCESS_COUNT++))
done < "$SUCCESS_LOG"

# Count failure
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] && ((FAILED_COUNT++))
done < "$FAILED_LOG"

echo "✅ Accessible:     $SUCCESS_COUNT / $TOTAL"
echo "❌ Not accessible: $FAILED_COUNT / $TOTAL"
echo "⏱ Total Time:      ${ELAPSED} seconds"
echo ""

if [ "$FAILED_COUNT" -gt 0 ]; then
    echo "--- IPs with NO access ---"
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && echo "   - $ip"
    done < "$FAILED_LOG"
fi

rm -f "$FAILED_LOG" "$SUCCESS_LOG"
echo ""

