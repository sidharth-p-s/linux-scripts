#!/bin/bash

LOG_DIR="/usr/local/cpanel/logs/cpbackup"
PARAM="backup_status"

WARNING_HOURS=192
CRITICAL_HOURS=240

# Find newest log
LATEST_LOG=$(ls -t $LOG_DIR/*.log 2>/dev/null | head -1)

if [ -z "$LATEST_LOG" ]; then
    echo "$PARAM CRITICAL - No backup log files found | $PARAM=0"
    exit 2
fi

# Check if latest log finished
STATE_LINE=$(grep "Final state is Backup::" "$LATEST_LOG" | tail -1)

if [ -z "$STATE_LINE" ]; then
    # Backup likely running – use last successful backup
    SUCCESS_LINE=$(grep -h "Final state is Backup::Success" $LOG_DIR/*.log | tail -1)

    if [ -z "$SUCCESS_LINE" ]; then
        echo "$PARAM CRITICAL - No successful backup found in logs | $PARAM=0"
        exit 2
    fi

else
    # Latest log completed
    if echo "$STATE_LINE" | grep -q "Backup::Success"; then
        SUCCESS_LINE="$STATE_LINE"
    elif echo "$STATE_LINE" | grep -q "Backup::Partial"; then
        echo "$PARAM CRITICAL - Backup completed partially | $PARAM=0"
        exit 2
    elif echo "$STATE_LINE" | grep -q "Backup::Failure"; then
        echo "$PARAM CRITICAL - Backup failed | $PARAM=0"
        exit 2
    else
        echo "$PARAM CRITICAL - Unknown backup state | $PARAM=0"
        exit 2
    fi
fi

# Extract timestamp
TIMESTAMP=$(echo "$SUCCESS_LINE" | awk -F'[][]' '{print $2}')

BACKUP_UNIX=$(date -d "$TIMESTAMP" +%s 2>/dev/null)
NOW_UNIX=$(date +%s)

if [ -z "$BACKUP_UNIX" ]; then
    echo "$PARAM CRITICAL - Unable to parse backup timestamp | $PARAM=0"
    exit 2
fi

BACKUP_AGE_HOURS=$(( (NOW_UNIX - BACKUP_UNIX) / 3600 ))

if [ "$BACKUP_AGE_HOURS" -ge "$CRITICAL_HOURS" ]; then
    echo "$PARAM CRITICAL - Backup is $BACKUP_AGE_HOURS hours old | backup_age_hours=$BACKUP_AGE_HOURS"
    exit 2
elif [ "$BACKUP_AGE_HOURS" -ge "$WARNING_HOURS" ]; then
    echo "$PARAM WARNING - Backup is $BACKUP_AGE_HOURS hours old | backup_age_hours=$BACKUP_AGE_HOURS"
    exit 1
else
    echo "$PARAM OK - Backup completed $BACKUP_AGE_HOURS hours ago | backup_age_hours=$BACKUP_AGE_HOURS"
    exit 0
fi

