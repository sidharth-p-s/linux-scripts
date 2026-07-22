#!/usr/bin/env bash

set -uo pipefail

AGE="+365"
LOG="wp_backup_scan_$(hostname)_$(date +%F_%H-%M-%S).log"

exec > >(tee -a "$LOG") 2>&1

echo "============================================================"
echo " WordPress Backup Scan"
echo " Host      : $(hostname)"
echo " Started   : $(date)"
echo " Age       : Older than 365 days"
echo "============================================================"
echo

echo "[INFO] Calculating total reclaimable space..."

TOTAL=$(find /home/*/public_html/ -type f -mtime "$AGE" \
\( \
-name "*.zip" -o \
-name "*.tar.gz" -o \
-name "*.tgz" -o \
-name "*.jpa" -o \
-name "*.wpress" \
\) \
-path "*wp-content*" \
-exec du -ch {} + | awk '/total$/ {print $1}')

echo "[INFO] Total reclaimable space: ${TOTAL:-0}"
echo

echo "[INFO] Top 20 largest backup files"
echo "------------------------------------------------------------"

find /home/*/public_html/ -type f -mtime "$AGE" \
\( \
-name "*.zip" -o \
-name "*.tar.gz" -o \
-name "*.tgz" -o \
-name "*.jpa" -o \
-name "*.wpress" \
\) \
-path "*wp-content*" \
-exec du -h {} + | sort -rh | head -20

echo
echo "[INFO] Generating detailed report..."
echo

find /home/*/public_html/ -type f -mtime "$AGE" \
\( \
-name "*.zip" -o \
-name "*.tar.gz" -o \
-name "*.tgz" -o \
-name "*.jpa" -o \
-name "*.wpress" \
\) \
-path "*wp-content*" \
-printf '%u|%h|%s|%TY-%Tm-%Td|%f\n' |
sort -t'|' -k1,1 -k2,2 |
awk -F'|' '

function human(x)
{
    s="B KMGTPE"
    while (x>=1024 && length(s)>1) {
        x/=1024
        s=substr(s,3)
    }
    return sprintf("%.1f%s",x,substr(s,1,1))
}

BEGIN{
    user=""
    dir=""
    dirsum=0
    users=0
    dirs=0
    files=0
    total=0
}

{
    if($1!=user){

        if(dir!=""){
            printf("Directory Total : %s\n\n",human(dirsum))
        }

        user=$1
        dir=""
        users++

        print "============================================================"
        print "User : "user
        print "============================================================"
    }

    if($2!=dir){

        if(dir!=""){
            printf("Directory Total : %s\n\n",human(dirsum))
        }

        dir=$2
        dirsum=0
        dirs++

        print "Directory : "dir
        print "------------------------------------------------------------"
        printf("%-9s %-12s %s\n","Size","Date","File")
    }

    dirsum+=$3
    total+=$3
    files++

    printf("%-9s %-12s %s\n",human($3),$4,$5)
}

END{

    if(dir!=""){
        printf("Directory Total : %s\n\n",human(dirsum))
    }

    print "============================================================"
    print "SUMMARY"
    print "============================================================"
    print "Users               :",users
    print "Backup Directories  :",dirs
    print "Backup Files        :",files
    print "Total Size          :",human(total)
}
'

echo
echo "[INFO] Scan completed successfully."
echo "[INFO] Log saved as: $LOG"
echo "[INFO] Finished at: $(date)"
