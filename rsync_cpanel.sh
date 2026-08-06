#!/bin/bash

# Set the source server IP
source_ip="$1"

SSH_USER="bobcares38137"
SSH_OPTS="-i /root/.ssh/id_rsa -o BatchMode=yes -o StrictHostKeyChecking=no"

# Function 1: Get local document root list
get_local_document_roots() {
    local user_name="$1"
    if [ -n "$user_name" ]; then
        cat /etc/apache2/conf/httpd.conf | grep DocumentRoot | grep "/home/$user_name/" | awk '{print $2}' | sort -n | uniq
    else
        cat /etc/apache2/conf/httpd.conf | grep DocumentRoot | grep home | awk '{print $2}' | sort -n | uniq 
    fi
}

# Function 2: Sync document roots
sync_document_roots() {
    local user_name="$1"
    local doc_roots=$(get_local_document_roots "$user_name")
    
    for root in $doc_roots; do
        if [ -d "$root" ]; then
            if ssh $SSH_OPTS ${SSH_USER}@"$source_ip" "[ -d \"$root\" ]" < /dev/null; then
                echo "Syncing document root: $root"
                rsync -avz     --rsync-path="sudo rsync"     -e "ssh $SSH_OPTS"     ${SSH_USER}@"$source_ip":"$root/"     "$root/"
            else
                echo "Document root $root doesn't exist on source. Skipping."
            fi
        else
            echo "Document root $root doesn't exist locally. Skipping."
        fi
    done
}

# Function 3: Get local email root list
get_local_email_roots() {
    local user_name="$1"
    if [ -n "$user_name" ]; then
        cat /home/$user_name/etc/*/passwd 2>/dev/null | cut -d ':' -f 6 | grep "/home/$user_name/" | sort -n | uniq
    else
        cat /home/*/etc/*/passwd | cut -d ':' -f 6 | sort -n | uniq 
    fi
}

# Function 4: Sync email roots
sync_email_roots() {
    local user_name="$1"
    local email_roots=$(get_local_email_roots "$user_name")
    
    for root in $email_roots; do
        if [ -d "$root" ]; then
            if ssh $SSH_OPTS ${SSH_USER}@"$source_ip" "[ -d \"$root\" ]" < /dev/null; then
                echo "Syncing email root: $root"
                rsync -avz     --rsync-path="sudo rsync"     -e "ssh $SSH_OPTS"     ${SSH_USER}@"$source_ip":"$root/"     "$root/"
            else
                echo "Email root $root doesn't exist on source. Skipping."
            fi
        else
            echo "Email root $root doesn't exist locally. Skipping."
        fi
    done
}

# Function 5: Get local database list
get_local_db_list() {
    local user_name="$1"
    if [ -n "$user_name" ]; then
        uapi --user="$user_name" Mysql list_databases 2>/dev/null | grep database: | awk '{print $2}' | grep "^${user_name}_"
    else
        mysql -N -e "SHOW DATABASES" | grep -vE "^(information_schema|performance_schema|mysql|sys)$"  
    fi
}

# Function 6: Sync databases
sync_databases() {
    local user_name="$1"
    local db_list=$(get_local_db_list "$user_name")
    
    for db in $db_list; do
        if mysql -e "USE $db" 2>/dev/null; then
            if ssh $SSH_OPTS ${SSH_USER}@"$source_ip" "sudo mysql --defaults-file=/root/.my.cnf -e 'USE $db' 2>/dev/null"; then
                echo "Syncing database: $db"
                ssh $SSH_OPTS ${SSH_USER}@"$source_ip" "sudo mysqldump --defaults-file=/root/.my.cnf $db" | mysql "$db"
            else
                echo "Database $db doesn't exist on source. Skipping."
            fi
        else
            echo "Database $db doesn't exist locally. Skipping."
        fi
    done
}

# Function 7: Migrate selected users
migrate_selected_users() {
    if [ ! -f "$PWD/user_list" ]; then
        echo "File $PWD/user_list not found."
        echo "Please create $PWD/user_list with a list of cPanel users to migrate (one per line) and run the script again."
        exit 1
    fi

    echo "Users to be migrated:"
    cat "$PWD/user_list"
    read -p "Confirm migration for these users? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Migration cancelled."
        exit 0
    fi

    # Use a file descriptor to read user_list, preserving stdin for read
    exec 3< "$PWD/user_list"
    while IFS= read -r user <&3; do
        if [ -n "$user" ]; then
            # Validate user exists locally
            if [ -d "/home/$user" ]; then
                echo "Starting migration for user: $user"
                sync_document_roots "$user"
                sync_email_roots "$user"
                sync_databases "$user"
                echo "Migration for user $user completed."
            else
                echo "User $user does not exist locally. Skipping."
            fi
        fi
    done
    exec 3<&- # Close the file descriptor
}

# Main execution
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <source_ip>"
    exit 1
fi

echo "Select migration option:"
echo "1) Migrate all users"
echo "2) Migrate selected users"
read -p "Enter choice (1 or 2): " choice

case $choice in
    1)
        echo "You chose to migrate all users."
        read -p "Confirm migration for all users? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            echo "Starting document root sync..."
            sync_document_roots
            echo "Starting email root sync..."
            sync_email_roots
            echo "Starting database sync..."
            sync_databases
            echo "Migration sync for all users completed."
        else
            echo "Migration cancelled."
            exit 0
        fi
        ;;
    2)
        echo "You chose to migrate selected users."
        migrate_selected_users
        echo "Migration sync for selected users completed."
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac
