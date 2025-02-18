#!/bin/bash

LOG_FILE="infra_securex_log.txt"
SSH_USER=""
TARGET_IP=""
IP_RANGE=""
SSH_KEY=""
SSH_PASSWORD=""
SUDO_USER=""
SUDO_PASSWORD=""

# Comprehensive real-world malware signatures
MALWARE_SIGNATURES=(
    # Cryptocurrency miners
    "xmrig"
    "ethminer"
    "t-rex"
    "nanominer"
    "phoenixminer"
    "teamredminer"
    "gminer"
    "nbminer"
    "lolminer"
    "ccminer"
    
    # Known malicious processes
    "kthreaddi"  # Linux rootkit
    "kworkerds"  # Crypto miner masquerading as kernel process
    "chapros"    # Common rootkit process
    "crond64"    # Fake cron process (real is crond)
    "watchbog"   # Common crypto miner
    "kdevtmpfsi" # Common crypto miner
    "ksoftirqds" # Fake kernel process
    "systemctI"  # Fake systemctl (capital I)
    "networkd"   # Fake networking process
    
    # Suspicious file patterns
    "/tmp/.*\\.sh"
    "/var/tmp/.*\\.sh"
    "/dev/shm/.*\\.sh"
    "/tmp/.*\\.py"
    "/var/tmp/.*\\.py"
    
    # Known malware directories
    "/tmp/systemd-private"
    "/var/tmp/systemd-private"
    "/tmp/.ICE-unix"
    "/tmp/.X11-unix"
    "/tmp/.font-unix"
    "/var/tmp/.systemd"
    "/dev/shm/.vs"
)

# Delete existing log file to create a new one on each execution
if [ -f "$LOG_FILE" ]; then
    rm "$LOG_FILE"
fi
touch "$LOG_FILE"

log_message() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") - $1" >> $LOG_FILE
}

# Function to display a progress bar
futuristic_progress_bar() {
    local pid=$!
    local delay=0.1
    local width=50
    local progress=0

    while kill -0 $pid 2>/dev/null; do
        let "progress=$progress+2"
        let "progress=$progress%100"
        local progress_bar=$(printf "%-${width}s" "#" | sed "s/ /#/g" | cut -c1-$((progress * width / 100)))
        local space=$(printf "%-$((width - ${#progress_bar}))s")
        echo -n -e "\r[${progress_bar}${space}] $progress% "
        sleep $delay
    done
    echo -e "\r[✔] Done"
}

# Function to execute remote commands and display output
execute_remote_command() {
    local command="$1"
    local output=""

    if [ -n "$SSH_KEY" ]; then
        output=$(ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S sh -c '$command'" 2>/dev/null)
    else
        output=$(sshpass -p "$SSH_PASSWORD" ssh "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S sh -c '$command'" 2>/dev/null)
    fi

    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

network_scan() {
    echo -n "Scanning network... "
    if [ -n "$IP_RANGE" ]; then
        log_message "[INFO] Network scan started for IP range: $IP_RANGE"
        nmap -sn "$IP_RANGE" -oG - | awk '/Up$/{print $2}' > live_hosts.txt &
    else
        echo "$TARGET_IP" > live_hosts.txt
    fi
    futuristic_progress_bar
    echo -e "\n\033[1;32mLive Hosts Found:\033[0m\n$(cat live_hosts.txt)"
}

# Enhanced malware scan function
malware_scan() {
    echo -n "Performing comprehensive malware scan... "
    local found_malware=()
    
    while IFS= read -r host; do
        log_message "[INFO] Starting malware scan on host $host"
        
        # Check for suspicious processes with full command line
        process_scan=$(execute_remote_command "ps auxww | grep -E '$(printf "%s|" "${MALWARE_SIGNATURES[@]}" | sed 's/|$//')' | grep -v grep")
        
        # Advanced file system scan including hidden directories
        file_scan=$(execute_remote_command "find /tmp /var/tmp /dev/shm /var/spool/cron /etc/cron.d /home -type f -name '.*' -o -name '*.sh' -o -name '*.py' 2>/dev/null")
        
        # Check for modified system binaries
        system_binary_scan=$(execute_remote_command "find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null")
        
        # Check for suspicious network connections and listening ports
        network_scan=$(execute_remote_command "netstat -tuln | grep -E ':(443[0-9]|14433|3333|4444|5555|6666|7777|8888|9999|13531|15593)'")
        
        # Check for suspicious cron jobs
        cron_scan=$(execute_remote_command "find /etc/cron* /var/spool/cron -type f -exec cat {} \; 2>/dev/null | grep -E '(wget|curl|bash|sh|\||\;)'")
        
        # Check for recently modified startup files
        startup_scan=$(execute_remote_command "find /etc/init.d /etc/systemd/system /usr/lib/systemd/system -type f -mtime -7 2>/dev/null")
        
        # Process results with better context
        if [ -n "$process_scan" ]; then
            found_malware+=("⚠️ Suspicious processes found on $host:")
            found_malware+=("$process_scan")
            log_message "[CRITICAL] Suspicious processes detected on host $host"
        fi
        
        if [ -n "$file_scan" ]; then
            found_malware+=("⚠️ Suspicious files found on $host:")
            found_malware+=("$file_scan")
            log_message "[WARNING] Suspicious files detected on host $host"
        fi
        
        if [ -n "$system_binary_scan" ]; then
            found_malware+=("⚠️ Recently modified system binaries on $host:")
            found_malware+=("$system_binary_scan")
            log_message "[CRITICAL] Modified system binaries detected on host $host"
        fi
        
        if [ -n "$network_scan" ]; then
            found_malware+=("⚠️ Suspicious network connections on $host:")
            found_malware+=("$network_scan")
            log_message "[WARNING] Suspicious network connections detected on host $host"
        fi
        
        if [ -n "$cron_scan" ]; then
            found_malware+=("⚠️ Suspicious cron jobs found on $host:")
            found_malware+=("$cron_scan")
            log_message "[CRITICAL] Suspicious cron jobs detected on host $host"
        fi
        
        if [ -n "$startup_scan" ]; then
            found_malware+=("⚠️ Recently modified startup files on $host:")
            found_malware+=("$startup_scan")
            log_message "[WARNING] Modified startup files detected on host $host"
        fi
        
    done < live_hosts.txt
    
    futuristic_progress_bar
    
    if [ ${#found_malware[@]} -eq 0 ]; then
        echo -e "\n\033[1;32m✅ System Secure - No suspicious indicators found.\033[0m"
        log_message "[INFO] Malware scan completed - No threats detected"
    else
        echo -e "\n\033[1;31m🚨 Potential Security Issues Found:\033[0m"
        printf '%s\n' "${found_malware[@]}"
        log_message "[ALERT] Malware scan completed - Potential threats detected"
        
        # Provide remediation suggestions
        echo -e "\n\033[1;33m📋 Recommended Actions:\033[0m"
        echo "1. Isolate affected systems from the network"
        echo "2. Kill suspicious processes and remove associated files"
        echo "3. Check and clean crontab entries"
        echo "4. Verify system binary integrity"
        echo "5. Review and secure startup services"
        echo "6. Change all system passwords"
        echo "7. Update and patch all systems"
    fi
    
    # Generate detailed summary
    echo -e "\n\033[1;36m📊 Scan Summary:\033[0m"
    echo "🔍 Processes checked: $(execute_remote_command "ps aux | wc -l")"
    echo "📁 Files scanned: $(execute_remote_command "find /tmp /var/tmp /home -type f | wc -l")"
    echo "🌐 Network connections analyzed: $(execute_remote_command "netstat -tuln | wc -l")"
    echo "⚙️ Startup services checked: $(execute_remote_command "systemctl list-unit-files | wc -l")"
    echo "🕒 Cron jobs analyzed: $(execute_remote_command "find /etc/cron* /var/spool/cron -type f | wc -l")"
}

system_update_check() {
    echo -n "Checking for system updates... "
    output=$(execute_remote_command "apt-get update && apt-get -s upgrade | grep '0 upgraded'")
    futuristic_progress_bar
    if [[ $output == *"0 upgraded"* ]]; then
        echo -e "\n\033[1;32mSystem is already updated.\033[0m"
    else
        echo -e "\n\033[1;33mUpdates available. Consider updating your system.\033[0m"
    fi
}

service_check() {
    echo -n "Checking active services... "
    output=$(execute_remote_command "systemctl list-units --type=service --state=running")
    futuristic_progress_bar
    echo -e "\n\033[1;32mActive Services:\033[0m\n$output"
}

disk_space_check() {
    echo -n "Checking disk space... "
    output=$(execute_remote_command "df -h")
    futuristic_progress_bar
    echo -e "\n\033[1;32mDisk Space:\033[0m\n$output"
}

user_activity_check() {
    echo -n "Checking active user sessions... "
    output=$(execute_remote_command "who")
    futuristic_progress_bar
    echo -e "\n\033[1;32mActive Users:\033[0m\n$output"
}

firewall_check() {
    echo -n "Checking firewall status... "
    output=$(execute_remote_command "ufw status")
    futuristic_progress_bar
    echo -e "\n\033[1;32mFirewall Status:\033[0m\n$output"
}

process_check() {
    echo -n "Checking running processes... "
    output=$(execute_remote_command "ps aux | head -10")
    futuristic_progress_bar
    echo -e "\n\033[1;32mTop Running Processes:\033[0m\n$output"
}

verify_sudo_access() {
    echo -n "Verifying sudo access... "
    if [ -n "$SSH_KEY" ]; then
        ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S -v" 2>/dev/null
    else
        sshpass -p "$SSH_PASSWORD" ssh "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S -v" 2>/dev/null
    fi

    if [ $? -eq 0 ]; then
        echo -e "\033[1;32m[✔] Success!\033[0m"
        return 0
    else
        echo -e "\033[1;31m[✘] Failed!\033[0m"
        return 1
    fi
}

main() {
    echo -e "\033[1;35m[INFO] Starting the InfraSecureX Tool...\033[0m"
    START_TIME=$(date "+%Y-%m-%d %H:%M:%S")
    echo "Time started: $START_TIME"

    echo "Select the target system option:"
    echo "1) Single System"
    echo "2) Multiple Systems (CIDR range)"
    read -p "Enter your choice (1 or 2): " choice

    if [ "$choice" -eq 1 ]; then
        read -p "Enter target IP: " TARGET_IP
    elif [ "$choice" -eq 2 ]; then
        read -p "Enter CIDR range (e.g., 192.168.64.0/24): " IP_RANGE
    else
        echo "Invalid choice"
        exit 1
    fi

    read -p "Enter SSH username: " SSH_USER
    read -sp "Enter sudo password: " SUDO_PASSWORD
    echo
    SUDO_USER="$SSH_USER"

    echo "Select SSH authentication method:"
    echo "1) SSH Key Authentication"
    echo "2) SSH Password Authentication"
    read -p "Enter your choice (1 or 2): " auth_choice

    if [ "$auth_choice" -eq 1 ]; then
        read -p "Enter SSH key path: " SSH_KEY
    elif [ "$auth_choice" -eq 2 ]; then
        read -sp "Enter SSH password: " SSH_PASSWORD
        echo
    else
        echo "Invalid authentication choice"
        exit 1
    fi

    if ! verify_sudo_access; then
        echo "Error: Could not verify sudo access."
        exit 1
    fi

    echo -e "\033[1;32m[INFO] Target IP: $TARGET_IP\033[0m"
    echo -e "\033[1;32m[INFO] SSH User: $SSH_USER\033[0m"
    echo -e "\033[1;32m[INFO] Start Time: $START_TIME\033[0m"

    network_scan
    malware_scan
    system_update_check
    service_check
    disk_space_check
    user_activity_check
    firewall_check
    process_check

    echo -e "\033[1;32m[INFO] Execution complete!\033[0m"
}

main
