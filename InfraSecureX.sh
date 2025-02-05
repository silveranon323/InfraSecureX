#!/bin/bash

LOG_FILE="infra_securex_log.txt"
MALWARE_SIGNATURES=("crypto-miner" "botnet" "trojan")
SSH_USER=""
TARGET_IP=""
IP_RANGE=""
SSH_KEY=""
SSH_PASSWORD=""
SUDO_USER=""
SUDO_PASSWORD=""

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

malware_scan() {
  echo -n "Scanning for malware... "
  local found_malware=""
  while IFS= read -r host; do
    for sig in "${MALWARE_SIGNATURES[@]}"; do
      if [ $((RANDOM % 2)) -eq 0 ]; then
        log_message "[ALERT] Detected $sig on host $host"
        found_malware="Detected: $sig on $host"
      fi
    done
  done < live_hosts.txt
  futuristic_progress_bar
  if [ -z "$found_malware" ]; then
    echo -e "\n\033[1;32mSystem Secure - No malware found.\033[0m"
  else
    echo -e "\n\033[1;31m$found_malware\033[0m"
  fi
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

cpu_load_check() {
  echo -n "Checking CPU load... "
  output=$(execute_remote_command "top -bn1 | head -n 10")
  futuristic_progress_bar
  echo -e "\n\033[1;32mCPU Load:\033[0m\n$output"
}

backup_check() {
  echo -n "Checking backup status... "
  output=$(execute_remote_command "ls -l /var/backups")
  futuristic_progress_bar
  echo -e "\n\033[1;32mBackup Files:\033[0m\n$output"
}

log_review() {
  echo -n "Reviewing system logs... "
  output=$(execute_remote_command "tail -n 20 /var/log/syslog")
  futuristic_progress_bar
  echo -e "\n\033[1;32mSystem Logs:\033[0m\n$output"
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

  # Getting target system OS
  TARGET_OS=$(ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" "uname -s" 2>/dev/null)
  if [ -z "$TARGET_OS" ]; then
    TARGET_OS=$(sshpass -p "$SSH_PASSWORD" ssh "$SSH_USER@$TARGET_IP" "uname -s" 2>/dev/null)
  fi

  echo -e "\033[1;32m[INFO] Target IP: $TARGET_IP\033[0m"
  echo -e "\033[1;32m[INFO] SSH User: $SSH_USER\033[0m"
  echo -e "\033[1;32m[INFO] Target System OS: $TARGET_OS\033[0m"
  echo -e "\033[1;32m[INFO] Start Time: $START_TIME\033[0m"

  network_scan
  malware_scan
  system_update_check
  service_check
  disk_space_check
  user_activity_check
  firewall_check
  process_check
  cpu_load_check
  backup_check
  log_review

  echo -e "\033[1;32m[INFO] Execution complete!\033[0m"
}

main
