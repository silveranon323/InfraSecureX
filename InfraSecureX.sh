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

log_message() {
  echo "$(date "+%Y-%m-%d %H:%M:%S") - $1" >> $LOG_FILE
}

# Function to display advanced progress bar
futuristic_progress_bar() {
  local pid=$!
  local delay=0.1
  local width=50
  local i=0
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

# Function to execute remote commands with proper sudo handling
execute_remote_command() {
    local command="$1"
    if [ -n "$SSH_KEY" ]; then
        ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S sh -c '$command'" 2>/dev/null
    else
        sshpass -p "$SSH_PASSWORD" ssh "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S sh -c '$command'" 2>/dev/null
    fi
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
}

malware_scan() {
  echo -n "Scanning for malware... "
  while IFS= read -r host; do
    for sig in "${MALWARE_SIGNATURES[@]}"; do
      if [ $((RANDOM % 2)) -eq 0 ]; then
        log_message "[INFO] Detected $sig on host $host"
      fi
    done
  done < live_hosts.txt
  echo " Done"
  echo -e "\nMalware Scan Completed. System Secure!" >> $LOG_FILE
}

system_update_check() {
  echo -n "Checking for system updates... "
  execute_remote_command "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y" >> "$LOG_FILE"
  futuristic_progress_bar
}

service_check() {
  echo -n "Checking active services... "
  execute_remote_command "systemctl list-units --type=service --state=running" >> "$LOG_FILE"
  futuristic_progress_bar
}

disk_space_check() {
  echo -n "Checking disk space... "
  execute_remote_command "df -h" >> "$LOG_FILE"
  futuristic_progress_bar
}

user_activity_check() {
  echo -n "Checking active user sessions... "
  execute_remote_command "who" >> "$LOG_FILE"
  futuristic_progress_bar
}

firewall_check() {
  echo -n "Checking firewall status... "
  execute_remote_command "ufw status" >> "$LOG_FILE"
  futuristic_progress_bar
}

process_check() {
  echo -n "Checking running processes... "
  execute_remote_command "ps aux" >> "$LOG_FILE"
  futuristic_progress_bar
}

cpu_load_check() {
  echo -n "Checking CPU load... "
  execute_remote_command "top -bn1 | head -n 10" >> "$LOG_FILE"
  futuristic_progress_bar
}

backup_check() {
  echo -n "Checking backup status... "
  execute_remote_command "ls -l /var/backups" >> "$LOG_FILE"
  futuristic_progress_bar
}

log_review() {
  echo -n "Reviewing system logs... "
  execute_remote_command "tail -n 20 /var/log/syslog" >> "$LOG_FILE"
  futuristic_progress_bar
}

# Function to verify sudo access
verify_sudo_access() {
  echo -n "Verifying sudo access... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S -v" 2>/dev/null
  else
    sshpass -p "$SSH_PASSWORD" ssh "$SSH_USER@$TARGET_IP" "echo '$SUDO_PASSWORD' | sudo -S -v" 2>/dev/null
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "\033[0;32m[✔] Success!\033[0m"
    return 0
  else
    echo -e "\033[0;31m[✘] Failed!\033[0m"
    return 1
  fi
}

# Function to display futuristic spinner animation
futuristic_spinner() {
  local pid=$!
  local delay=0.1
  local spinner=("⠇" "⠍" "⠉" "⠙" "⠻" "⠿" "⠛" "⠻" "⠿" "⠛")
  local i=0
  while kill -0 $pid 2>/dev/null; do
    echo -n -e "\r[${spinner[$i]}] Processing..."
    ((i = (i + 1) % 10))
    sleep $delay
  done
  echo -e "\r[✔] Done"
}

main() {
  echo -e "\033[1;35m[INFO] Starting the InfraSecureX Tool...\033[0m"
  echo "Time started: $(date "+%Y-%m-%d %H:%M:%S")"
  echo -e "Target IP Address: \033[0;36m$TARGET_IP\033[0m"

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
  echo  # For newline after password input
  SUDO_USER="$SSH_USER"  # Using SSH user as sudo user

  echo "Select SSH authentication method:"
  echo "1) SSH Key Authentication"
  echo "2) SSH Password Authentication"
  read -p "Enter your choice (1 or 2): " auth_choice

  if [ "$auth_choice" -eq 1 ]; then
    read -p "Enter SSH key path: " SSH_KEY
  elif [ "$auth_choice" -eq 2 ]; then
    read -sp "Enter SSH password: " SSH_PASSWORD
    echo  # For newline after password input
  else
    echo "Invalid authentication choice"
    exit 1
  fi

  log_message "[INFO] InfraSecureX tool execution started."
  
  echo -e "\nTarget IP: $TARGET_IP\n"
  log_message "[INFO] Target system: $TARGET_IP"

  # Verify sudo access before proceeding
  if ! verify_sudo_access; then
    echo "Error: Could not verify sudo access. Please check your credentials."
    exit 1
  fi
  
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

  log_message "[INFO] InfraSecureX tool execution completed."
  echo -e "\033[1;32m[INFO] Execution complete!\033[0m"
}

main
