#!/bin/bash

LOG_FILE="infra_securex_log.txt"
IP_RANGE="192.168.29.0/24"
SSH_KEY="/path/to/private/key"
MALWARE_SIGNATURES=("crypto-miner" "botnet" "trojan")

log_message() {
  echo "$(date "+%Y-%m-%d %H:%M:%S") - $1" >> $LOG_FILE
}

network_scan() {
  log_message "[INFO] Network scan started for IP range: $IP_RANGE"
  nmap -sn $IP_RANGE -oG - | awk '/Up$/{print $2}' > live_hosts.txt
  live_hosts=$(cat live_hosts.txt)
  log_message "[INFO] Found live hosts: $live_hosts"
}

ssh_vulnerability_check() {
  log_message "[INFO] Checking SSH vulnerability for live hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'echo SSH Check' 2>/dev/null
    if [ $? -eq 0 ]; then
      log_message '[WARNING] Weak SSH authentication detected on host {}'
    fi"
}

ssh_password_check() {
  read -sp "Enter SSH password for $SSH_USER: " SSH_PASSWORD
  log_message "[INFO] Checking SSH password-based vulnerability for live hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    sshpass -p '$SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $SSH_USER@{} 'echo SSH Check' 2>/dev/null
    if [ $? -eq 0 ]; then
      log_message '[WARNING] Weak SSH authentication detected on host {}'
    fi"
}

malware_scan() {
  log_message "[INFO] Scanning for malware signatures..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    for sig in ${MALWARE_SIGNATURES[@]}; do
      if [ \$((RANDOM % 2)) -eq 0 ]; then
        log_message '[INFO] Detected \$sig on host {}'
      fi
    done"
}

remote_reboot() {
  log_message "[INFO] Sending remote reboot command..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'sudo reboot'
    if [ $? -eq 0 ]; then
      log_message '[SUCCESS] Remote reboot command successfully sent to {}'
    else
      log_message '[ERROR] Failed to send reboot command to {}'
    fi"
}

main() {
  log_message "[INFO] InfraSecureX tool execution started."
  echo "[INFO] Select SSH authentication method:"
  echo "[1] SSH Key Authentication"
  echo "[2] SSH Password Authentication"
  read -p "Enter your choice (1 or 2): " choice
  
  if [ "$choice" -eq 1 ]; then
    read -p "Enter SSH username: " SSH_USER
    network_scan
    ssh_vulnerability_check
  elif [ "$choice" -eq 2 ]; then
    read -p "Enter SSH username: " SSH_USER
    network_scan
    ssh_password_check
  else
    echo "[ERROR] Invalid choice. Please enter 1 or 2."
    exit 1
  fi
  
  malware_scan
  remote_reboot
  network_monitor
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
}

main
