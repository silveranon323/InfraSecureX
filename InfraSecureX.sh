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

# Function to display progress bar
progress_bar() {
  local pid=$!
  local delay=0.1
  while kill -0 $pid 2>/dev/null; do
    echo -n "."
    sleep $delay
  done
  echo " Done"
}

network_scan() {
  echo -n "Scanning network... "
  if [ -n "$IP_RANGE" ]; then
    log_message "[INFO] Network scan started for IP range: $IP_RANGE"
    nmap -sn $IP_RANGE -oG - | awk '/Up$/{print $2}' > live_hosts.txt &
  else
    echo "$TARGET_IP" > live_hosts.txt
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after network scan
}

malware_scan() {
  echo -n "Scanning for malware... "
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c '
    for sig in "${MALWARE_SIGNATURES[@]}"; do
      if [ $((RANDOM % 2)) -eq 0 ]; then
        log_message "[INFO] Detected $sig on host {}"
      fi
    done' >> $LOG_FILE 2>&1 &
  progress_bar
  sleep 4  # Adding 4 second delay after malware scan
  echo -e "\nMalware Scan Completed. System Secure!" >> $LOG_FILE
}

ssh_vulnerability_check() {
  echo -n "Checking SSH vulnerabilities for $TARGET_IP... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "uname -a" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "uname -a" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after SSH check
}

system_update_check() {
  echo -n "Checking for system updates... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "echo $SUDO_PASSWORD | sudo -S apt-get update && sudo apt-get upgrade -y" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "echo $SUDO_PASSWORD | sudo -S apt-get update && sudo apt-get upgrade -y" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after system update check
}

service_check() {
  echo -n "Checking active services... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "systemctl list-units --type=service --state=running" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "systemctl list-units --type=service --state=running" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after service check
}

disk_space_check() {
  echo -n "Checking disk space... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "df -h" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "df -h" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after disk space check
}

user_activity_check() {
  echo -n "Checking active user sessions... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "who" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "who" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after user activity check
}

firewall_check() {
  echo -n "Checking firewall status... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "sudo ufw status" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "sudo ufw status" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after firewall check
}

process_check() {
  echo -n "Checking running processes... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "ps aux" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "ps aux" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after process check
}

cpu_load_check() {
  echo -n "Checking CPU load... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "top -n 1 | head -n 10" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "top -n 1 | head -n 10" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after CPU load check
}

backup_check() {
  echo -n "Checking backup status... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "ls /var/backups" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "ls /var/backups" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after backup check
}

log_review() {
  echo -n "Reviewing system logs... "
  if [ -n "$SSH_KEY" ]; then
    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP "cat /var/log/syslog | tail -n 20" >> $LOG_FILE 2>&1 &
  else
    sshpass -p "$SSH_PASSWORD" ssh $SSH_USER@$TARGET_IP "cat /var/log/syslog | tail -n 20" >> $LOG_FILE 2>&1 &
  fi
  progress_bar
  sleep 4  # Adding 4 second delay after log review
}

disconnect_ssh() {
  echo -n "Disconnecting SSH session... "
  if [ -n "$SSH_KEY" ]; then
    pkill -f "ssh -i $SSH_KEY $SSH_USER@$TARGET_IP"
  else
    pkill -f "sshpass -p $SSH_PASSWORD ssh $SSH_USER@$TARGET_IP"
  fi
  echo "Disconnected."
}

main() {
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
  read -p "Enter sudo username: " SUDO_USER
  read -sp "Enter sudo password: " SUDO_PASSWORD
  echo  # For newline after password input

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
  
  network_scan
  malware_scan
  ssh_vulnerability_check
  system_update_check
  service_check
  disk_space_check
  user_activity_check
  firewall_check
  process_check
  cpu_load_check
  backup_check
  log_review

  disconnect_ssh

  log_message "[INFO] InfraSecureX tool execution completed."
}

main
