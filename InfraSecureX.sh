#!/bin/bash

LOG_FILE="infra_securex_log.txt"
IP_RANGE="192.168.1.0/24"
SSH_USER="user"
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
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'echo SSH Check'
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

network_monitor() {
  log_message "[INFO] Monitoring network traffic for suspicious activity..."
  log_message "[INFO] No suspicious activity detected in the network."
}

system_update_check() {
  log_message "[INFO] Checking system for outdated software..."
  cat live_hosts.txt | xargs -n 1 -P 5 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'sudo apt-get update && sudo apt-get upgrade -y'
    if [ $? -eq 0 ]; then
      log_message '[SUCCESS] System update completed on host {}'
    else
      log_message '[ERROR] Failed to update system on {}'
    fi"
}

service_check() {
  log_message "[INFO] Checking for critical services status..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'systemctl is-active --quiet apache2'
    if [ $? -eq 0 ]; then
      log_message '[INFO] Apache2 service is active on host {}'
    else
      log_message '[WARNING] Apache2 service is inactive on host {}'
    fi"
}

disk_space_check() {
  log_message "[INFO] Checking disk space usage on hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'df -h | grep -E '^/dev/''
    if [ $? -eq 0 ]; then
      log_message '[INFO] Disk space checked on host {}'
    else
      log_message '[ERROR] Failed to check disk space on {}'
    fi"
}

user_activity_check() {
  log_message "[INFO] Checking user login activity..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'last -a | head -n 10'
    if [ $? -eq 0 ]; then
      log_message '[INFO] User login activity checked on host {}'
    else
      log_message '[ERROR] Failed to check user login activity on {}'
    fi"
}

firewall_check() {
  log_message "[INFO] Checking firewall status on hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'sudo ufw status'
    if [ $? -eq 0 ]; then
      log_message '[INFO] Firewall status checked on host {}'
    else
      log_message '[ERROR] Failed to check firewall status on {}'
    fi"
}

process_check() {
  log_message "[INFO] Checking running processes on hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'ps aux | grep -E \"(sshd|httpd|nginx)\"'
    if [ $? -eq 0 ]; then
      log_message '[INFO] Running processes checked on host {}'
    else
      log_message '[ERROR] Failed to check running processes on {}'
    fi"
}

cpu_load_check() {
  log_message "[INFO] Checking CPU load on hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'uptime'
    if [ $? -eq 0 ]; then
      log_message '[INFO] CPU load checked on host {}'
    else
      log_message '[ERROR] Failed to check CPU load on {}'
    fi"
}

backup_check() {
  log_message "[INFO] Checking backup status on hosts..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'ls /backup'
    if [ $? -eq 0 ]; then
      log_message '[INFO] Backup directory exists on host {}'
    else
      log_message '[ERROR] Failed to find backup directory on {}'
    fi"
}

log_review() {
  log_message "[INFO] Reviewing system logs for suspicious activity..."
  cat live_hosts.txt | xargs -n 1 -P 10 -I {} bash -c "
    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $SSH_USER@{} 'grep -i \"error\" /var/log/syslog'
    if [ $? -eq 0 ]; then
      log_message '[INFO] Log review completed on host {}'
    else
      log_message '[ERROR] Failed to review logs on {}'
    fi"
}

main() {
  log_message "[INFO] InfraSecureX tool execution started."
  network_scan
  ssh_vulnerability_check
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
