#!/bin/bash

# --- CONFIGURATION ---
WAZUH_MANAGER_IP="192.168.1.110"  # <- CHANGE to your Wazuh Manager IP
AGENT_NAME="loickenji"

# --- Root check ---
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

echo "[*] Installing Wazuh agent..."

# --- Add Wazuh repository and install agent ---
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install  wazuh-agent

# --- Configure agent ---
sed -i "s|<address>.*</address>|<address>192.168.1.110</address>|" /var/ossec/etc/ossec.conf
sed -i "s|<name>.*</name>|<name>loickenji</name>|" /var/ossec/etc/ossec.conf

# --- Optional: auto-register with agent-auth ---
/var/ossec/bin/agent-auth -m $WAZUH_MANAGER_IP -A $AGENT_NAME

# --- Start agent ---
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "[✔] Wazuh agent installed and connected to 192.168.1.110"
