#!/bin/bash
#
# Perform nmap-scan installation

if [ "$(id -u)" -ne 0 ]; then
      echo "This script can be executed only as root, Exiting.."
      exit 1
fi

# Custom error handler
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Install dependencies
if [ "$(dnf install pip nmap;pip install -r requirements.txt;)" != 0 ]; then
  err "Unable to install dependencies"
  exit 1
fi

# Move nmap_scan
SCANNER_PATH="/var/ossec/active-response/nmap"

if [ "$(mkdir -p $SCANNER_PATH)" != 0 ]; then
  err "Unable to create the folders. Check your privileges"
  exit 1
fi

# Write to the scanner python file
cat <<EOF > $SCANNER_PATH/nmap_scan.py
################################
# Python Script to Run Network Scans and append results to Wazuh Active Responses Log
# Requirements:
# NMAP installed in Agent
# python-nmap (https://pypi.org/project/python-nmap/)
# Do NOT include subnets with a network firewall in the path of the agent and the subnet.
################################
import json
import time

import nmap

with open("subnets.json", "r") as read_file:
    data = json.load(read_file)

scanner: nmap.PortScanner = nmap.PortScanner()
# Add subnets to scan to the Subnets Array
subnets: list[str] = data.get("subnets")
for subnet in subnets:
    json_output = {}
    # scanner.scan(subnet)
    for host in scanner.all_hosts():
        json_output['nmap_host'] = host
        for proto in scanner[host].all_protocols():
            if proto not in ["tcp", "udp"]:
                continue
            json_output['nmap_protocol'] = proto
            lport: list = list(scanner[host][proto].keys())
            lport.sort()
            for port in lport:
                hostname: str = ""
                json_output['nmap_port'] = port
                for h in scanner[host]["hostnames"]:
                    hostname: str = h["name"]
                    json_output['nmap_hostname'] = hostname
                    hostname_type: str = h["type"]
                    json_output['nmap_hostname_type'] = hostname_type
                    json_output['nmap_port_name'] = scanner[host][proto][port]["name"]
                    json_output['nmap_port_state'] = scanner[host][proto][port]["state"]
                    json_output['nmap_port_product'] = scanner[host][proto][port]["product"]
                    json_output['nmap_port_extrainfo'] = scanner[host][proto][port]["extrainfo"]
                    json_output['nmap_port_reason'] = scanner[host][proto][port]["reason"]
                    json_output['nmap_port_version'] = scanner[host][proto][port]["version"]
                    json_output['nmap_port_conf'] = scanner[host][proto][port]["conf"]
                    json_output['nmap_port_cpe'] = scanner[host][proto][port]["cpe"]
                    with open("/var/ossec/logs/active-responses.log", "a") as active_response_log:
                        active_response_log.write(json.dumps(json_output))
                        active_response_log.write("\n")
                time.sleep(2)


EOF

cat << EOF > $SCANNER_PATH/subnets.json
{
  "subnets": ["192.168.0.0/24", "10.0.0.0/24"]
}

EOF

# Create CRON job
JOB1="0 0 1 * * python $SCANNER_PATH/nmap_scan.py"
JOB2="0 0 15 * * python $SCANNER_PATH/nmap_scan.py"

case "$1" in
   install|update)

  CRON_FILE="/var/spool/cron/root"

  if [ ! -f $CRON_FILE ]; then
     echo "cron file for root does not exist, creating.."
     touch $CRON_FILE
     /usr/bin/crontab $CRON_FILE
  fi

  if [ "$(grep -qi 'nmap_scan_job' $CRON_FILE)" != 0 ]; then
     echo "Updating cron job for cleaning temporary files"
     crontab -u wazuh -l >/tmp/crontab
           /bin/echo "$JOB1" >> /tmp/crontab
           /bin/echo "$JOB2" >> /tmp/crontab
     crontab -u wazuh /tmp/crontab
  fi

  ;;

  *)

  echo "Usage: $0 {install|update}"
  exit 1
    ;;

esac

echo "Installation completed. Fill in the subnets to scan in CIDR format, e.g. 10.0.0.0/24"