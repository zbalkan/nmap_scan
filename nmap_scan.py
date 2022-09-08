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
