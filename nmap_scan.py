#!/usr/bin/env python3

################################
# Python Script to Run Network Scans and append results to Wazuh Active Responses Log
# Requirements:
# NMAP installed in Agent
# python-nmap (https://pypi.org/project/python-nmap/)
# Do NOT include subnets with a network firewall in the path of the agent and the subnet.
################################
import json
import logging
import os
import re
import sys
import traceback
from datetime import datetime
from grp import getgrnam  # type: ignore
from pwd import getpwnam  # type: ignore

import nmap

LOG_PATH: str = '/var/log'


def is_admin() -> bool:
    return (os.getuid() == 0)  # type: ignore


def detect_logpath() -> str:
    os.makedirs(LOG_PATH, exist_ok=True)
    return os.path.join(LOG_PATH, 'nmap_scan.log')


def touch_logfile(path: str) -> None:
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write('')


def ensure_log_permissions(path: str) -> None:
    if os.path.exists(path):
        # Set ownership to nmap:nmap (adjust UID and GID accordingly)
        nmap_uid = getpwnam('nmap')[2]
        nmap_gid = getgrnam('nmap')[2]
        os.chown(path, nmap_uid, nmap_gid)   # type: ignore
        # Set file permissions to 640
        os.chmod(path, 0o600)


def log_info(text: object, source_label: str, destination_label: str, target: str = '', verbose: bool = False) -> None:
    log(text, 'info', source_label, destination_label, target, verbose)


def log_error(text: object, source_label: str, destination_label: str, target: str = '', verbose: bool = False) -> None:
    log(text, 'error', source_label, destination_label, target, verbose)


def log(text: object, level: str, source_label: str, destination_label: str, target: str = '', verbose: bool = False) -> None:

    # sanitize field name
    sanitized = sanitize_log(text, 'target')

    logRecord: dict = dict()
    logRecord['nmap'] = dict()
    logRecord['nmap']["timestamp"] = str(datetime.now())
    logRecord['nmap']["type"] = "nmap_scan"
    logRecord['nmap']["data"] = sanitized
    logRecord['nmap']["level"] = level
    logRecord['nmap']["source_label"] = source_label
    logRecord['nmap']["destination_label"] = destination_label

    if len(target) > 0:
        logRecord['nmap']['target'] = target

    message: str = json.dumps(logRecord, sort_keys=True)

    if (level == 'error'):
        logging.error(message)
    if (level == 'info'):
        logging.info(message)

    if (verbose):
        print(json.dumps(json.loads(message), indent=4))


def sanitize_log(message, new_key: str):

    if isinstance(message, dict):
        # Traverse the JSON structure and look for the 'scan' object containing the IP
        if 'scan' in message:
            # Find the key that is the IP address
            for key in list(message['scan'].keys()):
                if is_valid_ip(key):
                    # Replace the IP address field name with the new key (e.g., "target")
                    message['scan'][new_key] = message['scan'].pop(
                        key)
        return message
    elif isinstance(message, str):
        return json.loads('{"text":"' + message + '"}')
    else:
        return json.loads('{"text":"' + str(message) + '"}')


def is_valid_ip(ip: str) -> bool:
    # Regular expression to validate IPv4 addresses
    ip_pattern = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return ip_pattern.match(ip) is not None


def main() -> None:

    # Running NMAP requires running as sudo/administrator
    if (is_admin() == False):
        raise PermissionError(
            "This application requires root/administrator privileges.")

    # Read and validate configuration
    configPath: str = os.path.dirname(
        os.path.realpath(__file__)) + "/config.json"
    try:
        with open(configPath, "r") as read_file:
            tempConfig = json.load(read_file)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Configuration file not found at {configPath}. Please ensure the config.json file exists and has the correct path.")

    except json.JSONDecodeError:
        raise ValueError(
            f"Invalid JSON structure in {configPath}. Please validate the JSON format.")

    subnets: list[str] = tempConfig.get("subnets")

    if not subnets:
        raise ValueError("No subnets provided in config file.")

    source_label: str = tempConfig.get("source_label")
    destination_label: str = tempConfig.get("destination_label")
    arguments = tempConfig.get("args")
    verbose: bool = tempConfig.get("verbose")

    # Initiate scan
    scanner: nmap.PortScannerYield = nmap.PortScannerYield()
    for subnet in subnets:

        # Log per subnet
        log_info(f"Starting scan against subnet: {subnet} with args: {arguments}",
                 source_label=source_label,
                 destination_label=destination_label,
                 verbose=verbose)

        for host, result in scanner.scan(subnet, arguments=arguments, sudo=True):
            if (verbose):
                print("Reporting host: " + host)
            log_info(result,
                     source_label=source_label,
                     destination_label=destination_label,
                     target=host,
                     verbose=verbose)

    log_info("Nmap scan completed.",
             source_label=source_label,
             destination_label=destination_label,
             verbose=verbose)


# We assume the result is successful when user interrupted
# the scan as it is an intentional act.
# Otherwise, exit with an error code of 1.
if __name__ == "__main__":
    logpath: str = detect_logpath()
    touch_logfile(logpath)
    ensure_log_permissions(logpath)
    root_logger: logging.Logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    handler: logging.FileHandler = logging.FileHandler(logpath, 'a', 'utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(handler)

    excepthook = log_error

    try:
        main()
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info(
            '{"nmap":{"level":"error", "data":{"text":"Cancelled by user."},"timestamp":"' + str(datetime.now()) + '", "type":"nmap_scan"}}')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        traceback.format_exc()
        logging.exception(
            '{"nmap":{"level":"error", "data":{"text":"ERROR:' + str(ex) + '"},"timestamp":"' + str(datetime.now()) + '", "type":"nmap_scan"}}')
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
