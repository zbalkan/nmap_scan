#!/usr/bin/env python3

################################
# Python Script to Run Network Scans and append results to Wazuh Active Responses Log
# Requirements:
# NMAP installed in Agent
# python-nmap (https://pypi.org/project/python-nmap/)
# Do NOT include subnets with a network firewall in the path of the agent and the subnet.
################################
import ctypes
import json
import logging
import os
import platform
import sys
from datetime import datetime

import nmap


def __is_admin() -> bool:
    if (platform.system() == "Windows"):
        return bool(ctypes.windll.shell32.IsUserAnAdmin()) != 0
    else:
        return (os.getuid() == 0)  # type: ignore


def __detect_logpath() -> str:
    logDir: str = os.path.join('/var/log', 'nmap_scan')
    if (platform.system() == "Windows"):
        logDir = os.path.join(
            os.getenv('ALLUSERSPROFILE', ''), 'nmap_scan')

    # if log folder does not exist, create
    os.makedirs(logDir, exist_ok=True)

    return os.path.join(logDir, 'nmap_scan.log')


def log_debug(text: object, source_label: str, destination_label: str, verbose: bool = False) -> None:
    __log(text, 'debug', source_label, destination_label, verbose)


def log_info(text: object, source_label: str, destination_label: str, verbose: bool = False) -> None:
    __log(text, 'info', source_label, destination_label, verbose)


def log_error(text: object, source_label: str, destination_label: str, verbose: bool = False) -> None:
    __log(text, 'error', source_label, destination_label, verbose)


def __log(text: object, level: str, source_label: str, destination_label: str, verbose: bool = False) -> None:
    logRecord: dict = dict()
    logRecord['nmap'] = dict()
    logRecord['nmap']["timestamp"] = str(datetime.now())
    logRecord['nmap']["type"] = "nmap_scan"
    logRecord['nmap']["message"] = text
    logRecord['nmap']["level"] = level
    logRecord['nmap']["source_label"] = source_label
    logRecord['nmap']["destination_label"] = destination_label

    message: str = json.dumps(logRecord, sort_keys=True)

    if (level == 'error'):
        logging.error(message)
    if (level == 'info'):
        logging.info(message)
    if (level == 'debug'):
        logging.debug(message)

    if (verbose):
        print(json.dumps(json.loads(message), indent=4))


def main() -> None:

    # Running NMAP requires running as sudo/administrator
    if (__is_admin() == False):
        raise Exception(
            "This application requires root/administrator privileges.")

    # Read and validate configuration
    configPath: str = os.path.dirname(
        os.path.realpath(__file__)) + "/config.json"
    try:
        with open(configPath, "r") as read_file:
            tempConfig = json.load(read_file)
    except:
        raise Exception("Invalid config file")

    subnets: list[str] = tempConfig.get("subnets")
    verbose: bool = tempConfig.get("verbose")

    source_label: str = tempConfig.get("source_label")
    destination_label: str = tempConfig.get("destination_label")
    arguments = tempConfig.get("args")

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
                     verbose=verbose)

    log_info("Nmap scan completed.",
             source_label=source_label,
             destination_label=destination_label,
             verbose=verbose)


# We assume the result is successful when user interrupted
# the scan as it is an intentional act.
# Otherwise, exit with an error code of 1.
if __name__ == "__main__":
    logpath: str = __detect_logpath()
    root_logger: logging.Logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    handler: logging.FileHandler = logging.FileHandler(logpath, 'a', 'utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(handler)

    excepthook = log_error

    try:
        main()
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info(
            '{"nmap":{"level":"error", "message":"Cancelled by user.","timestamp":"' + str(datetime.now()) + '", "type":"nmap_scan"}}')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        logging.info('ERROR: ' + str(ex))
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
