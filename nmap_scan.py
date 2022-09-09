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
import platform
import sys
from datetime import datetime

import nmap


def main() -> None:
    # Read configuration
    subnetsPath: str = os.path.dirname(
        os.path.realpath(__file__)) + "/subnets.json"
    with open(subnetsPath, "r") as read_file:
        data = json.load(read_file)

    subnets: list = data.get("subnets")
    verbose: bool = data.get("verbose")

    logpath: str = detect_logpath()

    root_logger: logging.Logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    handler: logging.FileHandler = logging.FileHandler(logpath, 'w', 'utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(handler)

    excepthook = logging.error

    # Initiate scan
    scanner: nmap.PortScannerYield = nmap.PortScannerYield()
    for subnet in subnets:
        # Log per subnet
        if (verbose):
            log_debug("Starting scan over in subnet: " +
                      subnet, verbose=verbose)

        for host, result in scanner.scan(subnet):
            if (verbose):
                print("Reporting host: " + host)
            log_info(result, verbose=verbose)

    if (verbose):
        log_debug("Nmap scan completed.", verbose=verbose)


def detect_logpath() -> str:
    logDir: str = os.path.join('/var/log', 'nmap_scan')
    if (platform.system() == "Windows"):
        logDir: str = os.path.join(
            os.getenv('ALLUSERSPROFILE', ''), 'nmap_scan')

    # if log folder does not exist, create
    os.makedirs(logDir, exist_ok=True)

    return os.path.join(logDir, 'nmap_scan.log')


def log_debug(text: object, verbose: bool = False) -> None:
    logRecord: dict = dict()
    now: datetime = datetime.now()
    logRecord["timestamp"] = str(now.now())
    logRecord["timezone"] = str(now.tzname())
    logRecord["utc"] = str(now.utcnow())
    logRecord["type"] = "nmap_scan"
    logRecord["level"] = "debug"
    logRecord["message"] = text
    message: str = json.dumps(logRecord, sort_keys=True)
    logging.debug(message)

    if (verbose):
        print(message)


def log_info(text: object, verbose: bool = False) -> None:
    logRecord: dict = dict()
    now: datetime = datetime.now()
    logRecord["timestamp"] = str(now.now())
    logRecord["timezone"] = str(now.tzname())
    logRecord["utc"] = str(now.utcnow())
    logRecord["type"] = "nmap_scan"
    logRecord["level"] = "info"
    logRecord["message"] = text
    message: str = json.dumps(logRecord, sort_keys=True)
    logging.debug(message)

    if (verbose):
        print(message)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
