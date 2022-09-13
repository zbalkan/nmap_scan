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

import jsonschema
import nmap

SCHEMA: str = '''
{
    "$schema": "https://json-schema.org/draft/2019-09/schema",
    "$id": "http://example.com/example.json",
    "type": "object",
    "default": {},
    "title": "Root Schema",
    "required": [
        "subnets",
        "verbose"
    ],
    "properties": {
        "subnets": {
            "type": "array",
            "default": [],
            "title": "The subnets Schema",
            "items": {
                "type": "string",
                "default": "",
                "title": "A Schema",
                "examples": [
                    "192.168.166.0/24"
                ]
            },
            "examples": [
                [
                    "192.168.166.0/24"]
            ]
        },
        "verbose": {
            "type": "boolean",
            "default": false,
            "title": "The verbose Schema",
            "examples": [
                true
            ]
        }
    },
    "examples": [{
        "subnets": [
            "192.168.166.0/24"
        ],
        "verbose": true
    }]
}
'''


def main() -> None:
    # Read and validate configuration
    configPath: str = os.path.dirname(
        os.path.realpath(__file__)) + "/config.json"
    with open(configPath, "r") as read_file:
        tempConfig = json.load(read_file)

    if (__validate_json(tempConfig, SCHEMA) == False):
        print("Invalid config file")
        exit(1)

    subnets: list = tempConfig.get("subnets")
    verbose: bool = tempConfig.get("verbose")

    logpath: str = detect_logpath()

    root_logger: logging.Logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    handler: logging.FileHandler = logging.FileHandler(logpath, 'w', 'utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(handler)

    excepthook = log_error

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
    __log(text, 'debug', verbose)


def log_info(text: object, verbose: bool = False) -> None:
    __log(text, 'info', verbose)


def log_error(text: object, verbose: bool = False) -> None:
    __log(text, 'error', verbose)


def __log(text: object, level: str, verbose: bool = False) -> None:
    logRecord: dict = dict()
    now: datetime = datetime.now()
    logRecord["localtime"] = str(now.now())
    logRecord["utctime"] = str(now.utcnow())
    logRecord["type"] = "nmap_scan"
    logRecord["message"] = text
    logRecord["level"] = level

    message: str = json.dumps(logRecord, sort_keys=True)

    if (level == 'error'):
        logging.error(message)
    if (level == 'info'):
        logging.info(message)
    if (level == 'debug'):
        logging.debug(message)

    if (verbose):
        print(json.dumps(json.loads(message), indent=4))


def __validate_json(jsonData: str, schema) -> bool:
    try:
        jsonschema.validate(instance=jsonData, schema=schema)
    except Exception:
        return False
    return True


# We assume the result is successful when user interrupted
# the scan as it is an intentional act.
# Otherwise, exit with an error code of 1.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print(str(ex))
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
