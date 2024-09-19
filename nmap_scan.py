#!/usr/bin/env python3

################################
# Python Script to Run Network Scans and log the results that can be consumed by any SIEM.
# Requirements:
# NMAP installed in Agent
# python-nmap (https://pypi.org/project/python-nmap/)
# Do NOT include subnets with a network firewall in the path of the agent and the target.
################################
import ipaddress
import json
import logging
import os
import re
import sys
import traceback
import uuid
from datetime import datetime

import nmap

LOG_DIR: str = '/var/log'
CONFIG_PATH: str = '/usr/local/etc/nmap_scan.conf'
STATE_PATH: str = 'var/run/nmap_scan/nmap_scan.state'


def is_admin() -> bool:
    return (os.getuid() == 0)  # type: ignore


def detect_logpath() -> str:
    os.makedirs(LOG_DIR, exist_ok=True)
    return os.path.join(LOG_DIR, 'nmap_scan.log')


def touch(file: str) -> None:
    if not os.path.exists(file):
        dir = os.path.dirname(file)
        os.makedirs(dir, exist_ok=True)
        with open(file, 'w') as f:
            f.write('')


def ensure_log_permissions(path: str) -> None:
    if os.path.exists(path):
        os.chown(path, 0, 0)   # type: ignore
        # Set file permissions to 640
        os.chmod(path, 0o600)


def log_message(message: object, level: str, target: str, config: dict, correlation_id: str) -> None:

    message_json: dict = dict()
    message_json['nmap'] = dict()

    # let's dd some metadata for querying
    message_json['nmap']['type'] = 'nmap_scan'
    message_json['nmap']['level'] = level
    message_json['nmap']['target'] = target
    message_json['nmap']['scan_name'] = config['scan_name']
    message_json['nmap']['source_label'] = config['source_label']
    message_json['nmap']['destination_label'] = config['destination_label']
    message_json['nmap']['correlation_id'] = correlation_id

    # finally the log itself
    message_json['nmap']['data'] = sanitize_log(message, 'target')
    message_json['nmap']['timestamp'] = str(datetime.now())

    message_str: str = json.dumps(message_json, sort_keys=True)

    if (level == 'error'):
        logging.error(message_str)
    if (level == 'info'):
        logging.info(message_str)

    if (config['verbose']):
        print(json.dumps(json.loads(message_str), indent=4))


def sanitize_log(message, new_key: str):

    if isinstance(message, dict):
        # Traverse the JSON structure and look for the 'scan' object containing the IP
        if 'scan' in message:
            # Find the key that is the IP address
            for key in list(message['scan'].keys()):
                if is_valid_ip(key):
                    # Replace the IP address field name with the new key (e.g., 'target')
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


def load_state() -> dict:
    state: dict
    try:
        with open(STATE_PATH, 'r') as state_file:
            state = json.load(state_file)
    except:
        # create the file if it does not exist
        touch(STATE_PATH)

        state = dict()
        state['scanned_hosts'] = []

    return state


def save_state(state) -> None:
    with open(STATE_PATH, 'w') as state_file:
        state_file.write(json.dumps(state))


def range_to_ip(ip_input: str):
    """
    Parse input which can be a single IP, an IP range (e.g., 192.168.0.2-254), or a CIDR block.
    Collapse the input into the smallest possible CIDR notation(s).

    :param ip_input: String representation of an IP address, range, or CIDR.
    :return: List of CIDR notations as strings.
    """

    # Regular expressions for CIDR, single IP, and IP range
    cidr_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
    single_ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    range_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){2}\.\d{1,3}-\d{1,3}$")

    # Check if input is CIDR notation
    if cidr_pattern.match(ip_input):
        # Handle CIDR directly
        network = ipaddress.IPv4Network(ip_input, strict=False)
        return [host for host in network.hosts()]

    # Check if it's a single IP
    elif single_ip_pattern.match(ip_input):
        # Convert single IP to a /32 network
        return [ipaddress.IPv4Address(ip_input)]

    # Check if it's a range (e.g., 192.168.0.2-254)
    elif range_pattern.match(ip_input):
        # Extract base IP and range
        base_ip, range_part = ip_input.rsplit('.', 1)
        start_suffix, end_suffix = range_part.split('-')
        ip_list = []

        # Summarize IP range (e.g., 192.168.0.2 to 192.168.25.254) to CIDRs
        first_ip = base_ip + '.' + start_suffix
        last_ip = base_ip + '.' + end_suffix
        for cidr in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(first_ip), ipaddress.IPv4Address(last_ip)):
            ip_list.extend([ip for ip in cidr.hosts()])

    else:
        raise ValueError(f"Invalid input format: {ip_input}")


def filter_scanned(scannable_targets, scanned):
    if len(scanned) == 0:
        return scannable_targets
    else:
        logging.info(
            f'{len(scanned)} out of {len(scannable_targets)} hosts are already scanned')
        ips_to_scan = []

        # Convert scanned_hosts (strings) to IPv4Address objects and store them in a set for fast lookups
        scanned_hosts = {
            ipaddress.IPv4Address(address=ip) for ip in scanned}

        for target in scannable_targets:
            ip_list = range_to_ip(target)
            if ip_list:
                ips_to_scan.extend(
                    [
                        ip for ip in ip_list if ip.compressed not in scanned_hosts])

        logging.info(f'{len(ips_to_scan)} addresses filtered')
        # Convert the individual IPv4Address objects into IPv4Network objects with /32 prefix
        hosts_to_scan_as_networks = [
            ipaddress.IPv4Network(address=host) for host in ips_to_scan]

        # Summarize the /32 networks into the smallest possible set of subnets
        summarized_subnets = ipaddress.collapse_addresses(
            addresses=hosts_to_scan_as_networks)

        # Update targets with the summarized subnets in compressed form
        filtered = [str(subnet) for subnet in summarized_subnets]
        logging.info(
            f'{len(filtered)} addresses filtered')
        return filtered


def load_configuration():
    try:
        with open(CONFIG_PATH, 'r') as read_file:
            configuration = json.load(read_file)
    except FileNotFoundError:
        raise FileNotFoundError(
            f'Configuration file not found at {CONFIG_PATH}. Please ensure the config.json file exists and has the correct path.')

    except json.JSONDecodeError:
        raise ValueError(
            f'Invalid JSON structure in {CONFIG_PATH}. Please validate the JSON format.')

    return configuration


def main(state: dict) -> None:

    # Running NMAP requires running as sudo/administrator
    if (is_admin() == False):
        raise PermissionError(
            'This application requires root/administrator privileges.')

    configuration = load_configuration()

    targets = configuration.get('targets')

    if not targets or len(targets) == 0:
        raise ValueError('No subnets provided in config file.')

    arguments: str = configuration.get('args')
    verbose: bool = configuration.get('verbose')

    # Filtering out already scanned hosts
    targets = filter_scanned(scannable_targets=targets,
                             scanned=state['scanned_hosts'])

    if len(targets) == 0:
        log_message(message='No hosts to scan.',
                    level='info',
                    target='None',
                    config=configuration,
                    correlation_id=state['correlation_id'])
        return

    # Log per scan
    sanitized_targets = str.join(',', targets)
    log_message(message=f'Starting scan {configuration["scan_name"]} against target: {sanitized_targets} with args: {arguments}',
                level='info',
                target=sanitized_targets,
                config=configuration,
                correlation_id=state['correlation_id'])

    # Initiate scan
    scanner: nmap.PortScannerYield = nmap.PortScannerYield()

    for target in targets:
        # Log per target
        log_message(message=f'Starting scan against target: {target} with args: {arguments}',
                    level='info',
                    target=target,
                    config=configuration,
                    correlation_id=state['correlation_id'])

        for host, result in scanner.scan(target, arguments=arguments, sudo=True):
            if (verbose):
                print(f'Reporting host: {host}')
            log_message(message=result,
                        level='info',
                        target=host,
                        config=configuration,
                        correlation_id=state['correlation_id'])
            state['scanned_hosts'].append(host)
            save_state(state)

    log_message(message='Nmap scan completed.',
                level='info',
                target=sanitized_targets,
                config=configuration,
                correlation_id=state['correlation_id'])


# We assume the result is successful when user interrupted
# the scan as it is an intentional act.
# Otherwise, exit with an error code of 1.
if __name__ == '__main__':
    logpath: str = detect_logpath()
    touch(logpath)
    ensure_log_permissions(logpath)
    root_logger: logging.Logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    handler: logging.FileHandler = logging.FileHandler(logpath, 'a', 'utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(handler)

    excepthook = log_message

    try:
        # This is ugly but in order to let the user know the scan was cancelled
        # or failed due to an error, we need to load the state here
        # pass itto the main function
        # allow other functions to use the state
        # out of main() scope

        # Read state for partial scans
        state: dict = load_state()
        if 'correlation_id' not in state:
            state['correlation_id'] = uuid.uuid4().hex

        main(state=state)
    except KeyboardInterrupt:
        print('Cancelled by user.')
        cancel_log: dict = dict()
        cancel_log['nmap'] = dict()
        cancel_log['nmap']['text'] = 'Cancelled by user.'
        cancel_log['nmap']['timestamp'] = str(datetime.now())
        cancel_log['nmap']['type'] = 'nmap_scan'
        cancel_log['nmap']['level'] = 'error'
        cancel_log['nmap']['correlation_id'] = state['correlation_id']
        logging.info(json.dumps(cancel_log))
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print(f'ERROR: {str(ex)}')
        err_log: dict = dict()
        err_log['nmap'] = dict()
        err_log['nmap']['text'] = f'ERROR:{str(ex)}\nTRACEBACK:\n{traceback.format_exc()}'
        err_log['nmap']['timestamp'] = str(datetime.now())
        err_log['nmap']['type'] = 'nmap_scan'
        err_log['nmap']['level'] = 'error'
        err_log['nmap']['correlation_id'] = state['correlation_id']
        logging.exception(json.dumps(err_log))
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
