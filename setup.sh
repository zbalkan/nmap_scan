#!/usr/bin/env bash
set -eu -o pipefail

LOGROTATE_CONFIG_PATH="/etc/logrotate.d/nmap_scan"
SCANNER_DIR="/opt/nmap_scan"
CONFIG_PATH="/usr/local/etc/nmap_scan.conf"
SERVICE_PATH="/etc/systemd/system/nmap_scan.service"
TIMER_PATH="/etc/systemd/system/nmap_scan.timer"
LOG_PATH="/var/log/nmap_scan.log"
STATE_PATH="var/run/nmap_scan/nmap_scan.state"

AUTO_CONFIRM=false
UNINSTALL=false

if [[ "${_DEBUG:-}" == "true" ]]; then
    set -x
fi

# Function to ensure the script is run as root
function check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script can be executed only as root, Exiting.."
        exit 1
    fi
}

# Function to check for the -y and -u options
function parse_arguments() {
    while getopts ":yu" opt; do
        case $opt in
        y)
            AUTO_CONFIRM=true
            ;;
        u)
            UNINSTALL=true
            ;;
        *)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        esac
    done
}

function check_systemd() {
    # Check if systemctl is available
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "Error: systemctl is not installed or available." >&2
        exit 1
    fi
}

# Function to install dependencies with error handling
function install_dependencies() {
    echo "Installing dependencies"

    # Check if dnf is available
    if ! command -v dnf >/dev/null 2>&1; then
        echo "Error: dnf is not installed or available." >&2
        exit 1
    fi

    # Check if pip3 is available
    if ! command -v pip3 >/dev/null 2>&1; then
        echo "Error: pip3 is not installed or available." >&2
        exit 1
    fi

    # Install python3-pip and nmap, exit with error if installation fails
    if ! dnf install -y python3-pip nmap; then
        echo "Error: Failed to install python3-pip or nmap" >&2
        exit 1
    fi

    # Install required python packages
    if ! pip3 install python-nmap==0.7.1; then
        echo "Error: Failed to install Python packages" >&2
        exit 1
    fi
}

# Function to create necessary directories and files
function create_directories_and_files() {
    echo "Creating nmap_scan folder and files"

    mkdir -p "$SCANNER_DIR"
    chown -R root:root "$SCANNER_DIR"

    # Check if the nmap_scan.py script already exists
    if [[ -f "$SCANNER_DIR/nmap_scan.py" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $SCANNER_DIR/nmap_scan.py"
        else
            read -r -p "File $SCANNER_DIR/nmap_scan.py already exists. Overwrite? (y/N): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping nmap_scan.py creation."
                return
            fi
        fi
    fi

    # Write the nmap_scan.py script
    cat <<EOF >"$SCANNER_DIR/nmap_scan.py"
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


EOF

    # Set the ownership and permissions for nmap_scan.py
    chown root:root "$SCANNER_DIR/nmap_scan.py"
    chmod 500 "$SCANNER_DIR/nmap_scan.py" # Owner (nmap) has read and execute, no permissions for others

    # Check if config.json already exists
    if [[ -f "$CONFIG_PATH/config.json" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $SCANNER_DIR/nmap_scan.py"
        else
            read -r -p "File $CONFIG_PATH/config.json already exists. Overwrite? (y/N): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping config.json creation."
                return
            fi
        fi
    fi

    # Create the config.json file
    cat <<EOF >"$CONFIG_PATH"
{
  "source_label": "source",
  "destination_label": "destination",
  "scan_name": "VLAN X to VLAN Y",
  "targets": [
    "192.168.0.0/24"
  ],
  "args": "-T4 -Pn -p- -sS -sU --min-parallelism 100 --min-rate 1000  -n",
  "verbose": true
}

EOF

    # Set permissions for the config file
    chown root:root "$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH" # Only owner (nmap) can read/write
}

# Function to set up the systemd service
function setup_systemd_service() {
    local SERVICE_PATH="/etc/systemd/system/nmap_scan.service"

    # Check if the service file already exists
    if [[ -f "$SERVICE_PATH" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $SERVICE_PATH"
        else
            read -r -p "Systemd service file $SERVICE_PATH already exists. Overwrite? (y/N): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping systemd service creation."
                return
            fi
        fi
    fi

    echo "Creating systemd service file at $SERVICE_PATH"
    cat <<EOF | tee "$SERVICE_PATH" >/dev/null
[Unit]
Description=Run nmap_scan.py script

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $SCANNER_DIR/nmap_scan.py
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
TimeoutStartSec=300
Restart=on-failure
RestartSec=30
StartLimitInterval=5min
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SERVICE_PATH"
}

# Function to set up the systemd timer
function setup_systemd_timer() {
    local TIMER_PATH="/etc/systemd/system/nmap_scan.timer"

    # Check if the timer file already exists
    if [[ -f "$TIMER_PATH" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $TIMER_PATH"
        else
            read -r -p "Systemd timer file $TIMER_PATH already exists. Overwrite? (y/N): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping systemd timer creation."
                return
            fi
        fi
    fi

    echo "Creating systemd timer file at $TIMER_PATH"
    cat <<EOF | tee "$TIMER_PATH" >/dev/null
[Unit]
Description=Timer to run nmap_scan.py script on 1st and 16th of every month

[Timer]
OnCalendar=*-*-1,16 01:10:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    chmod 644 "$TIMER_PATH"
}

# Function to enable and start the systemd service and timer
function enable_and_start_systemd() {
    echo "Reloading systemd daemon"
    systemctl daemon-reload

    echo "Enabling and starting the nmap_scan.timer"
    systemctl enable --now nmap_scan.timer

    # Confirm the status of the timer
    systemctl status nmap_scan.timer
}

# Function to create a logrotate configuration for nmap_scan logs
function setup_logrotate() {
    echo "Creating logrotate configuration for nmap_scan logs"

    # Check if the logrotate config already exists
    if [[ -f "$LOGROTATE_CONFIG_PATH" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing logrotate configuration at $LOGROTATE_CONFIG_PATH"
        else
            read -r -p "Logrotate configuration already exists at $LOGROTATE_CONFIG_PATH. Overwrite? (y/N): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping logrotate configuration."
                return
            fi
        fi
    fi

    # Create the logrotate configuration file
    cat <<EOF >"$LOGROTATE_CONFIG_PATH"
/var/log/nmap_scan.log {
    daily
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 600 root root
}
EOF

    # Set appropriate permissions for the logrotate config
    chmod 644 "$LOGROTATE_CONFIG_PATH"
    echo "Logrotate configuration created at $LOGROTATE_CONFIG_PATH"
}

# Function to uninstall everything
function uninstall() {

    if ! (systemctl list-units --full -all | grep "nmap_scan"); then
        echo "Service nmap_scan does not exist. Nothing to uninstall."
        exit 1
    fi
    echo "Uninstalling nmap scan setup"

    # Check if the logrotate config already exists
    if [[ "$AUTO_CONFIRM" == "true" ]]; then
        echo "Uninstalling without confirmation"
    else
        read -r -p "Are you sure you want to uninstall nmap_scan? (y/N): " choice
        if [[ "$choice" != "y" ]]; then
            echo "Canceling the uninstall operation."
            return
        fi
    fi

    # Stop and disable systemd service and timer
    if systemctl is-active --quiet nmap_scan.timer; then
        echo "Stopping and disabling systemd timer and service"
        systemctl stop nmap_scan.timer
        systemctl disable nmap_scan.timer
    fi

    if systemctl is-active --quiet nmap_scan.service; then
        echo "Stopping and disabling systemd service"
        systemctl stop nmap_scan.service
        systemctl disable nmap_scan.service
    fi

    if [[ -f "$SERVICE_PATH" ]]; then
        echo "Removing systemd service file: $SERVICE_PATH"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -f "$SERVICE_PATH"
        else
            rm "$SERVICE_PATH"
        fi
        if [[ -f "$SERVICE_PATH" ]]; then
            echo "Failed to delete $SERVICE_PATH. Consider removing manually."
        fi
    fi

    if [[ -f "$TIMER_PATH" ]]; then
        echo "Removing systemd timer file: $TIMER_PATH"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -f "$TIMER_PATH"
        else
            rm "$TIMER_PATH"
        fi
        if [[ -f "$TIMER_PATH" ]]; then
            echo "Failed to delete $TIMER_PATH. Consider removing manually."
        fi
    fi

    if [[ -f "$LOGROTATE_CONFIG_PATH" ]]; then
        echo "Removing logrotate configuration: $LOGROTATE_CONFIG_PATH"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -f "$LOGROTATE_CONFIG_PATH"
        else
            rm "$LOGROTATE_CONFIG_PATH"
        fi
        if [[ -f "$LOGROTATE_CONFIG_PATH" ]]; then
            echo "Failed to delete $LOGROTATE_CONFIG_PATH. Consider removing manually."
        fi
    fi

    if [[ -d "$SCANNER_DIR" ]]; then
        echo "Removing nmap_scan script directory: $SCANNER_DIR"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -rf "$SCANNER_DIR"
        else
            rm -r "$SCANNER_DIR"
        fi
        if [[ -f "$SCANNER_DIR" ]]; then
            echo "Failed to delete $SCANNER_DIR. Consider removing manually."
        fi
    fi

    if [[ -d "$CONFIG_PATH" ]]; then
        echo "Removing nmap_scan config file: $CONFIG_PATH"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -f "$CONFIG_PATH"
        else
            rm "$CONFIG_PATH"
        fi
        if [[ -f "$CONFIG_PATH" ]]; then
            echo "Failed to delete $CONFIG_PATH. Consider removing manually."
        fi
    fi

    if [[ -d "$LOG_PATH" ]]; then
        echo "Removing nmap_scan log file: $LOG_PATH"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -f "$LOG_PATH"
        else
            rm "$LOG_PATH"
        fi
        if [[ -f "$LOG_PATH" ]]; then
            echo "Failed to delete $LOG_PATH. Consider removing manually."
        fi
    fi

    if [[ -d "$STATE_PATH" ]]; then
        echo "Removing nmap_scan state file: $STATE_PATH"
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            rm -f "$STATE_PATH"
        else
            rm "$STATE_PATH"
        fi
        if [[ -f "$STATE_PATH" ]]; then
            echo "Failed to delete $STATE_PATH. Consider removing manually."
        fi
    fi
    # Reload systemd to reflect the removed files
    echo "Reloading systemd daemon"
    systemctl daemon-reload

    echo "Uninstallation completed."
}

# Main function to run the setup process
function main() {
    check_root
    parse_arguments "$@"
    if [[ "$UNINSTALL" == "true" ]]; then
        echo "Removing nmap scan setup"
        uninstall
    else
        echo "Setting up nmap scan"
        check_systemd
        install_dependencies
        create_directories_and_files
        setup_systemd_service
        setup_systemd_timer
        enable_and_start_systemd
        setup_logrotate

        echo ""
        echo "Installation completed. Update the configuration file at $CONFIG_PATH to define the target subnets you want to scan."
    fi
}

# Call the main function with all script arguments
main "$@"
