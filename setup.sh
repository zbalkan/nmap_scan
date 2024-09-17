#!/usr/bin/env bash
set -eu -o pipefail

LOGROTATE_CONFIG_PATH="/etc/logrotate.d/nmap_scan"
SCANNER_PATH="/opt/nmap_scan"
CONFIG_PATH="/usr/local/etc/nmap_scan"

AUTO_CONFIRM=false

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

# Function to check for the -y option and set AUTO_CONFIRM
function parse_arguments() {
    while getopts ":y" opt; do
        case $opt in
        y)
            AUTO_CONFIRM=true
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
    if ! pip3 install python-nmap==0.7.1 typing_extensions; then
        echo "Error: Failed to install Python packages" >&2
        exit 1
    fi
}

# Function to create necessary directories and files
function create_directories_and_files() {
    echo "Creating nmap_scan folder and files"

    mkdir -p "$SCANNER_PATH"
    mkdir -p "$CONFIG_PATH"
    chown -R root:root "$SCANNER_PATH"
    chown -R root:root "$CONFIG_PATH"

    # Check if the nmap_scan.py script already exists
    if [[ -f "$SCANNER_PATH/nmap_scan.py" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $SCANNER_PATH/nmap_scan.py"
        else
            read -r -p "File $SCANNER_PATH/nmap_scan.py already exists. Overwrite? (y/n): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping nmap_scan.py creation."
                return
            fi
        fi
    fi

    # Write the nmap_scan.py script
    cat <<EOF >"$SCANNER_PATH/nmap_scan.py"
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

import nmap

LOG_PATH: str = '/var/log'
CONFIG_PATH: str = "/usr/local/etc/nmap_scan" + '/config.json'


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
        os.chown(path, 0, 0)   # type: ignore
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
    try:
        with open(CONFIG_PATH, "r") as read_file:
            tempConfig = json.load(read_file)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Configuration file not found at {CONFIG_PATH}. Please ensure the config.json file exists and has the correct path.")

    except json.JSONDecodeError:
        raise ValueError(
            f"Invalid JSON structure in {CONFIG_PATH}. Please validate the JSON format.")

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


EOF

    # Set the ownership and permissions for nmap_scan.py
    chown root:root "$SCANNER_PATH/nmap_scan.py"
    chmod 500 "$SCANNER_PATH/nmap_scan.py" # Owner (nmap) has read and execute, no permissions for others

    # Check if config.json already exists
    if [[ -f "$CONFIG_PATH/config.json" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $SCANNER_PATH/nmap_scan.py"
        else
            read -r -p "File $CONFIG_PATH/config.json already exists. Overwrite? (y/n): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping config.json creation."
                return
            fi
        fi
    fi

    # Create the config.json file
    cat <<EOF >"$CONFIG_PATH/config.json"
{
  "source_label": "source",
  "destination_label": "destination",
  "subnets": [
    "192.168.0.0/24"
  ],
  "args": "-T4 -Pn -p- -sS -sU --min-parallelism 100 --min-rate 1000  -n",
  "verbose": true
}

EOF

    # Set permissions for the config.json file
    chown root:root "$CONFIG_PATH/config.json"
    chmod 600 "$CONFIG_PATH/config.json" # Only owner (nmap) can read/write
}

# Function to set up the systemd service
function setup_systemd_service() {
    local SERVICE_FILE="/etc/systemd/system/nmap_scan.service"

    # Check if the service file already exists
    if [[ -f "$SERVICE_FILE" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $SERVICE_FILE"
        else
            read -r -p "Systemd service file $SERVICE_FILE already exists. Overwrite? (y/n): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping systemd service creation."
                return
            fi
        fi
    fi

    echo "Creating systemd service file at $SERVICE_FILE"
    cat <<EOF | tee "$SERVICE_FILE" >/dev/null
[Unit]
Description=Run nmap_scan.py script

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $SCANNER_PATH/nmap_scan.py
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

    chmod 644 "$SERVICE_FILE"
}

# Function to set up the systemd timer
function setup_systemd_timer() {
    local TIMER_FILE="/etc/systemd/system/nmap_scan.timer"

    # Check if the timer file already exists
    if [[ -f "$TIMER_FILE" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing $TIMER_FILE"
        else
            read -r -p "Systemd timer file $TIMER_FILE already exists. Overwrite? (y/n): " choice
            if [[ "$choice" != "y" ]]; then
                echo "Skipping systemd timer creation."
                return
            fi
        fi
    fi

    echo "Creating systemd timer file at $TIMER_FILE"
    cat <<EOF | tee "$TIMER_FILE" >/dev/null
[Unit]
Description=Timer to run nmap_scan.py script on 1st and 16th of every month

[Timer]
OnCalendar=*-*-1,16 01:10:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    chmod 644 "$TIMER_FILE"
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

# Function to list all active systemd timers
function list_active_timers() {
    echo "Listing all active timers:"
    systemctl list-timers --all
}

# Function to create a logrotate configuration for nmap_scan logs
function setup_logrotate() {
    echo "Creating logrotate configuration for nmap_scan logs"

    # Check if the logrotate config already exists
    if [[ -f "$LOGROTATE_CONFIG_PATH" ]]; then
        if [[ "$AUTO_CONFIRM" == "true" ]]; then
            echo "Overwriting existing logrotate configuration at $LOGROTATE_CONFIG_PATH"
        else
            read -r -p "Logrotate configuration already exists at $LOGROTATE_CONFIG_PATH. Overwrite? (y/n): " choice
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

# Main function to run the setup process
function main() {
    check_root
    parse_arguments "$@"
    check_systemd
    install_dependencies
    create_directories_and_files
    setup_systemd_service
    setup_systemd_timer
    enable_and_start_systemd
    list_active_timers
    setup_logrotate

    echo ""
    echo "Installation completed. Update the configuration file at $CONFIG_PATH/config.json to define the target subnets you want to scan."
}

# Call the main function with all script arguments
main "$@"
