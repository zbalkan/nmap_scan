#!/usr/bin/env bash
set -eu -o pipefail

LOGROTATE_CONFIG_PATH="/etc/logrotate.d/nmap_scan"
SCANNER_PATH="/usr/local/sbin"
CONFIG_PATH="/usr/local/etc/nmap_scan"

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
    if ! pip3 install --root-user-action=ignore python-nmap==0.7.1 typing_extensions; then
        echo "Error: Failed to install Python packages" >&2
        exit 1
    fi
}

# Function to create the nmap user (no password, no login shell)
function create_nmap_user() {
    echo "Creating a non-privileged nmap user with no password and no login shell"

    # Create the user as a system account with no login shell
    useradd -r -s /usr/sbin/nologin -M nmap || echo "nmap user already exists"

    # Lock the nmap user to prevent password login (no password, no access)
    passwd -l nmap

    # Ensure the shell is set to nologin to prevent accidental `su` usage
    usermod -s /usr/sbin/nologin nmap
}

# Function to configure sudo permissions for the nmap user with secure permissions
function configure_sudo_permissions() {
    echo "Configuring sudo permissions for nmap user"

    # Create sudoers file with secure permissions
    echo "nmap ALL=(root) NOPASSWD: /usr/bin/nmap, /usr/bin/python3" | sudo tee /etc/sudoers.d/nmap >/dev/null
    sudo chmod 440 /etc/sudoers.d/nmap # Set secure permissions for sudoers file
}

# Function to create necessary directories and files
function create_directories_and_files() {
    echo "Creating nmap_scan folder and files"

    mkdir -p "$SCANNER_PATH"
    mkdir -p "$CONFIG_PATH"
    chown -R nmap:nmap "$SCANNER_PATH"
    chown -R nmap:nmap "$CONFIG_PATH"

    # Check if the nmap_scan.py script already exists
    if [[ -f "$SCANNER_PATH/nmap_scan.py" ]]; then
        read -r -p "File $SCANNER_PATH/nmap_scan.py already exists. Overwrite? (y/n): " choice
        if [[ "$choice" != "y" ]]; then
            echo "Skipping nmap_scan.py creation."
            return
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


def is_admin() -> bool:
    return (os.getuid() == 0)  # type: ignore


def detect_logpath() -> str:
    logDir: str = '/var/log'
    # if log folder does not exist, create
    os.makedirs(logDir, exist_ok=True)

    return os.path.join(logDir, 'nmap_scan.log')


def log_debug(text: object, source_label: str, destination_label: str, target: str = '', verbose: bool = False) -> None:
    log(text, 'debug', source_label, destination_label, target, verbose)


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
    if (level == 'debug'):
        logging.debug(message)

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

    # Check if config.json already exists
    if [[ -f "$CONFIG_PATH/config.json" ]]; then
        read -r -p "File $CONFIG_PATH/config.json already exists. Overwrite? (y/n): " choice
        if [[ "$choice" != "y" ]]; then
            echo "Skipping config.json creation."
            return
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

    # Set the ownership and permissions for nmap_scan.py
    chown nmap:nmap "$SCANNER_PATH/nmap_scan.py"
    chmod 500 "$SCANNER_PATH/nmap_scan.py" # Owner (nmap) has read and execute, no permissions for others

    # Set permissions for the config.json file
    chown nmap:nmap "$CONFIG_PATH/config.json"
    chmod 600 "$CONFIG_PATH/config.json" # Only owner (nmap) can read/write
}

# Function to set up the systemd service
function setup_systemd_service() {
    local SERVICE_FILE="/etc/systemd/system/nmap_scan.service"

    echo "Creating systemd service file at $SERVICE_FILE"
    cat <<EOF | sudo tee "$SERVICE_FILE" >/dev/null
[Unit]
Description=Run nmap_scan.py script

[Service]
Type=simple
User=nmap
ExecStart=/usr/bin/sudo /usr/bin/python3 $SCANNER_PATH/nmap_scan.py
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
TimeoutStartSec=300
Restart=on-failure
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

    sudo chmod 644 "$SERVICE_FILE"
}

# Function to set up the systemd timer
function setup_systemd_timer() {
    local TIMER_FILE="/etc/systemd/system/nmap_scan.timer"

    echo "Creating systemd timer file at $TIMER_FILE"
    cat <<EOF | sudo tee "$TIMER_FILE" >/dev/null
[Unit]
Description=Timer to run nmap_scan.py script on 1st and 16th of every month

[Timer]
OnCalendar=*-*-1,16 01:10:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo chmod 644 "$TIMER_FILE"
}

# Function to enable and start the systemd service and timer
function enable_and_start_systemd() {
    echo "Reloading systemd daemon"
    sudo systemctl daemon-reload

    echo "Enabling and starting the nmap_scan.timer"
    sudo systemctl enable nmap_scan.timer
    sudo systemctl start nmap_scan.timer

    # Confirm the status of the timer
    sudo systemctl status nmap_scan.timer
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
        echo "Logrotate configuration already exists at $LOGROTATE_CONFIG_PATH"
        read -r -p "Overwrite the existing configuration? (y/n): " choice
        if [[ "$choice" != "y" ]]; then
            echo "Skipping logrotate configuration."
            return
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
    create 640 nmap nmap
    endscript
}
EOF

    # Set appropriate permissions for the logrotate config
    chmod 644 "$LOGROTATE_CONFIG_PATH"
    echo "Logrotate configuration created at $LOGROTATE_CONFIG_PATH"
}

# Main function to run the setup process
function main() {
    check_root
    install_dependencies
    create_nmap_user
    configure_sudo_permissions
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
