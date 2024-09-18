# NMAP Scanner for Wazuh

A python script that runs an nmap scan within a network subnet and writes the results to log file in a json format.

## Usage

### Scheduled usage

You can use the setup script:

- Run `setup.sh`
- Use the confirmation flag `-y` if you want to skip replying or want to use it as a part of automation.
- Fill in `config.json` with the subnet(s) or IP ranges
- Check systemd timers and update if needed

Or, you can set it up manually:

- Run `pip install python-nmap==0.7.1`
- Copy `nmap_scan.py` and `config.json` to a known location.
- Create systemd timers or cron jobs

### Single use (for test and debugging)

- Fill in `config.json` with the subnet(s) or IP ranges
- Run `pip install python-nmap==0.7.1`
- Run `python3 nmap_scan.py`

Or

- run `sudo systemctl start nmap_scan.service` if you used the default method.

## Uninstall

The `setup.sh` file has a `-u` flag to uninstall the service. Just run:

```shell
./setup.sh -u
```

There is a confirmation step here as well bt you can bypass it using the confirmation flag `-y`.

```shell
./setup.sh -u -y
```

The uninstall comand cleans up the items below. If you want to cleanup you can check these paths:
LOGROTATE CONFIG PATH: "/etc/logrotate.d/nmap_scan"
SCANNER PATH: "/opt/nmap_scan/nmap_scan.py"
CONFIG PATH: "/usr/local/etc/nmap_scan/config.json"
SERVICE FILE: "/etc/systemd/system/nmap_scan.service"
TIMER FILE: "/etc/systemd/system/nmap_scan.timer"
LOG PATH: "/var/log/nmap_scan.log"

Or you can run a search like `find / -name "nmap_scan*"` and clean the remnants yourself.

## Configuration

The configuration allows defining targets as nmap accepts such as "192.168.0.0/24" or "192.168.0.2-254". It alo allow labeling the source and destination, so that you can write custom rules.

```json
{
  "source_label": "source",
  "destination_label": "destination",
  "subnets": [
    "192.168.0.0/24"
  ],
  "args": "-sV -T4 -Pn -p- -sT -sU",
  "verbose": true
}
```

## Wazuh rule

```xml
<group name="nmap,network_scan">
     <rule id="110030" level="3">
         <decoded_as>json</decoded_as>
         <field name="nmap.type">nmap_scan</field>
         <description>NMAP scan messages grouped</description>
         <options>no_full_log</options>
     </rule>

     <rule id="110031" level="3">
         <if_sid>110030</if_sid>
         <field name="nmap.level">debug</field>
         <description>NMAP scan debug messages</description>
         <options>no_full_log</options>
     </rule>

     <rule id="110032" level="5">
         <if_sid>110030</if_sid>
         <field name="nmap.level">info</field>
         <description>NMAP scan results</description>
         <options>no_full_log</options>
     </rule>
 </group>
```

## Thanks

Based on the work of [juaromu](https://github.com/juaromu/wazuh-nmap).
