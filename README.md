# NMAP Scanner for Wazuh

A python script that runs an nmap scan within a network subnet and writes the results to log file in a json format.

## Usage

### Scheduled usage

You can use the setup script:

- Run `setup.sh`
- Fill in `config.json` with the subnet(s) required
- Check crontab for tasks

Or, you can set it up manually:

- Run `pip install -r requirements.txt`
- Copy `nmap_scan.py` and `config.json` to a known location.
- Create cron jobs to run

### Single use (for test and debugging)

- Fill in `config.json` with the subnet(s) required
- Run `pip install -r requirements.txt`
- Run `python3 nmap_scan.py`

## Configuration

The configuration allows defining targets as nmap accepts such as "192.168.0.0/24" or "192.168.0.2.254". It alo allow labeling the source and destination, so that you can write custom rules.

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
