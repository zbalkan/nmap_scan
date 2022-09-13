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

## Wazuh rule

```xml
 <group name="linux,nmap,network_scan">
     <rule id="200400" level="3">
         <decoded_as>json</decoded_as>
         <field name="type">nmap_scan</field>
         <field name="level">debug</field>
         <description>NMAP scan debug messages</description>
         <options>no_full_log</options>
     </rule>

     <rule id="200401" level="5">
         <decoded_as>json</decoded_as>
         <field name="type">nmap_scan</field>
         <field name="level">info</field>
         <description>NMAP scan results</description>
         <options>no_full_log</options>
     </rule>
 </group>
```

## Thanks

Based on the work <https://github.com/juaromu/wazuh-nmap>. 
