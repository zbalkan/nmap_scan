# NMAP Scanner for Wazuh

An NMAP script to run nmap scan within a network subnet and writes the results to Wazuh active-response.log
Based on the work <https://github.com/juaromu/wazuh-nmap>

## Usage

- Run `setup.sh`
- Fill in `subnets.json` with the subnet(s) required
- Check crontab for tasks
