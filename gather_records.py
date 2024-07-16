from config.config import *

import requests
import subprocess
import re
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

logger.info('Starting Cloudflare > Samba AD DNS record import...')

# Cloudflare API endpoint to list zones
zones_endpoint = 'https://api.cloudflare.com/client/v4/zones'

# Headers for authentication using API Token
headers = {
'Authorization': f'Bearer {api_token}',
'Content-Type': 'application/json'
}

# GATHER NGINX SITES
#
#

# Dump nginx config to get a definitive list of sites nginx is aware of        
raw_result = subprocess.check_output([nginx, '-T'], stderr=subprocess.STDOUT).decode() 

print(raw_result)















domain_name = domain_names[0]

def run_samba_tool(cmd, *args):
    args = list(args) 

    try:
        # Run samba-tool, redirect stderr to stdout, decode bytes in utf-8 to str
        # Need to APPEND *args to predefined args
        subproc_cmd = [samba_tool, 'dns', cmd, domain_controller] + args
        logger.info(f'Running: "{subproc_cmd}"')
        raw_result = subprocess.check_output(subproc_cmd, stderr=subprocess.STDOUT).decode() 
        # Split output into array of lines
        lines = raw_result.splitlines()
        # Pack
        if len(lines) > 1:
            # Create an empty dict
            result = {}
            # Split each line by colon,strip whitespace padding, pack into dict
            for line in lines:
                pairs = line.split(':')
                if len(pairs) > 1:
                    result[pairs[0].strip()] = pairs[1].strip()
            return True, result 
        else:
            return(raw_result)
    except subprocess.CalledProcessError as err:
        # ^ This is a catch-all for a non-zero return code
        logger.info(f'Error running dns {cmd} with argument(s) {args}:\n{err.output.decode()}')
        # Look at output for samba-tool specific error code (decode bytes to utf-8)
        if 'WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST' in err.output.decode():
            return False, err.output.decode()
    else:
        return Exception('Unknown error in AD query')

# Check if zone exists in AD by querying for the zone info
logger.info(f'Checking if zone {domain_name} exists in AD...')
zone = run_samba_tool('zoneinfo', domain_name)
if not zone[0]:
    logger.info(f'Zone {domain_name} does not exist in AD, creating it...')
    # The zone does not exist, so create it
    run_samba_tool('zonecreate', domain_name)
else:
    logger.info(f'Zone {domain_name} already exists in AD.')

print(run_samba_tool('query', domain_name, 'dummy', 'A'))


# Get records for zone from Cloudflare
# Iterate through them, check if they are in AD
# If they are in AD, update them (be lazy and don't check for similarity, no real cost)
# If they are not in AD, add them
# If they are in AD, but NOT in Cloudflare, remove them from AD

#Get the zone ID for the domain
'''response = requests.get(zones_endpoint, headers=headers, params={'name': domain_name})
if response.status_code == 200:
    zones = response.json().get('result')
    if zones:
        zone_id = zones[0]['id']
        logger.debug(f'Zone ID for {domain_name}: {zone_id}')

        # Now that we have the Zone ID, use it to get records for that zone
        # Cloudflare API endpoint to list DNS records
        dns_records_endpoint = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'

        # Get DNS records for the zone
        response = requests.get(dns_records_endpoint, headers=headers) #.get default value None
        if response.status_code == 200:
            logger.info(f'Public DNS records for {domain_name} retrieved!')
            dns_records = response.json().get('result')
            for record in dns_records:
                print(f"Type: {record['type']}, Name: {record['name']}, Content: {record['content']}")
                #run_samba_tool('query', domain_name, record['name'], record['type'])
                run_samba_tool('query', 'smvirtual.biz', 'dummy', 'A')
        else:
            logger.error('Failed to retrieve DNS records:', response.json())

    else:
        logger.warning(f'No zones found for domain: {domain_name}')
else:
    logger.error('Failed to retrieve zones:', response.json())
'''
