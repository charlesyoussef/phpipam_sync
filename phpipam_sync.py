#!/usr/bin/env python
"""Phpipam IPAM server sync from DNA Center, MS DHCP Server, and static hosts in a CSV file:

This script automatically syncs to the specified IPAM server subnet:
- DNA Center hosts
- Static hosts from CSV file
- Leased hosts from the Microsoft DHCP server scope list

It also deletes any stale hosts (addresses in IPAM terms) from the corresponding Phpipam subnet
that were not refreshed in the last script run.

The RBAC control on the subnet management is natively built inside Phpipam,
which can be easily consumed from the Web interface of Phpipam.
"""

import json
import requests
import time
import sys
import csv
import argparse
import socket
import pypsrp
import paramiko
from pypsrp.client import Client
from requests.auth import HTTPBasicAuth
import env_lab

__author__ = "Charles Youssef"
__copyright__ = "Copyright 2018 Cisco and/or its affiliates"
__license__ = "CISCO SAMPLE CODE LICENSE"
__version__ = "1.1"
__email__ = "cyoussef@cisco.com"

# DNAC Variables:
#################

DNAC_HOST = env_lab.DNA_CENTER['host']
DNAC_USER = env_lab.DNA_CENTER['username']
DNAC_PASSWORD = env_lab.DNA_CENTER['password']
DNAC_PORT = env_lab.DNA_CENTER['port']

# IPAM Variables:
#################

PHPIPAM_HOST = env_lab.PHPIPAM['host']
PHPIPAM_USER = env_lab.PHPIPAM['username']
PHPIPAM_PASSWORD = env_lab.PHPIPAM['password']
PHPIPAM_PORT = env_lab.PHPIPAM['port']
PHPIPAM_APPID = env_lab.PHPIPAM['app_id']
PHPIPAM_SUBNET_ID = int(env_lab.PHPIPAM['subnetId'])
PHPIPAM_SYNC_TAG_DELIMITER = env_lab.PHPIPAM['delimiter_string']

# DHCP Server Variables:
########################

DHCP_SERVER_FQDN = env_lab.MS_DHCP_SERVER['fqdn']
DHCP_SERVER_USERNAME = env_lab.MS_DHCP_SERVER['username']
DHCP_SERVER_PASSWORD = env_lab.MS_DHCP_SERVER['password']
DHCP_SERVER_SSL = env_lab.MS_DHCP_SERVER['ssl']
DHCP_SERVER_SCOPES = env_lab.MS_DHCP_SERVER['scopes']

IOS_DHCP_SWITCH = env_lab.IOS_DHCP_SERVER['switch']
IOS_DHCP_PORT = env_lab.IOS_DHCP_SERVER['ssh_port']
IOS_DHCP_USERNAME = env_lab.IOS_DHCP_SERVER['username']
IOS_DHCP_PASSWORD = env_lab.IOS_DHCP_SERVER['password']

# Static hosts CSV file Variable:
#################################

STATICS_CSV_FILE = env_lab.STATIC_HOSTS_CSV_FILE['path']

# DNAC Functions:
#################

def dnac_get_auth_token(controller_ip=DNAC_HOST, username=DNAC_USER, password=DNAC_PASSWORD, port=DNAC_PORT):
    """ Authenticates with DNAC controller and returns a token to be used in subsequent API invocations
    """

    login_url = "https://{0}:{1}/api/system/v1/auth/token".format(controller_ip, port)
    try:
        result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
        result.raise_for_status()
    except:
        print_with_timestamp("Unable to authenticate to DNA Center. Please verify settings and reachability.")
        sys.exit(1)

    token = result.json()["Token"]
    return {
        "controller_ip": controller_ip,
        "token": token
    }

def dnac_create_url(path, controller_ip=DNAC_HOST, port=DNAC_PORT):
    """ Helper function to create a DNAC API endpoint URL using v1 URI
    """
    return "https://%s:%s/api/v1/%s" % (controller_ip, port, path)

def dnac_create_url_v2(path, controller_ip=DNAC_HOST, port=DNAC_PORT):
    """ Helper function to create a DNAC API endpoint URL using v2 URI
    """
    return "https://%s:%s/api/v2/%s" % (controller_ip, port, path)

def dnac_get_url(url):
    """ Helper function to get data from a DNAC endpoint v1 URI
    """
    url = dnac_create_url(path=url)
    token = dnac_get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except ConnectionError as error:
        print_with_timestamp("Error processing DNAC API request. Please verify settings and reachability. %s." % error)
        sys.exit(1)

    return response.json()

def dnac_get_url_v2(url):
    """ Helper function to get data from a DNAC endpoint v2 URI
    """
    url = dnac_create_url_v2(path=url)
    token = dnac_get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except ConnectionError as error:
        print_with_timestamp("Error processing DNAC API request. Please verify settings and reachability. %s." % error)
        sys.exit(1)

    return response.json()

# IPAM Functions:
#################

def ipam_get_auth_token(ipam_ip=PHPIPAM_HOST, port=PHPIPAM_PORT, username=PHPIPAM_USER, password=PHPIPAM_PASSWORD, app_id=PHPIPAM_APPID):
    """ Authenticates with IPAM and returns a token to be used in subsequent API invocations
    """
    login_url = "http://{0}:{1}/api/{2}/user/".format(ipam_ip, port, app_id)
    try:
        result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
        result.raise_for_status()
    except:
        print_with_timestamp("Unable to authenticate to the IPAM Server. Please verify settings and reachability.")
        sys.exit(1)

    token = result.json()["data"]["token"]
    return {
        "ipam_ip": ipam_ip,
        "token": token
    }

def ipam_create_url(path, ipam_ip=PHPIPAM_HOST, port=PHPIPAM_PORT, app_id=PHPIPAM_APPID):
    """ Helper function to create a PHPIPAM API endpoint URL
    """
    return "http://%s:%s/api/%s/%s" % (ipam_ip, port, app_id, path)

def ipam_get_url(url):
    """ Helper function to get data from a PHPIPAM endpoint URL
    """
    url = ipam_create_url(path=url)
    token = ipam_get_auth_token()
    headers = {'token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except ConnectionError as error:
        print_with_timestamp("Error processing IPAM API request. Please verify settings and reachability. %s." % error)
        sys.exit(1)

    return response.json()

# Main program functions (Post-authentication):
################################################

def is_valid_ipv4_address(address):
    """Returns a boolean result of whether "address" argument is a valid IPv4 address or not.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton was found
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def convert_mac_address_format(cisco_mac):
    """Converts a MAC address from the cisco format xxxx.xxxx.xxxx to the standard format
    accepted by IPAM xx:xx:xx:xx:xx:xx
    """
    a = cisco_mac.replace('.','')
    result = ':'.join([a[0:2], a[2:4], a[4:6], a[6:8], a[8:10], a[10:12]])
    return result

def print_with_timestamp(msg):
    """Helper to print the msg string prepended with the current timestamp.
    """
    print("%s: %s" % (time.asctime(time.localtime(time.time())), msg))

def process_host_in_ipam(ip_add, token, url, payload):
    """ Inserts the host with IP address ip_add in IPAM DB if it does not already exist, or updates that host note field with the program execution timestamp if it already exists.
    payload is dict holding the entry to be inserted in IPAM. When updating the IPAM host, we need to remove the subnetId and IP-address from payload as otherwise the Patch call to IPAM won't be accepted.
    """
    try:
        ipam_response = requests.request("POST", url, data=json.dumps(payload), headers={'token': token, 'Content-Type': "application/json"})
    except ConnectionError as error:
        print_with_timestamp("Error processing IPAM API request. %s" % error)
        sys.exit(1)

    if ipam_response.status_code == 201:
        # The host was not present in IPAM DB so it got added with 201 status_code returned:
        print_with_timestamp("Added host %s to IPAM DB" % ip_add)
    elif ipam_response.status_code < 500:
        # The host already exists in IPAM DB, so we need to update the "note" tag with the current time_tag:
        print_with_timestamp("Host %s already exists in IPAM DB" % ip_add)
        # Strip the "subnetId" and "ip" keys as they can't be sent in an address update call:
        payload.pop("subnetId")
        ip_address = payload.pop("ip")
        # Get the "id" of this host IP address, to be able to update its timestamp note tag:
        ipam_search_address_response = ipam_get_url("addresses/search/%s/" %(ip_address))
        ip_address_id = ipam_search_address_response["data"][0]["id"]
        # Send the update API call:
        ipam_address_update_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST, PHPIPAM_PORT, PHPIPAM_APPID, ip_address_id)
        try:
            ipam_address_update_response = requests.request("PATCH", ipam_address_update_url, data=json.dumps(payload), headers={'token': token, 'Content-Type': "application/json"})
            ipam_address_update_response.raise_for_status()
        except:
            print_with_timestamp("Error processing IPAM API request. Please verify settings and reachability.")
            sys.exit(1)
    elif json.loads(ipam_response.text)['message'].startswith('IP address not in selected subnet'):
        # The IP address we're trying to add does not belong to the parent IPAM subnets
        print_with_timestamp("%s. Skipping it" % json.loads(ipam_response.text)['message'])
    else:
        # The IPAM server returned a 5xx status code: Error on server side:
        print_with_timestamp("IPAM DB Server side error. Retry later.")
        sys.exit(1)


def sync_from_dnac(time_tag, ipam_token, ipam_addresses_url):
    """Connect to DNA Center, import its hosts, then process them in IPAM using the passed ipam token, url and timestamp arguments.
    """
    # Get the list of hosts from DNAC:
    hosts_response = dnac_get_url("host")
    hosts_list = hosts_response["response"]

    # Add the DNAC hosts to the IPAM subnet defined globally:
    print("\nSyncing hosts from DNA Center...")
    for host in hosts_list:
        payload = {
            "subnetId": str(PHPIPAM_SUBNET_ID),
            "ip": host["hostIp"],
            "is_gateway": "0",
            "description": "Connected to %s port %s" % (host["connectedNetworkDeviceName"], host["connectedInterfaceName"]),
            "hostname": host["id"],
            "mac": host["hostMac"],
            "note": "dnac%s%s" %(PHPIPAM_SYNC_TAG_DELIMITER,str(time_tag))
        }

        # Process the host in IPAM:
        process_host_in_ipam(host["hostIp"], ipam_token, ipam_addresses_url, payload)

def sync_from_static_csv(csv_file, time_tag, ipam_token, ipam_addresses_url):
    """ Reads the host rows from the CSV file and process them in IPAM using the passed ipam token, url and timestamp arguments.
    """
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            print("\nSyncing static hosts from local CSV file...")
            for host in reader:
                # if the entry line starts by a valid IPv4 address, make the payload json body and process it in IPAM.
                if is_valid_ipv4_address(host[0]):
                    payload = {
                        "subnetId": str(PHPIPAM_SUBNET_ID),
                        "ip": host[0],
                        "is_gateway": "0",
                        "description": host[1],
                        "hostname": host[2],
                        "mac": host[3],
                        "note": "static%s%s" %(PHPIPAM_SYNC_TAG_DELIMITER,str(time_tag))
                    }
                    # Add the host to the IPAM:
                    process_host_in_ipam(host[0], ipam_token, ipam_addresses_url, payload)
                else:
                    #Else, skip it and print an informational message
                    print_with_timestamp("Skipping an invalid host entry in CSV file: '%s'" % host[0])

    except EnvironmentError:
        print_with_timestamp("Unable to open the CSV file. Please verify the file variable in the environment file and retry.")
        sys.exit(1)


def sync_from_ms_dhcp_server(time_tag, ipam_token, ipam_addresses_url):
    """Connect to DHCP server via PowerShell Remoting, import its dhcp scopes leases, then process them in IPAM using the passed ipam token, url and timestamp arguments.
    """

    client = Client(DHCP_SERVER_FQDN, username=DHCP_SERVER_USERNAME,
                        password=DHCP_SERVER_PASSWORD, ssl=DHCP_SERVER_SSL)

    for scope in DHCP_SERVER_SCOPES:
        # scope is a subnet IP address. IP address check:
        if is_valid_ipv4_address(scope):
            command = r"Get-DhcpServerv4Lease -Scopeid %s" % scope
            try:
                dhcp_server_output, streams, had_errors = client.execute_ps(command)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, pypsrp.exceptions.AuthenticationError, requests.exceptions.HTTPError) as error:
                print_with_timestamp("Unable to connect to the DHCP Server. Please verify settings and reachability.")
                sys.exit(1)
            formatted_dhcp_server_output = dhcp_server_output.split("\n")
            print("\nSyncing the leased hosts from the MS DHCP Server, scope %s ..." % scope)
            # Iterate through the list of hosts leases for this scope, starting from index 3 to skip the empty line, then column names line, then the delimiter line:
            for lease in range(3,len(formatted_dhcp_server_output)-2):
                lease_list = formatted_dhcp_server_output[lease].split()
                payload = ""
                # when length of lease_list is 8, this means all the fields are populated including the hostname
                if (len(lease_list) == 8) & (lease_list[4] == "Active"):
                    payload = {
                        "subnetId": str(PHPIPAM_SUBNET_ID),
                        "ip": lease_list[0],
                        "is_gateway": "0",
                        "description": lease_list[3],
                        "hostname": lease_list[3],
                        "mac": lease_list[2],
                        "note": "dhcp%s%s" %(PHPIPAM_SYNC_TAG_DELIMITER,str(time_tag))
                    }
                # when length of lease_list is 7, this means the hostname field is empty.
                # MAC address field is shifted to the left after the string split.
                elif (len(lease_list) == 7) & (lease_list[3] == "Active"):
                    payload = {
                        "subnetId": str(PHPIPAM_SUBNET_ID),
                        "ip": lease_list[0],
                        "is_gateway": "0",
                        "description": "N/A",
                        "hostname": "N/A",
                        "mac": lease_list[2],
                        "note": "dhcp%s%s" %(PHPIPAM_SYNC_TAG_DELIMITER,str(time_tag))
                    }
                # Add the host to the IPAM if it's an active lease:
                if payload != "":
                    process_host_in_ipam(lease_list[0], ipam_token, ipam_addresses_url, payload)

        else: # value entered in scopes list variable is invalid, skipping it:
            print_with_timestamp("\nSkipping an invalid scope entry in the scopes list variable: '%s'" % scope)


def sync_from_ios_dhcp_server(time_tag, ipam_token, ipam_addresses_url):
    """Connect to IOS DHCP server via SSH, and import its dhcp binding database into IPAM
    """

    #Open the SSH session:
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(IOS_DHCP_SWITCH, port=IOS_DHCP_PORT, username=IOS_DHCP_USERNAME, password=IOS_DHCP_PASSWORD, look_for_keys=False, allow_agent=False)
    except (socket.error, paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.SSHException):
        print_with_timestamp("Unable to connect to IOS DHCP Server %s. Please verify settings and reachability." % IOS_DHCP_SWITCH)
        sys.exit(1)

    print("\nSyncing the leased hosts from the IOS DHCP Server %s ..." % IOS_DHCP_SWITCH)
    stdin, stdout, stderr = ssh_client.exec_command("show ip dhcp binding")
    # If no errors, parse the CLI output, else return an error:
    if str(stderr.read()) == "b''":
        cli_output = str(stdout.read()).split("\\n")
        for line in cli_output:
            # If the line starts with an IP address, create a payload based on it.
            # Else, skip this line and do nothing.
            if is_valid_ipv4_address(line.split(" ")[0]):
                payload = {
                    "subnetId": str(PHPIPAM_SUBNET_ID),
                    "ip": line.split()[0],
                    "is_gateway": "0",
                    "description": "Added via IOS DHCP Server",
                    "hostname": "N/A",
                    "mac": convert_mac_address_format(line.split()[1]),
                    "note": "dhcp%s%s" %(PHPIPAM_SYNC_TAG_DELIMITER,str(time_tag))
                }
                process_host_in_ipam(line.split()[0], ipam_token, ipam_addresses_url, payload)
    else:
        print_with_timestamp("Unable to get the DHCP output from IOS Switch %s. Please retry later." % IOS_DHCP_SWITCH)


def delete_stale_hosts(source, time_tag, ipam_token, ipam_addresses_url):
    """Deletes the hosts that have not been added/refreshed in the last script run source.
    Source can be either dnac, static, dhcp, or all.
    This relies on the timestamp in the note field of the host in IPAM DB,
    to be compared with the time_tag which is the timestamp at the start of the script execution.
    """
    print("\nDeleting any stale hosts from IPAM server...")
    subnet_addresses_response = ipam_get_url("subnets/%s/addresses/" %(PHPIPAM_SUBNET_ID))
    if subnet_addresses_response["success"]:
        for host in subnet_addresses_response["data"]:
            # If source is "all" or the first part of the note tag matches the source, proceed with comparing the time_tag to the note tag.
            if (source == "all") or (host["note"].split(PHPIPAM_SYNC_TAG_DELIMITER)[0] == source):
                # If the tag does not match time_tag or , the host was not updated in this run
                # so need to delete it. Else, do nothing.
                if ((len(host["note"].split(PHPIPAM_SYNC_TAG_DELIMITER)) != 1) and (host["note"].split(PHPIPAM_SYNC_TAG_DELIMITER)[1] != str(time_tag))):
                    ipam_address_delete_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST, PHPIPAM_PORT, PHPIPAM_APPID, host["id"])
                    try:
                        ipam_address_delete_response = requests.request("DELETE", ipam_address_delete_url, headers={'token': ipam_token, 'Content-Type': "application/json"})
                        print_with_timestamp("Host %s was deleted from IPAM DB" % host["ip"])
                    except:
                        print_with_timestamp("Could not delete Host %s. Returned message from server: %s" %(host["ip"], ipam_address_delete_response.json()["message"]))
                        sys.exit(1)
    else:
        # Could not get the addresses from the IPAM subnet
        print_with_timestamp("Unable to get the subnet addresses from the IPAM. Please Retry later.")
        sys.exit(1)

def verify_ipam_subnet_usage():
    """Returns the current usage of the IPAM subnet.
    """
    print("\nCurrent IPAM server subnet usage:")
    ipam_subnet_response = ipam_get_url("subnets/%s/usage/" %(PHPIPAM_SUBNET_ID))
    if ipam_subnet_response["success"]:
        print("{0:20}{1:20}{2:20}{3:20}{4:20}".
            format("Subnet ID","Used Hosts","Free Hosts",
            "Used Percent","Freehosts Percent"))
        print("{0:20}{1:20}{2:20}{3:20}{4:20}".
            format(str(PHPIPAM_SUBNET_ID), ipam_subnet_response["data"]["used"], ipam_subnet_response["data"]["freehosts"],
            str(ipam_subnet_response["data"]["Used_percent"]), str(ipam_subnet_response["data"]["freehosts_percent"])))
    else:
        print_with_timestamp("Unable to get the subnet usage info from the IPAM. Retry later.")
        sys.exit(1)

# Executable:
#############

def main():

    # Argparse block:
    parser = argparse.ArgumentParser(description="Sync IPAM server from DNA Center, DHCP server and/or static hosts in CSV file. If no arguments are passed, the default is to sync from all 3 sources.")
    parser.add_argument("-c", "--dnac", action="store_true", help="sync IPAM from DNA Center")
    parser.add_argument("-d", "--dhcp", action="store_true", help="sync IPAM from MS DHCP Server")
    parser.add_argument("-s", "--static", action="store_true", help="sync IPAM from static CSV file")
    parser.add_argument("-v", "--verify", action="store_true", help="verify the current IPAM subnet usage")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()

    # Get the current time, to be used to tag addresses inserted/refreshed in this run:
    time_tag = int(time.time())

    # Authenticate/refresh the token to IPAM:
    ipam_token = ipam_get_auth_token()["token"]

    # Get the IPAM addresses (hosts) API URI:
    ipam_addresses_url = ipam_create_url("addresses")

    if args.dnac:
        # Sync from DNAC to the IPAM DB:
        sync_from_dnac(time_tag, ipam_token, ipam_addresses_url)
        # Delete the stale dnac hosts from IPAM DB:
        delete_stale_hosts("dnac", time_tag, ipam_token, ipam_addresses_url)

    if args.dhcp:
        # Sync from the DHCP server scopes leases to the IPAM DB:
        sync_from_ms_dhcp_server(time_tag, ipam_token, ipam_addresses_url)
        # Sync from the IOS DHCP server:
        sync_from_ios_dhcp_server(time_tag, ipam_token, ipam_addresses_url)
        # Delete the stale dhcp hosts from IPAM DB:
        delete_stale_hosts("dhcp", time_tag, ipam_token, ipam_addresses_url)


    if args.static:
        # Sync the static hosts from the CSV file STATICS_CSV_FILE to the IPAM DB:
        sync_from_static_csv(STATICS_CSV_FILE, time_tag, ipam_token, ipam_addresses_url)
        # Delete the stale static hosts from IPAM DB:
        delete_stale_hosts("static", time_tag, ipam_token, ipam_addresses_url)

    if args.verify:
        # Return the IPAM subnet usage:
        verify_ipam_subnet_usage()

    if len(sys.argv) == 1:
        # No args are passed. Then sync from all the 3 sources and verify the IPAM subnet usage:
        sync_from_dnac(time_tag, ipam_token, ipam_addresses_url)
        sync_from_ms_dhcp_server(time_tag, ipam_token, ipam_addresses_url)
        sync_from_static_csv(STATICS_CSV_FILE, time_tag, ipam_token, ipam_addresses_url)
        delete_stale_hosts("all", time_tag, ipam_token, ipam_addresses_url)
        verify_ipam_subnet_usage()


if __name__ == "__main__":
    main()
