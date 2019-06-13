#!/usr/bin/env python
"""
This is a program to synchronize a PHPIPAM server with addresses (hosts)
from multiple sources being:
- Cisco DNA Center
- Microsoft DHCP Server
- Cisco DHCP Server running on Cisco IOS switch
- Static hosts defined in a CSV file

PHPIPAM is a free open source IP Address Management (IPAM) solution.

The prerequisite is to have the parent IP subnet created in PHPIPAM database.

The synchronization consists of both:
- Adding new addresses (hosts) that are discovered and not present in IPAM database.
- Deleting stale addresses (hosts) that used to exist but are not anymore advertised
by the same source(s) in the last program execution.

Whenever an address (host) is added or deleted from the PHPIPAM Database, notifications are made via:
- a log entry added to a log text file in local directory
- a message is posted in a Webex Teams space
- at the end of the program Execution, a single email is sent with the list of added & deleted hosts

The Role-based Access Control (RBAC) on the subnet management is natively built
inside PHPIPAM which can be consumed from the server Web interface.
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
import smtplib
import os
import schedule
from email.mime.text import MIMEText
from pypsrp.client import Client
from requests.auth import HTTPBasicAuth
from webexteamssdk import WebexTeamsAPI
from datetime import datetime

# If the env_file.py is missing from local directory
# or has invalid content, exit the program gracefully:
try:
    import env_file
except (SyntaxError, ModuleNotFoundError):
    print("env_file.py file not found. Please clone it from the env_file_template and " \
        "complete the required fields in the proper format.")
    sys.exit(1)

__author__ = "Charles Youssef"
__copyright__ = "Copyright 2019 Cisco and/or its affiliates"
__license__ = "CISCO SAMPLE CODE LICENSE"
__version__ = "1.1"
__email__ = "cyoussef@cisco.com"


# Global variables read from the env_file; catching any errors gracefully:
try:
    # PHPIPAM Variables:
    PHPIPAM_HOST = env_file.PHPIPAM['host']
    PHPIPAM_USER = env_file.PHPIPAM['username']
    PHPIPAM_PASSWORD = env_file.PHPIPAM['password']
    PHPIPAM_PORT = env_file.PHPIPAM['port']
    PHPIPAM_APPID = env_file.PHPIPAM['app_id']
    PHPIPAM_SUBNET_ID = int(env_file.PHPIPAM['subnetId'])
    # DNA_CENTER Variables:
    DNAC_HOST = env_file.DNA_CENTER['host']
    DNAC_USER = env_file.DNA_CENTER['username']
    DNAC_PASSWORD = env_file.DNA_CENTER['password']
    DNAC_PORT = env_file.DNA_CENTER['port']
    # Microsoft DHCP Server Variables:
    DHCP_SERVER_FQDN = env_file.MS_DHCP_SERVER['fqdn']
    DHCP_SERVER_USERNAME = env_file.MS_DHCP_SERVER['username']
    DHCP_SERVER_PASSWORD = env_file.MS_DHCP_SERVER['password']
    DHCP_SERVER_SSL = env_file.MS_DHCP_SERVER['ssl']
    DHCP_SERVER_SCOPES = env_file.MS_DHCP_SERVER['scopes']
    # Cisco IOS DHCP Server Variables:
    IOS_DHCP_SWITCH = env_file.IOS_DHCP_SERVER['switch']
    IOS_DHCP_PORT = env_file.IOS_DHCP_SERVER['ssh_port']
    IOS_DHCP_USERNAME = env_file.IOS_DHCP_SERVER['username']
    IOS_DHCP_PASSWORD = env_file.IOS_DHCP_SERVER['password']
    # Static CSV variable:
    STATICS_CSV_FILE = env_file.STATIC_HOSTS_CSV_FILE['path']
    # Email Server Variables:
    EMAIL_SERVER = env_file.EMAIL_PROPERTIES['mail_server']
    EMAIL_FROM_ADDRESS = env_file.EMAIL_PROPERTIES['from_address']
    EMAIL_TO_ADDRESS_LIST = env_file.EMAIL_PROPERTIES['to_address_list']
    EMAIL_SUBJECT = env_file.EMAIL_PROPERTIES['email_subject']
    EMAIL_CONTENT_FILE = env_file.EMAIL_PROPERTIES['email_content_tempfile']
    # Webex Teams Variables:
    TEAMS_ROOM_ID = env_file.WEBEX_TEAMS['room_id']
    TEAMS_BOT_TOKEN = env_file.WEBEX_TEAMS['bot_token']

except (NameError, KeyError):
    print("Invalid input in env_file. Please complete the required fields in the proper format.")
    sys.exit(1)

# Constant tags, added to the IPAM address "owner" field to identify the address source:
TAG_DNAC = "DNAC"
TAG_MSDHCP = "MSDHCP"
TAG_IOSDHCP = "IOSDHCP"
TAG_STATIC = "STATIC"

# Flag for whether an email needs to be sent or not:
email_flag = False
# Global file open to add logs for email notification when required:
email_body = open(EMAIL_CONTENT_FILE, "w")

# Log file name, where program output is also appended in local directory.
# It is updated in main() function.
LOG_FILE = None

# Scheduler time, defining how frequently the main program is rerun.
# This can be updated by the user input too. Default is defined here as 15 minutes:
script_rerun_timer = 15

# DNAC Helper Functions:

def dnac_get_auth_token(controller_ip=DNAC_HOST, username=DNAC_USER, password=DNAC_PASSWORD,
    port=DNAC_PORT, log_file=LOG_FILE, email_content_file=EMAIL_CONTENT_FILE):
    """ Authenticates with DNA Center and returns a token to be used in subsequent API calls
    """

    login_url = "https://{0}:{1}/api/system/v1/auth/token".format(controller_ip, port)
    try:
        result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
        result.raise_for_status()
    except:
        print("Unable to authenticate to DNA Center. Please verify " \
            "settings and reachability.")
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
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

def dnac_get_url(url, log_file, EMAIL_CONTENT_FILE):
    """ Helper function to get data from a DNAC endpoint v1 URI
    """
    url = dnac_create_url(path=url)
    token = dnac_get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except ConnectionError as error:
        print("Error processing DNAC API request. Please verify settings " \
            "and reachability. %s." % error)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

    return response.json()

def dnac_get_url_v2(url, log_file, EMAIL_CONTENT_FILE):
    """ Helper function to get data from a DNAC endpoint v2 URI
    """
    url = dnac_create_url_v2(path=url)
    token = dnac_get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except ConnectionError as error:
        print("Error processing DNAC API request. Please verify settings " \
            "and reachability. %s." % error)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

    return response.json()

# IPAM Helper Functions:

def ipam_get_auth_token(ipam_ip=PHPIPAM_HOST, port=PHPIPAM_PORT, username=PHPIPAM_USER,
    password=PHPIPAM_PASSWORD, app_id=PHPIPAM_APPID, log_file=LOG_FILE,
    email_content_file=EMAIL_CONTENT_FILE):
    """ Authenticates with IPAM and returns a token to be used in subsequent API calls
    """
    login_url = "http://{0}:{1}/api/{2}/user/".format(ipam_ip, port, app_id)
    try:
        result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
        result.raise_for_status()
    except:
        print("Unable to authenticate to the IPAM Server. Please verify " \
            "settings and reachability.")
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
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

def ipam_get_url(url, log_file, EMAIL_CONTENT_FILE):
    """ Helper function to get data from a PHPIPAM endpoint URL
    """
    url = ipam_create_url(path=url)
    token = ipam_get_auth_token()
    headers = {'token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except ConnectionError as error:
        print("Error processing IPAM API request. Please verify settings " \
            "and reachability. %s." % error)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

    return response.json()

# Other Helper Functions:

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

def print_with_timestamp_and_log(msg, log_file):
    """Helper to print the msg string prepended with the current timestamp.
    """
    result = "%s: %s" % (time.asctime(time.localtime(time.time())), msg)
    log_file.write("%s\n" %result)
    print(result)

def process_host_in_ipam(ip_add, token, url, payload, log_file, email_body, EMAIL_CONTENT_FILE,
    webex_teams_api):
    """ Inserts the host with IP address ip_add in IPAM DB if it does not already exist,
    or updates that host note field with the new program execution timestamp if it already exists.
    Payload is a dict holding the entry to be inserted in IPAM.
    When updating the IPAM host, we need to remove the subnetId and IP-address from payload as
    otherwise the Patch API call to IPAM won't be accepted.
    """
    global email_flag
    try:
        ipam_response = requests.request("POST", url, data=json.dumps(payload),
            headers={'token': token, 'Content-Type': "application/json"})
    except ConnectionError as error:
        print("Error processing IPAM API request. %s" % error)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

    if ipam_response.status_code == 201:
        # The host was not present in IPAM DB so it got added with 201 status_code returned:
        msg = "Added host %s to IPAM DB" % ip_add
        email_flag = notify_via_log_email_teams(msg, log_file, email_body, webex_teams_api)
    elif ipam_response.status_code == 409:
        # The host already exists in IPAM DB; "note" tag to be updated to the current time_tag:
        print_with_timestamp_and_log("Host %s already exists in IPAM DB" % ip_add, log_file)
        # Strip the "subnetId" and "ip" keys as they can't be sent in an address update call:
        payload.pop("subnetId")
        ip_address = payload.pop("ip")
        # Get the "id" of this host IP address, to be able to update its timestamp note tag:
        ipam_search_address_response = ipam_get_url("addresses/search/%s/" %(ip_address), log_file,
        EMAIL_CONTENT_FILE)
        ip_address_id = ipam_search_address_response["data"][0]["id"]
        ip_address_note = ipam_search_address_response["data"][0]["note"]
        ip_address_owner = ipam_search_address_response["data"][0]["owner"]
        ip_address_sources_set = set(ip_address_owner.split(','))
        payload_note = payload["note"]
        payload_owner = payload["owner"]
        if payload_owner not in ip_address_sources_set:
            ip_address_sources_set.add(payload_owner)
            new_payload_owner = ','.join(list(ip_address_sources_set))
        else:
            new_payload_owner = ip_address_owner
        payload["owner"] = new_payload_owner
        # Send the update API call:
        ipam_address_update_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST,
            PHPIPAM_PORT, PHPIPAM_APPID, ip_address_id)
        try:
            ipam_address_update_response = requests.request("PATCH", ipam_address_update_url,
                data=json.dumps(payload), headers={'token': token, 'Content-Type': "application/json"})
            ipam_address_update_response.raise_for_status()
        except:
            print_with_timestamp_and_log("Error processing IPAM API request. " \
            "Please verify settings and reachability.", log_file)
            cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
            sys.exit(1)

    elif json.loads(ipam_response.text)['message'].startswith('IP address not in selected subnet'):
        # The IP address we're trying to add does not belong to the parent IPAM subnets
        print_with_timestamp_and_log("%s. Skipping it" % json.loads(ipam_response.text)['message'], log_file)
    else:
        # The IPAM server returned a 5xx status code: Error on server side:
        print_with_timestamp_and_log("IPAM DB Server side error. Retry later.", log_file)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)


def sync_from_dnac(time_tag, ipam_token, ipam_addresses_url, log_file, webex_teams_api):
    """Connect to DNA Center, import its hosts, then process them in IPAM using
    the passed ipam token, url and timestamp arguments.
    """
    # Get the list of hosts from DNAC:
    hosts_response = dnac_get_url("host", log_file, EMAIL_CONTENT_FILE)
    hosts_list = hosts_response["response"]

    # Add the DNAC hosts to the IPAM subnet defined globally:
    print("\nSyncing hosts from DNA Center...")
    log_file.write("\nSyncing hosts from DNA Center...\n")
    for host in hosts_list:
        payload = {
            "subnetId": str(PHPIPAM_SUBNET_ID),
            "ip": host["hostIp"],
            "is_gateway": "0",
            "description": "Connected to %s port %s" % (
                host["connectedNetworkDeviceName"], host["connectedInterfaceName"]),
            "hostname": host["id"],
            "mac": host["hostMac"],
            "owner": TAG_DNAC,
            "note": str(time_tag)
        }

        # Process the host in IPAM:
        process_host_in_ipam(host["hostIp"], ipam_token, ipam_addresses_url, payload,
            log_file, email_body, EMAIL_CONTENT_FILE, webex_teams_api)

def sync_from_static_csv(csv_file, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
    EMAIL_CONTENT_FILE, webex_teams_api):
    """ Reads the host rows from the CSV file and process them in IPAM
    using the passed ipam token, url and timestamp arguments.
    """
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            print("\nSyncing static hosts from local CSV file...")
            log_file.write("\nSyncing static hosts from local CSV file...\n")
            for host in reader:
                # if the entry line starts by a valid IPv4 address, make the payload json body
                # and process it in IPAM.
                if is_valid_ipv4_address(host[0]):
                    payload = {
                        "subnetId": str(PHPIPAM_SUBNET_ID),
                        "ip": host[0],
                        "is_gateway": "0",
                        "description": "N/A" if host[1] == '' else host[1],
                        "hostname": "N/A" if host[2] == '' else host[2],
                        #"mac": "00:00:00:00:00:00" if not host[3] else host[3],
                        "owner": TAG_STATIC,
                        "note": str(time_tag)
                    }
                    # Add the host to the IPAM:
                    process_host_in_ipam(host[0], ipam_token, ipam_addresses_url, payload,
                        log_file, email_body, EMAIL_CONTENT_FILE, webex_teams_api)
                else:
                    #Else, skip it and print an informational message
                    print_with_timestamp_and_log("Skipping an invalid host entry in CSV file: '%s'"
                    % host[0], log_file)

    except EnvironmentError:
        print_with_timestamp_and_log("Unable to open the CSV file. Please verify the file " \
        "variable in the environment file and retry.", log_file)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)


def sync_from_ms_dhcp_server(time_tag, ipam_token, ipam_addresses_url, log_file, EMAIL_CONTENT_FILE,
    webex_teams_api):
    """Connect to DHCP server via PowerShell Remoting, import its dhcp scopes leases,
    then process them in IPAM using the passed ipam token, url and timestamp arguments.
    """

    client = Client(DHCP_SERVER_FQDN, username=DHCP_SERVER_USERNAME,
                        password=DHCP_SERVER_PASSWORD, ssl=DHCP_SERVER_SSL)

    # validate that all entered DHCP scopes in the list env variable are valid IP subnet addresses.
    # If any invalid entry is found, exit the program.
    for scope in DHCP_SERVER_SCOPES:
        if not is_valid_ipv4_address(scope):
            print("At least one invalid scope is found in MS DHCP Server scopes list. " \
                "Please use valid IP subnet DHCP scope entries and retry.")
            sys.exit(1)

    # All scopes are valid, proceed with the sync from the DHCP server:
    for scope in DHCP_SERVER_SCOPES:
        command = r"Get-DhcpServerv4Lease -Scopeid %s" % scope
        try:
            dhcp_server_output, streams, had_errors = client.execute_ps(command)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
            pypsrp.exceptions.AuthenticationError, requests.exceptions.HTTPError) as error:
            print_with_timestamp_and_log("Unable to connect to the DHCP Server. Please verify " \
                "settings and reachability.", log_file)
            cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
            sys.exit(1)
        formatted_dhcp_server_output = dhcp_server_output.split("\n")
        print("\nSyncing the leased hosts from the MS DHCP Server, scope %s..." % scope)
        log_file.write("\nSyncing the leased hosts from the MS DHCP Server, scope %s...\n" % scope)
        # Iterate through the list of hosts leases for this scope, starting from index 3
        # to skip the empty line, then column names line, then the delimiter line:
        for lease in range(3,len(formatted_dhcp_server_output)-2):
            lease_list = formatted_dhcp_server_output[lease].split()
            payload = ""
            # when length of lease_list is 8, this means all the fields are populated
            # including the hostname
            if (len(lease_list) == 8) & (lease_list[4] == "Active"):
                payload = {
                    "subnetId": str(PHPIPAM_SUBNET_ID),
                    "ip": lease_list[0],
                    "is_gateway": "0",
                    "description": lease_list[3],
                    "hostname": lease_list[3],
                    "mac": lease_list[2],
                    "owner": TAG_MSDHCP,
                    "note": str(time_tag)
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
                    "owner": TAG_MSDHCP,
                    "note": str(time_tag)
                }
            # Add the host to the IPAM if it's an active lease:
            if payload != "":
                process_host_in_ipam(lease_list[0], ipam_token, ipam_addresses_url, payload,
                    log_file, email_body, EMAIL_CONTENT_FILE, webex_teams_api)


def sync_from_ios_dhcp_server(time_tag, ipam_token, ipam_addresses_url, log_file, EMAIL_CONTENT_FILE,
    webex_teams_api):
    """Connect to IOS DHCP server via VTY, and import its dhcp binding database into IPAM
    """

    #Open the VTY session:
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(IOS_DHCP_SWITCH, port=IOS_DHCP_PORT, username=IOS_DHCP_USERNAME,
            password=IOS_DHCP_PASSWORD, look_for_keys=False, allow_agent=False)
    except (socket.error, paramiko.ssh_exception.AuthenticationException,
        paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.SSHException) as error:
        print_with_timestamp_and_log("Unable to connect to IOS DHCP Server %s. Please verify " \
        "settings and reachability. %s" % (IOS_DHCP_SWITCH, error), log_file)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

    print("\nSyncing the leased hosts from the IOS DHCP Server %s..." % IOS_DHCP_SWITCH)
    log_file.write("\nSyncing the leased hosts from the IOS DHCP Server %s...\n" % IOS_DHCP_SWITCH)
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
                    "owner": TAG_IOSDHCP,
                    "note": str(time_tag)
                }
                process_host_in_ipam(line.split()[0], ipam_token, ipam_addresses_url,
                    payload, log_file, email_body, EMAIL_CONTENT_FILE, webex_teams_api)
    else:
        print_with_timestamp_and_log("Unable to get the DHCP output from IOS Switch %s. " \
            "Please retry later." % IOS_DHCP_SWITCH, log_file)


def delete_stale_hosts(source, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
EMAIL_CONTENT_FILE, webex_teams_api):
    """Deletes the hosts that have not been added/refreshed in the last script run source.
    Source can be either one of the source tag variables defined globally.
    This relies on the timestamp in the note field of the host in IPAM DB,
    to be compared with the time_tag which is the timestamp at the start of the script execution.
    """
    global email_flag
    print("\nDeleting any stale hosts from IPAM server...")
    log_file.write("\nDeleting any stale hosts from IPAM server...\n")
    subnet_addresses_response = ipam_get_url("subnets/%s/addresses/" %(PHPIPAM_SUBNET_ID), log_file,
    EMAIL_CONTENT_FILE)
    if subnet_addresses_response["success"]:
        for host in subnet_addresses_response["data"]:
            host_sources_set = set(host["owner"].split(','))
            host_timetag = host["note"]
            if (host_timetag != str(time_tag)):
                if host_sources_set == {source}:
                    ipam_address_delete_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST,
                        PHPIPAM_PORT, PHPIPAM_APPID, host["id"])
                    try:
                        ipam_address_delete_response = requests.request("DELETE", ipam_address_delete_url,
                            headers={'token': ipam_token, 'Content-Type': "application/json"})
                        msg = "Host %s was deleted from IPAM DB" % host["ip"]
                        email_flag = notify_via_log_email_teams(msg, log_file, email_body, webex_teams_api)
                    except:
                        print_with_timestamp_and_log("Could not delete Host %s. Returned message from " \
                            "server: %s" %(host["ip"], ipam_address_delete_response.json()["message"]),
                            log_file)
                        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
                        sys.exit(1)
                elif source in host_sources_set: #update the host with the new sources set
                    host_sources_set.remove(source)
                    #print(host["ip"])
                    new_payload_owner = ','.join(list(host_sources_set))
                    new_payload = {"owner": new_payload_owner}
                    host_id = host["id"]
                    # Send the update API call:
                    ipam_address_update_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST,
                        PHPIPAM_PORT, PHPIPAM_APPID, host_id)
                    try:
                        ipam_address_update_response = requests.request("PATCH", ipam_address_update_url,
                            data=json.dumps(new_payload), headers={'token': ipam_token,
                            'Content-Type': "application/json"})
                        ipam_address_update_response.raise_for_status()
                    except:
                        print_with_timestamp_and_log("Error processing IPAM update API request. Please " \
                            "verify settings and reachability.", log_file)
                        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
                        sys.exit(1)

    else:
        # Could not get the addresses from the IPAM subnet
        print_with_timestamp_and_log("Unable to get the subnet addresses from the IPAM. " \
            "Please Retry later.", log_file)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

def verify_ipam_subnet_usage(log_file, email_body, EMAIL_CONTENT_FILE):
    """Returns the summary of the current usage of the IPAM subnet.
    """
    print("\nCurrent IPAM server subnet usage:")
    log_file.write("\nCurrent IPAM server subnet usage:\n")
    ipam_subnet_response = ipam_get_url("subnets/%s/usage/" %(PHPIPAM_SUBNET_ID), log_file,
    EMAIL_CONTENT_FILE)
    if ipam_subnet_response["success"]:
        column_names = "{0:20}{1:20}{2:20}{3:20}{4:20}".format("Subnet ID","Used Hosts",
            "Free Hosts","Used Percent","Freehosts Percent")
        column_values = "{0:20}{1:20}{2:20}{3:20}{4:20}".format(str(PHPIPAM_SUBNET_ID),
            ipam_subnet_response["data"]["used"], ipam_subnet_response["data"]["freehosts"],
            str(round(ipam_subnet_response["data"]["Used_percent"],3)),
            str(round(ipam_subnet_response["data"]["freehosts_percent"],3)))
        print(column_names)
        print(column_values)
        log_file.write("%s\n%s" % (column_names, column_values))
    else:
        print_with_timestamp_and_log("Unable to get the subnet usage info from the IPAM. " \
            "Please retry later.", log_file)
        cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

def send_email():
    """Send the email notification containing addresses additions/deletions logs
    When the email_flag is set, which means there was at least one new address learned/deleted.
    """
    if email_flag:
        with open(EMAIL_CONTENT_FILE) as fp:
            msg = MIMEText(fp.read())
        msg['Subject'] = EMAIL_SUBJECT
        msg['From'] = EMAIL_FROM_ADDRESS
        msg['To'] = EMAIL_TO_ADDRESS_LIST
        sl = smtplib.SMTP(EMAIL_SERVER)
        sl.send_message(msg)
        sl.quit()
        #print("\nAn email listing the new & stale hosts was sent to the email recipient list.")

def cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE):
    """Prior to the program exit, close the open files, delete the temp email-body file,
    and send the email if necessary.
    """
    email_body.write("\nBest Regards,\nCisco DIT Team\n")
    #log_file.close()
    email_body.close()
    send_email()
    os.remove(EMAIL_CONTENT_FILE)

def notify_via_log_email_teams(msg, log_file, email_body, webex_teams_api):
    """When a host is added or deleted, this function will be called
    To send a notification via email and post in the Webex Teams space, and add the log to the logfile.
    It returns a boolean flag which tells if an email will need to be sent or not.
    """
    print_with_timestamp_and_log(msg, log_file)
    email_body.write("\n%s: %s\n" % (time.asctime(time.localtime(time.time())), msg))
    email_flag = True
    webex_teams_api.messages.create(roomId=TEAMS_ROOM_ID, text=msg)
    return email_flag


def main():
    """Main program
    """
    # User input flags definition:
    parser = argparse.ArgumentParser(description="Sync IPAM server from DNA Center, DHCP server \
        and/or static hosts in CSV file. If no arguments are passed, the default is to sync \
        from all 3 sources.")
    parser.add_argument("-c", "--dnac", action="store_true", help="sync IPAM from DNA Center")
    parser.add_argument("-d", "--dhcp", action="store_true", help="sync IPAM from MS DHCP Server")
    parser.add_argument("-s", "--static", action="store_true", help="sync IPAM from static CSV file")
    parser.add_argument("-v", "--verify", action="store_true", help="verify the current IPAM subnet usage")
    parser.add_argument("-l", metavar='IP-Address', type=str, help="search for an IP address inside IPAM")
    parser.add_argument("-t", metavar='rerun-timer', type=int,
        help="define the script auto-rerun timer in minutes")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()

    # Get the current time. First one is used to tag addresses inserted/refreshed
    # Second one is used to print logging timestamp:
    time_tag = int(time.time())
    time_now = time.asctime(time.localtime(time.time()))

    # Open a log file in local directory in append mode to write the log messages into,
    # and include the current day date (YYYY-MM-DD) in the filename:
    file_name = "logfile-phpipam_sync_%s.log" % datetime.now().strftime("%Y-%m-%d")
    log_file = open(file_name, "a")
    log_file.write("\n\n**** Execution of PHPIPAM Sync Script on: %s ****\n" % time_now)

    # File open to write email log notifications if any:
    email_body = open(EMAIL_CONTENT_FILE, "w")

    # Initiate the Webex Teams API session:
    webex_teams_api = WebexTeamsAPI(access_token=TEAMS_BOT_TOKEN)

    # Authenticate/refresh the token to IPAM:
    ipam_token = ipam_get_auth_token()["token"]

    # Create the API URI for IPAM addresses (hosts):
    ipam_addresses_url = ipam_create_url("addresses")

    # If -c/--dnac input flag is set:
    if args.dnac:
        # Sync from DNAC to the IPAM DB:
        sync_from_dnac(time_tag, ipam_token, ipam_addresses_url, log_file, webex_teams_api)
        # Delete the stale dnac hosts from IPAM DB:
        delete_stale_hosts(TAG_DNAC, time_tag, ipam_token, ipam_addresses_url, log_file,
        email_body, EMAIL_CONTENT_FILE, webex_teams_api)

    # If -d/--dhcp input flag is set:
    if args.dhcp:
        # Sync from the DHCP server scopes leases to the IPAM DB:
        sync_from_ms_dhcp_server(time_tag, ipam_token, ipam_addresses_url, log_file, EMAIL_CONTENT_FILE,
            webex_teams_api)
        # Delete the stale MS DHCP hosts from IPAM DB:
        delete_stale_hosts(TAG_MSDHCP, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)
        # Sync from the IOS DHCP server:
        sync_from_ios_dhcp_server(time_tag, ipam_token, ipam_addresses_url, log_file, EMAIL_CONTENT_FILE,
            webex_teams_api)
        # Delete the stale IOS DHCP hosts from IPAM DB:
        delete_stale_hosts(TAG_IOSDHCP, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)

    # If -s/--static input flag is set
    if args.static:
        # Sync the static hosts from the CSV file STATICS_CSV_FILE to the IPAM DB:
        sync_from_static_csv(STATICS_CSV_FILE, time_tag, ipam_token, ipam_addresses_url, log_file,
            email_body, EMAIL_CONTENT_FILE, webex_teams_api)
        # Delete the stale static hosts from IPAM DB:
        delete_stale_hosts(TAG_STATIC, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)

    # If -v/--verify input flag is set:
    if args.verify:
        # Return the IPAM subnet usage:
        verify_ipam_subnet_usage(log_file, email_body, EMAIL_CONTENT_FILE)
        sys.exit(1)

    # If -l input flag is set:
    if args.l:
        # check if the argument entered is a valid IP address
        ip_address = args.l
        if not is_valid_ipv4_address(ip_address):
            print("\nInvalid argument. Please enter a valid IP address after -l.")
            sys.exit(1)

        # Search for the IP address in IPAM DB:
        ipam_search_address_response = ipam_get_url("addresses/search/%s/" %(ip_address), log_file,
        EMAIL_CONTENT_FILE)
        if ipam_search_address_response['success']:
            result = ipam_search_address_response["data"][0]
            print("\nIP address %s is present in IPAM Database:" % ip_address)
            column_names = "{0:20}{1:20}{2:50}{3:50}".format("IP address", "MAC address",
                "Hostname", "Description")
            host_mac = "N/A" if result['mac'] is None else result['mac']
            host_hostname = "N/A" if result['hostname'] is None else result['hostname']
            host_description = "N/A" if result['description'] is None else result['description']
            column_values = "{0:20}{1:20}{2:50}{3:50}\n".format(ip_address, host_mac, host_hostname,
                host_description)
            print(column_names)
            print(column_values)
        else:
            print("\nIP address %s was not found in IPAM Database." % ip_address)
        sys.exit(1)

    # If -t input flag is set:
    if args.t:
        # check if the argument entered is a valid integ
        timer_input = args.t

        # if input timer is less than 5 minutes, set the rerun_timer to 5 minutes and notify user:
        if timer_input < 5:
            print("Input timer is too agressive. Setting to the minimum recommended of 5 minutes.")
            timer_input = 5

        script_rerun_timer = timer_input

    # If no args are passed, or only the -t argument is passed:
    # Then sync from all the 3 sources and verify the IPAM subnet usage:
    if (len(sys.argv) == 1 or (args.t and len(sys.argv) == 3)):
        sync_from_dnac(time_tag, ipam_token, ipam_addresses_url, log_file, webex_teams_api)
        delete_stale_hosts(TAG_DNAC, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)
        sync_from_static_csv(STATICS_CSV_FILE, time_tag, ipam_token, ipam_addresses_url, log_file,
        email_body, EMAIL_CONTENT_FILE, webex_teams_api)
        delete_stale_hosts(TAG_STATIC, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)
        sync_from_ms_dhcp_server(time_tag, ipam_token, ipam_addresses_url, log_file, EMAIL_CONTENT_FILE,
        webex_teams_api)
        delete_stale_hosts(TAG_MSDHCP, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)
        sync_from_ios_dhcp_server(time_tag, ipam_token, ipam_addresses_url, log_file, EMAIL_CONTENT_FILE,
        webex_teams_api)
        delete_stale_hosts(TAG_IOSDHCP, time_tag, ipam_token, ipam_addresses_url, log_file, email_body,
        EMAIL_CONTENT_FILE, webex_teams_api)
        verify_ipam_subnet_usage(log_file, email_body, EMAIL_CONTENT_FILE)

    # close the open files, and send the email if email_flg is set:
    cleanup_before_exit(log_file, email_body, EMAIL_CONTENT_FILE)

    # Print message that the script will rerun in 15 minutes:
    print("\n%s: The script will rerun in %s minutes...\n" % (time.asctime(time.localtime(time.time())),
        script_rerun_timer))

if __name__ == "__main__":
    # Run the program now then repeatedly every "script_rerun_timer" minutes
    main()
    schedule.every(script_rerun_timer).minutes.do(main)
    while True:
        schedule.run_pending()
        time.sleep(1)
