"""Variables are stored in this file.
"""

DNA_CENTER = {
    "host": "10.113.108.31",
    "port": 443,
    "username": "ixc",
    "password": "Cisco123"
}

# This is the devnet sandbox DNAC:
"""
DNA_CENTER = {
    "host": "sandboxdnac.cisco.com",
    "port": 443,
    "username": "devnetuser",
    "password": "Cisco123!"
}
"""

PHPIPAM = {
    "host": "10.113.108.199",
    "port": 80,
    "username": "admin",
    "password": "dy}9Jw:BSa",
    "app_id": "dnac",
    "subnetId": 7,
    "delimiter_string": "----"
    #The last field is used to separate the "source" and "timestamp" in the "note" field  of hosts
    #added into IPAM server via this project. It should be excluded from "note" field for hosts
    #manually added to IPAM or via other means besides this project.
}

MS_DHCP_SERVER = {
    "fqdn": "mea-cisco-demos-dns2.cisco.com",
    "username": "cyoussef",
    "password": "Cisco123",
    "ssl": False,
    "scopes": ["10.113.108.0", "10.113.110.0"]
    #The last field is a python list of all the scopes to be tracked at the specified DHCP server.
}

IOS_DHCP_SERVER = {
    "switch": "10.113.104.254",
    "ssh_port": 22,
    "username": "ixc",
    "password": "Cisco123"
}


STATIC_HOSTS_CSV_FILE = {
    "path": "hosts.csv"
    #This is the CSV file where the static hosts are saved.
    #Host fields are listed in this order:
    #IP_address, description, hostname, MAC_address
}
