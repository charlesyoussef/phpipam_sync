"""Variables are stored in this file.
    Please fill the values for these variables before you run the main script.
"""

DNA_CENTER = {
    "host": "", #example: "dnac.abc.com" or "192.168.10.10"
    "port": , #example 80
    "username": "", #example "admin"
    "password": "" #example "dftgh1!"
}

PHPIPAM = {
    """
    - The app_id is defined when creating the API application profile in PHPIPAM settings.
    - The subnetId is the PHPIPAM identifier of the parent subnet in which the hosts will be sync into
    from the other sources via this project.
    For more info on these fields and PHPIPAM API & administration please check:
    https://phpipam.net/api/api_documentation/
    """
    "host": "", #example "ipam.abc.com" or "192.168.10.10"
    "port": , #Example 80
    "username": "", #example "admin"
    "password": "", #example "dftgh1!"
    "app_id": "", #example "dnac_app" or "100"
    "subnetId": , #example 10
}

MS_DHCP_SERVER = {
    "fqdn": "", #example "dhcp-server.abc.com" or "192.168.10.10"
    "username": "", #example "admin"
    "password": "", #example "dftgh1!"
    "ssl": , #example False or True
    "scopes": ["", ""] #example: ["10.1.1.0", "10.1.2.0"]
    # scopes is a list of strings of all the dhcp scope subnets to be tracked via this project.
}

IOS_DHCP_SERVER = {
    "switch": "", #example "switch.abc.com" or "192.168.10.10"
    "ssh_port": , #example 22
    "username": "", #example "admin"
    "password": "" #example "dftgh1!"
}

STATIC_HOSTS_CSV_FILE = {
    "path": "" #example "hosts.csv"
    """This is the CSV file where the static hosts are saved.
    The order of the host properties in the CSV file should be:
    IP_address, description, hostname, MAC_address
    For example, one sample entry would be:
    10.255.255.1,Static Host 1,StaticHost1,00:00:11:11:25:51
    """
}

EMAIL_PROPERTIES = {
    "mail_server": "", #example "mail.abc.com" or "192.168.10.10"
    "from_address": "", #example "noreply@abc.com"
    "to_address_list": "", #example "network-team@abc.com"
    "email_subject": "", #example "PHPIPAM Address Updates"
    "email_content_tempfile": "" #example "email_content.log"
    # email_content_tempfile is the base of the local-directory file where logs are saved
}

WEBEX_TEAMS = {
    "room_id": "", # ID of the Webex Teams space where notifications will be posted
    "bot_token": "" #Token of the Webex teams bot whose identity will be used to post messages
    # For help on getting those fields, please check: https://developer.webex.com/docs/api/getting-started
}
