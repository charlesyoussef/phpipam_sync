"""Variables are stored in this file.
    Please fill the values for these variables before you run the main script.
"""

DNA_CENTER = {
    "host": "", #String
    "port": , #Integer
    "username": "", #String
    "password": "" #String
}

PHPIPAM = {
    """
    - The app_id is defined when creating the API application profile in PHPIPAM settings.
    - The subnetId is the PHPIPAM identifier of the parent subnet in which the hosts will be sync into
    from the other sources via this project.
    For more info on these fields and PHPIPAM API & administration please check:
    https://phpipam.net/api/api_documentation/
    """
    "host": "", #String
    "port": , #Integer
    "username": "", #String
    "password": "", #String
    "app_id": "", #String
    "subnetId": , #Integer
}

MS_DHCP_SERVER = {
    "fqdn": "", #String
    "username": "", #String
    "password": "", #String
    "ssl": , #Boolean
    "scopes": ["", ""] #List of strings, for example: ["10.1.1.0", "10.1.2.0"]
    # scopes is a list of strings of all the dhcp scope subnets to be tracked via this project.
}

IOS_DHCP_SERVER = {
    "switch": "", #String
    "ssh_port": , #Integer
    "username": "", #String
    "password": "" #String
}

STATIC_HOSTS_CSV_FILE = {
    "path": "" #String
    """This is the CSV file where the static hosts are saved.
    The order of the host properties in the CSV file should be:
    IP_address, description, hostname, MAC_address
    For example, one sample entry would be:
    10.255.255.1,Static Host 1,StaticHost1,00:00:11:11:25:51
    """
}

EMAIL_PROPERTIES = {
    "mail_server": "", #String
    "from_address": "", #String
    "to_address_list": "", #String
    "email_subject": "", #String
    "email_content_tempfile": "email_content.log" #String 
    # email_content_tempfile is the base of the local-directory file where logs are saved
}
