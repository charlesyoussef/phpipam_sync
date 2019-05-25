## PHPIPAM Sync:

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

The Role-based Access Control (RBAC) on the subnet management is natively built
inside PHPIPAM which can be consumed from the server Web interface.
Phpipam IPAM server sync from DNA-Center, Microsoft-Server & IOS DHCP Servers, and static hosts in a CSV file:

---

## Usage

1. Copy the "env_file_template.py" and rename the copy to "env_file.py". Then update the variables in env_file.py with the correct values for the DNA-Center, PHPIPAM, MS and IOS DHCP servers, and CSV file.

2. Run the script phpipam_sync.py to perform the synchronization of hosts information into PHPIPAM server from the sources (DNA-Center, Static, DHCP-Server):
- If no parameters are specified: the sync will be made from all the sources, and a verification of the resulting IPAM subnet usage is returned.
- Parameters can be specified to chose the sync sources and/or to just return the subnet usage.

(phpipam-venv) cyoussef:$python phpipam_sync.py -h
usage: phpipam_sync.py [-h] [-c] [-d] [-s] [-v] [-l IP-Address]

Sync IPAM server from DNA Center, DHCP server and/or static hosts in CSV file.
If no arguments are passed, the default is to sync from all 3 sources.

optional arguments:
  -h, --help     show this help message and exit
  -c, --dnac     sync IPAM from DNA Center
  -d, --dhcp     sync IPAM from MS DHCP Server
  -s, --static   sync IPAM from static CSV file
  -v, --verify   verify the current IPAM subnet usage
  -l IP-Address  search for an IP address inside IPAM
(phpipam-venv) cyoussef:$

---

## Installation & prerequisites

It is recommended to install the Python dependencies in a new virtual environment based on Python 3.6 or above. For information on setting up a virtual environment please check:
http://docs.python-guide.org/en/latest/dev/virtualenvs/

Python package prerequisites in "requirements.txt" file which is located in the root directory of this distribution. To install them:
$ pip install -r requirements.txt


## Authors & Maintainers

Charles Youssef <cyoussef@cisco.com>

## Credits

- pierrecdn@docker for the PHPIPAM server and Database docker container images:
https://hub.docker.com/r/pierrecdn/phpipam/

- Jordan Borean for the PSRP Python client for Powershell Remoting Protocol which was used to integrate with MS DHCP Server:
https://pypi.org/project/pypsrp/


## License

This project is licensed to you under the terms of the [Cisco Sample Code License](./LICENSE).
