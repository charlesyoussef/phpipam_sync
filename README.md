# PHPIPAM Sync
Phpipam IPAM server sync from DNA-Center, Microsoft-Server DHCP Server, and static hosts in a CSV file:

This script automatically syncs to the specified IPAM server subnet:
- DNA-Center hosts
- Leased hosts from the Microsoft DHCP server scope list
- Static hosts from CSV file  

It also deletes any stale hosts (addresses in IPAM terms) from the corresponding Phpipam subnet
that were not refreshed in the last script run.

The RBAC control on the subnet management is natively built inside Phpipam,
which can be easily consumed from the Web interface of Phpipam.

---

## Usage

1. Copy the "env_lab_template.py" and rename the copy to "env_lab.py". Then update the variables in env_lab.py with the correct values for the DNA-Center, PHPIPAM, MS-DHCP servers and CSV file.

2. Run the script phpipam_sync.py to perform the synchronization of hosts information into PHPIPAM server from the sources (DNA-Center, Static, DHCP-Server):
- If no parameters are specified: the sync will be made from all the sources, and a verification of the resulting IPAM subnet usage is returned.
- Parameters can be specified to chose the sync sources and/or to just return the subnet usage.

$ python phpipam_sync.py -h

usage: phpipam_sync.py [-h] [-c] [-d] [-s] [-v]

Sync IPAM server from DNA Center, DHCP server and/or static hosts in CSV file.
If no arguments are passed, the default is to sync from all 3 sources.

optional arguments:

  -h, --help    show this help message and exit
  
  -c, --dnac    sync IPAM from DNA Center
  
  -d, --dhcp    sync IPAM from MS DHCP Server
  
  -s, --static  sync IPAM from static CSV file 'hosts.csv'
  
  -v, --verify  verify the current IPAM subnet usage
  
$

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
