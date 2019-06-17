#### phpIPAM-Sync Program:

## Business Challenge:

Many IT Teams are facing challenges tracking and managing the IP subnet usage on their networks, with lack of centralized visibility of workloads currently present on the network.

This is contributed to by many factors mainly:
- The growth in the number of endpoints on the network, from users to servers and things (IoT).
- Diversity of technology, especially with the additions of SDN and network controllers like Cisco SDA.
- Use of manual processes of managed IP addresses, commonly via some form of Excel or Smartsheet.

## Solution presented in this program:

phpIPAM-Sync is a program that tackles the business challenge described above, with the following benefits:

- Free: It feeds IP information into a free open-source IPAM (IP Address Management) solution called
phpIPAM, from multiple sources as described next.
- Ease-of-use: The requirements are very simple to setup and users can very easily get the program running.
- Extensible: Modular program which can easily be extended to add additional sources/functionality.

## Description:

This is a program to synchronize a PHPIPAM server with addresses (hosts) from multiple sources being:
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

The program includes a built-in scheduler to run the rerun the program every 15 minutes.
This way you do not need to use a separate cron job to schedule it.

## Usage

1. Copy the "env_file_template.py" and rename the copy to "env_file.py". Then update the variables in env_file.py with the correct values for the DNA-Center, PHPIPAM, MS and IOS DHCP servers, and CSV file.

2. Run the script phpipam_sync.py to perform the synchronization of hosts information into PHPIPAM server from the sources (DNA-Center, Static, DHCP-Server):
- If no parameters are specified: the sync will be made from all the sources, and a verification of the resulting IPAM subnet usage is returned.
- Parameters can be specified to chose the sync sources and/or to just return the subnet usage.

(phpipam-venv) cyoussef:$python phpipam_sync.py -h
usage: phpipam_sync.py [-h] [-c] [-d] [-s] [-v] [-l IP-Address] [-t rerun-timer]

Sync IPAM server from DNA Center, DHCP server and/or static hosts in CSV file.
If no arguments are passed, the default is to sync from all 3 sources.

optional arguments:

  -h, --help     show this help message and exit

  -c, --dnac     sync IPAM from DNA Center

  -d, --dhcp     sync IPAM from MS DHCP Server

  -s, --static   sync IPAM from static CSV file

  -v, --verify   verify the current IPAM subnet usage

  -l IP-Address  search for an IP address inside IPAM

  -t rerun-timer  define the script auto-rerun timer in minutes

(phpipam-venv) cyoussef:$


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
