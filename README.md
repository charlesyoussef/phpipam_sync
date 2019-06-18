#### phpIPAM-Sync Program:

## Business Challenge

Many IT Teams are facing challenges tracking and managing the IP subnet usage on their networks, with lack of centralized visibility of workloads currently present on their network.

Many factors contribute to this situation, including:
- Growth in the number of endpoints on the network, from users to servers and IoT devices
- Diversity of technology, especially with the addition of SDN and network controllers, like Cisco SDA
- Use of manual processes to manage IP addresses, commonly via some form of Excel or Smartsheet

## Proposed Solution

phpIPAM-Sync is a program that tackles the business challenge described above, featuring the following benefits:

- Free: it feeds IP information into a free open-source IPAM (IP Address Management) solution called
[phpIPAM](https://phpipam.net/), from multiple sources as described in the following sections
- Ease of use: the requirements are very simple to setup and users can very easily get the solution running
- Extensible: it is a modular program that can be easily extended to add additional sources/functionality

## Description

This is a program to synchronize a phpIPAM server with addresses (hosts) from multiple sources, including:
- [Cisco DNA Center](https://www.cisco.com/c/en/us/products/cloud-systems-management/dna-center/index.html)
- Microsoft DHCP Server
- Cisco DHCP Server running on Cisco IOS switch
- Static hosts defined in a CSV file

[phpIPAM](https://phpipam.net/) is a free open source IP Address Management (IPAM) solution.

The prerequisite is to have the parent IP subnet created in phpIPAM database.

The synchronization consists of both:
- Adding new addresses (hosts) that are discovered but not present in IPAM database
- Deleting stale addresses (hosts) that used to exist but are not anymore advertised by the same source(s) in the last program execution

Whenever an address (host) is added or deleted from the phpIPAM database, notifications are made via:
- Log entry added to a log text file in local directory
- Message  posted in a Webex Teams space
- Single email sent with the list of added & deleted hosts, at the end of the program execution

The Role-based Access Control (RBAC) on the subnet management is natively built inside phpIPAM, which can be consumed from the server Web interface.

The program includes a built-in scheduler to rerun the program every X minutes, where X has a default value of 15, but it can be set via user input at run time (in which case the minimum allowed value is 5). This feature simplifies how to use the program, avoiding the requirement of a separate cron job to schedule running the program.

## Usage

1. Copy the "env_file_template.py" and rename the copy to "env_file.py". Then update the variables in "env_file.py" with the correct values for your DNA-Center, PHPIPAM, MS and IOS DHCP servers, and CSV file.

2. Run the script "phpipam_sync.py" to perform the synchronization of hosts information from the sources (DNA-Center, Static, DHCP-Server) to the phpIPAM server:
- If no parameters are specified the sync will be performed from all sources, and it will return a verification of the resulting IPAM subnet usage 
- Parameters can be specified to choose the sync sources and/or to just return the subnet usage

```
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

  -t rerun-timer  define the script auto-rerun timer in minutes. Default is 15; Minimum allowed is 5 

(phpipam-venv) cyoussef:$
```

## Installation & prerequisites

It is recommended to install the Python dependencies in a new virtual environment based on Python 3.6 or above. For information on setting up a virtual environment please check:
http://docs.python-guide.org/en/latest/dev/virtualenvs/

Python package prerequisites are defined in the "requirements.txt" file, located in the root directory of this distribution. To install them:

```
$ pip install -r requirements.txt
```

## Authors & Maintainers

Charles Youssef <cyoussef@cisco.com>

## Credits

- pierrecdn@docker for the phpIPAM server and Database docker container images:
https://hub.docker.com/r/pierrecdn/phpipam/

- Jordan Borean for the PSRP Python client for Powershell Remoting Protocol which was used to integrate with MS DHCP Server:
https://pypi.org/project/pypsrp/


## License

This project is licensed to you under the terms of the [Cisco Sample Code License](./LICENSE).
