
██████╗ ██╗███╗   ██╗ ██████╗ ██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██║████╗  ██║██╔════╝ ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
██████╔╝██║██╔██╗ ██║██║  ███╗██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║
██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║
██║     ██║██║ ╚████║╚██████╔╝██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                     


## Introduction

This repository provides an automated solution for setting up and configure a gaming  firewall with advanced configurations using Ansible. It allows administrators to deploy, manage, and maintain consistent firewall rules and settings across multiple Linux-based hosts, utilizing Ansible's powerful automation capabilities.

### Repository Structure

* `generate.sh`: Helper script for initiating configuration.
* `ansible-firewall/`: Directory containing Ansible playbooks and roles.

  * `bootstrap.yml`: Initializes the environment and installs necessary prerequisites.
  * `requirements.yml' : Installs Ansible Galaxy/Collections requirements
  * `setup.yml' : Initial Ubuntu vm setup,package install, Pihole install, then can be used to update floating settingsd(as an example, Pihole setting files/dhcp settings and adlist)
  * `firewall.yml' : Sets up and updates firewall, QoS and interfaces configuaration
  * `diag_firewall.sh`: Script for diagnosing firewall settings and issues.
  * `group_vars/`: Contains group-specific variables.
  * `inventory/hosts`: Inventory file listing managed hosts.
  * `roles/firewall`: Role for firewall-specific tasks and configurations.


## Requirements

* Ansible (ensure it is installed and accessible on your system).
* SSH access to target firewall hosts.

## Usage

1. Clone the repository:

```bash
git clone <repository_url>
cd ansible-firewall
```

2. Install required Ansible roles and dependencies:

```bash
ansible-galaxy install -r requirements.yml
```

3. Edit inventory file (`inventory/hosts`) to match your environment.

Remember to set up correctly your IP range, your NICs name from your Ubuntu install.

All tethering will be automatically assigned the WAN NIC name you choose.

4. Modify variables in `group_vars/` to fit your specific firewall requirements.

5. Run the main playbook to deploy configurations:

```bash
ansible-playbook -i inventory/hosts setup.yml
then 
ansible-playbook -i inventory/hosts firewall.yml

You can use any IP you want to first connect to the Ubuntu VM/Rpi/SBC, it will switch to the IP you set up for the LAN interface only after a reboot(to ensure that you don't lose connection towards it with ansible)

```

## Diagnostics

To diagnose firewall settings, use the provided script:

```bash
./diag_firewall.sh
```

## nDPI Setup
WIP, not functional, don't run this


nDPI is installed automatically by the Ansible playbook. Ensure the
`ndpi` role is listed in `site.yml` and run the playbook against your
hosts:

```bash
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
