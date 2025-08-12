## Introduction

This repository provides an automated solution for setting up and configuring a gaming-focused firewall with advanced traffic management using **Ansible**. In addition to standard firewall rules, it leverages a **dnsmasq** and **ipsets** combination to further classify and control traffic, allowing for fine-grained prioritization, filtering, and categorization based on DNS lookups.

With this approach, administrators can deploy, manage, and maintain consistent firewall rules and settings across multiple Linux-based hosts while automatically mapping specific domains or traffic categories into ipsets for efficient filtering and QoS handling. All of this is orchestrated through Ansible’s powerful automation capabilities, ensuring reproducibility and ease of maintenance.

---

### Repository Structure

* `generate.sh`: Helper script for initiating configuration.
* `ansible-firewall/`: Directory containing Ansible playbooks and roles.

  * `bootstrap.yml`: Initializes the environment and installs necessary prerequisites.
  * `requirements.yml`: Installs Ansible Galaxy/Collections requirements.
  * `setup.yml`: Performs initial Ubuntu VM setup, package installation, Pi-hole installation, and updates to floating settings (e.g., Pi-hole setting files, DHCP settings, and adlists).
  * `firewall.yml`: Configures and updates firewall, QoS, interface configuration, **dnsmasq**, and **ipsets** rules for traffic classification.
  * `diag_firewall.sh`: Script for diagnosing firewall settings and issues.
  * `group_vars/`: Contains group-specific variables.
  * `inventory/hosts`: Inventory file listing managed hosts.
  * `roles/firewall`: Role for firewall-specific tasks and configurations.

---

## Requirements

* Ansible (ensure it is installed and accessible on your system).
* SSH access to target firewall hosts.

---

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

3. Edit the inventory file (`inventory/hosts`) to match your environment.

   Make sure to correctly configure your IP range and NIC names from your Ubuntu install.
   All tethering will be automatically assigned to the WAN NIC name you choose.

4. Modify variables in `group_vars/` to fit your specific firewall and traffic classification requirements.

5. Run the main playbooks to deploy configurations:

```bash
ansible-playbook -i inventory/hosts setup.yml
ansible-playbook -i inventory/hosts firewall.yml
```

> You can use any IP you want to initially connect to the Ubuntu VM/RPi/SBC; it will switch to the IP you set up for the LAN interface only after a reboot (to ensure you don’t lose connection with Ansible during setup).

---

## Diagnostics

To diagnose firewall settings, use the provided script:

```bash
./diag_firewall.sh
```

---

## How dnsmasq + ipsets Classification Works

This setup uses **dnsmasq** to monitor and log DNS queries passing through the firewall. Specific domain patterns (such as gaming servers, streaming services, or ad networks) are matched and automatically assigned to **ipsets** — kernel-managed IP address sets used by `iptables`/`nftables` for fast lookups.

**Workflow:**

1. **dnsmasq** resolves DNS queries and matches domains against configured rules.
2. When a match occurs, the resolved IP is added to an ipset.
3. **Firewall rules** then apply different policies to each ipset, enabling:

   * Traffic prioritization (e.g., low-latency routing for gaming domains).
   * Selective blocking or filtering (e.g., ad/malware domains).
   * Category-based shaping (e.g., throttling large downloads during peak hours).

This method ensures domain-based filtering remains accurate even when IPs change, as ipsets are dynamically updated from DNS lookups in real-time.

**Example dnsmasq + ipset rule:**

```ini
# /etc/dnsmasq.d/ipset.conf
domain-set=examplegame.com,gaming_servers
ipset=/examplegame.com/gaming_servers
```

**Example iptables rule using the ipset:**

```bash
iptables -A OUTPUT -m set --match-set gaming_servers dst -j MARK --set-mark 10
```

This ensures that any traffic to `examplegame.com` will automatically be marked for high-priority handling.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
