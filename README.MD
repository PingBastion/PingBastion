# PingBastion

PingBastion turns a vanilla Ubuntu system into a firewall appliance with an
emphasis on **smooth gaming**.  The included playbooks configure
nftables-based filtering, Netplan interface definitions, Docker & Pi‑hole and a
CAKE QoS setup optimised for low latency.

The repository contains everything needed to bootstrap a fresh machine and keep
the configuration reproducible.  All logic lives inside Ansible roles so it can
be applied over and over again without manual tweaking.

## Why “smooth gaming”?

Lag spikes ruin online games.  PingBastion applies
[CAKE](https://www.bufferbloat.net/projects/codel/wiki/Cake/) traffic shaping on
both the WAN and LAN interfaces to curb bufferbloat and prioritise small control
packets.  Values for bandwidth, RTT and DSCP mappings are defined in
`group_vars/` so they are easy to tune for your own connection speed.

## Repository layout

- `generate.sh` – bootstrap script that creates an empty project layout.
- `ansible-firewall/`
  - `bootstrap.yml` – controller setup (installs `sshpass`, populates
    `known_hosts`).
  - `setup.yml` – initial package install, Docker engine and Pi‑hole deployment.
  - `firewall.yml` – applies nftables rules, Netplan configuration and QoS.
  - `diag_firewall.sh` – connectivity diagnostics to run on the target host.
  - `group_vars/` – example variables for firewall rules and CAKE settings.
  - `inventory/` – sample hosts file.
  - `roles/` – implementation of the `first_setup` and `firewall` roles.
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

## How to use

1. Clone the repository and install dependencies:
   ```bash
   git clone <repository_url>
   cd PingBastion/ansible-firewall
   ansible-galaxy install -r requirements.yml
   ```
2. Adjust `inventory/hosts` and the YAML files under `group_vars/`.
   The `firewall_cfg` structure controls interface names, address ranges,
   nftables policy, DSCP classes and CAKE limits.
3. Bootstrap the controller (optional but handy if using password auth):
   ```bash
   ansible-playbook bootstrap.yml -i inventory/hosts
   ```
4. Run the initial setup which installs required packages, Docker and Pi‑hole:
   ```bash
   ansible-playbook setup.yml -i inventory/hosts
   ```
5. Apply the firewall rules and QoS configuration:
   ```bash
   ansible-playbook firewall.yml -i inventory/hosts
   ```

### Customising the firewall

Firewall behaviour is driven by variables under `group_vars/`.  The main file
`firewalls.yml` documents every option – interface names, NAT, default policies
and a list of simple allow/deny rules.  DSCP classes can be defined to mark
traffic which the CAKE qdisc will then prioritise.

The `first_setup` role also contains tasks to install Pi‑hole either natively or
through Docker Compose.  Adjust settings such as `pihole_timezone` and
`pihole_webpassword` in `roles/first_setup/defaults/main.yml` or override them in
group vars.

### Diagnostics

`diag_firewall.sh` can be executed on a deployed firewall to verify link state,
addressing, routing, DNS and NAT configuration.  Example:
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
ssh root@<firewall-ip> 'bash -s' < diag_firewall.sh | tee diag.log
iptables -A OUTPUT -m set --match-set gaming_servers dst -j MARK --set-mark 10
```

### Experimental nDPI role

An unfinished role for traffic classification via nDPI exists but is disabled by
default.  Uncomment the `ndpi` line in `firewall.yml` to experiment.

This ensures that any traffic to `examplegame.com` will automatically be marked for high-priority handling.

---

## License

PingBastion is released under the MIT License.  See [LICENSE](LICENSE) for
details.
