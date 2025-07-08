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
```bash
ssh root@<firewall-ip> 'bash -s' < diag_firewall.sh | tee diag.log
```

### Experimental nDPI role

An unfinished role for traffic classification via nDPI exists but is disabled by
default.  Uncomment the `ndpi` line in `firewall.yml` to experiment.

## License

PingBastion is released under the MIT License.  See [LICENSE](LICENSE) for
details.
