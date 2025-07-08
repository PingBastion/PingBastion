#!/usr/bin/env bash
set -e
ROOT=ansible-firewall

# Scaffold
mkdir -p \
  "$ROOT"/{inventory,group_vars,host_vars} \
  "$ROOT"/roles/firewall/{tasks,templates,handlers}

touch "$ROOT"/inventory/hosts                          # inventory stub

cat >"$ROOT"/group_vars/all.yml <<'YAML'
ansible_python_interpreter: /usr/bin/python3
ansible_shell_executable: /bin/bash
YAML

# Basic playbook skeleton
cat >"$ROOT"/site.yml <<'YAML'
- name: Configure Firewalls
  hosts: firewalls
  roles:
    - firewall
YAML

echo "Project skeleton generated in $ROOT/"
