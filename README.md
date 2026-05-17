# KVM/QEMU Debian VM Toolkit

A production ready set of shell scripts for automated creation, configuration, and management of debian virtual machines on kvm/qemu hosts with network isolation

## Features

- **automated network creation**: dynamically finds available bridges and assigns unique subnets
- **smart vm provisioning**: template based creation with linked clones or full copies, and automatic disk expansion
- **complete network isolation**: each vm gets a dedicated network, subnet, and firewall rules
- **firstboot automation**: auto configures hostname, ssh keys, machine-id, network interface (netplan or legacy /etc/network/interfaces), and filesystem expansion supporting lvm and standard partitions including mbr extended/logical layouts
- **dual internet access**: vpn preferred routing with direct internet fallback
- **simple hardening**: ssh key regeneration, disabled root login and password authentication
- **complete cleanup**: safe removal of vm, snapshots, networks, ufw rules, and dhcp leases

---

## Prerequisites

### Host requirements

- a debian based linux host with these installed:
  ```bash
  sudo apt install qemu-kvm qemu-utils libvirt-clients libvirt-daemon-system libguestfs-tools virtinst ufw dnsutils
  ```

### Base qcow2 template

- a pre built debian qcow2 image with these installed (firstboot script can also install them but requires internet access):
  ```bash
  sudo apt install cloud-guest-utils lvm2 e2fsprogs
  ```

> note password auth and root login are disabled on first boot so template should already have ssh pub key in ~/.ssh/authorized_keys

### Mullvad or other vpn (optional)

- configure_host_ufw_normal.sh detects mullvad's tunnel interface automatically and adds a vpn routing rule if found, else it configures direct internet access only
- dns forwarding for vm is handled by libvirt's dnsmasq

> note edit the vpn interface section to match your vpn

---

## Script configuration

first edit these variables inside create_debian_vm.sh to match your environment

| Variable | Description |
|---|---|
| TEMPLATE_IMAGE | path to base qcow2 template |
| NETWORK | match network name created in step 1 |
| --os-variant | adjust to distro/version |
| renderer (in netplan config) | NetworkManager or networkd |

---

## Usage workflow

```bash
# 1. create an isolated virtual network
sudo ./create_vm_network_normal.sh --name yourvm-net

# 2. configure ufw firewall rules for the new network
sudo ./configure_host_ufw_normal.sh --network yourvm-net

# 3. create vm from template (edit script variables first)
sudo ./create_debian_vm.sh yourvm yourram yourvcpu yourstorage clonetype  # e.g. sudo ./create_debian_vm.sh yourvm 4096 2 20 linked|full

# 4. (optional) remove the vm, its network, and all associated configuration
sudo ./delete_vm_and_cleanup.sh --vm yourvm
```

> note firstboot log at /var/log/firstboot-config.log

---

## Ideal for

- **development environments**: consistent, isolated vm setups
- **homelab automation**: multi vm deployments with network segmentation
- **cloud infrastructure**: scalable vm provisioning on dedicated servers
