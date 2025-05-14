# KVM/QEMU Debian VM Toolkit

A comprehensive collection of production-ready shell scripts for automated creation and configuration of Debian virtual machines on KVM/QEMU hosts.

## Features

- **Isolated VM Networks**: Create secure, NAT-based virtual networks with separate subnets
- **Automated VM Provisioning**: Clone and configure VMs from base qcow2 templates
- **Custom Firewall Rules**: Apply specific UFW firewall configurations per VM network
- **First-Boot Optimization**: Automatically prepare VMs with proper networking, hostname, and SSH keys

## Network Architecture

This toolkit implements network isolation using:
- Multiple virtual bridges (virbr0, virbr1, virbr2, etc.)
- Unique subnet per VM (192.168.122.0/24, 192.168.123.0/24, etc.)
- Dedicated firewall rules for each network segment
- Proper DNS resolution with VPN integration

## Requirements

- Debian-based Linux host with KVM/QEMU installed
- Base qcow2 template with these packages pre-installed:
  - `cloud-guest-utils`
  - `lvm2`
  - `e2fsprogs`
- Mullvad VPN installed on host (for DNS forwarding)
  - *Note: If using another VPN provider, edit the DNS forwarding sections accordingly*

## Included Scripts

1. **create_vm_network_normal.sh** - Sets up isolated virtual networks
2. **configure_host_ufw_normal.sh** - Configures UFW firewall rules for VM networks
3. **create_debian_vm.sh** - Provisions VMs from templates with automatic configuration
4. **delete_vm_and_cleanup.sh** - Removes VM networks and associated configurations

## Ideal For

- Developers needing consistent VM environments
- Homelab enthusiasts building multi-VM setups
- Cloud server administrators requiring isolated VM deployments
