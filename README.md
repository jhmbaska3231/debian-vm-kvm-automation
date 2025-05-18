# KVM/QEMU Debian VM Toolkit

A production-ready collection of shell scripts for automated creation, configuration, and management of Debian virtual machines on KVM/QEMU hosts with network isolation.

## Key Features
- **Automated Network Creation**: Dynamically finds available bridges and assigns unique subnets
- **Smart VM Provisioning**: Template-based creation with linked clones, full copies, and automatic disk expansion
- **Complete Network Isolation**: Each VM gets dedicated network, subnet, and firewall rules
- **First-Boot Automation**: Auto-configures hostname, SSH keys, machine-ID, and filesystem expansion
- **Dual Internet Access**: VPN-preferred routing with direct internet fallback
- **Simple Hardening**: SSH key regeneration, disabled root login and password authentication
- **Complete Cleanup**: Safe removal of VMs, networks, UFW rules, and DHCP leases

## Quick Start

### Prerequisites
- Debian-based Linux host with KVM/QEMU installed
- Base qcow2 template with these packages pre-installed:
  - `cloud-guest-utils`
  - `lvm2`
  - `e2fsprogs`
- Mullvad VPN installed on host (for DNS forwarding)
  - *Note: If using another VPN provider, edit the DNS forwarding sections accordingly*
```

### Usage Workflow
1. Set up isolated virtual network
sudo ./create_vm_network_normal.sh --name myvm-net

2. Configure UFW firewall rules for VM network
sudo ./configure_host_ufw_normal.sh --network myvm-net

3. Create VM from template (edit script variables first)
sudo ./create_debian_vm.sh myvm 4096 2 20 linked

4. (Optional) Remove VM, network, and associated configurations when no longer needed
sudo ./delete_vm_and_cleanup.sh --vm myvm
```

## Ideal For
- **Development Environments**: Consistent, isolated VM setups
- **Homelab Automation**: Multi-VM deployments with network segmentation  
- **Cloud Infrastructure**: Scalable VM provisioning on dedicated servers
