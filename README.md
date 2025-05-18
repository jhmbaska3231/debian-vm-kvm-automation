# KVM/QEMU Debian VM Toolkit

A production-ready collection of shell scripts for automated creation, configuration, and management of Debian virtual machines on KVM/QEMU hosts with network isolation.

## Key Features

- **Automated Network Creation**: Dynamically finds available subnets and bridge interfaces
- **Smart VM Provisioning**: Supports both linked clones and full copies with automatic disk expansion
- **Network Isolation**: Each VM gets its own dedicated network with unique subnet and firewall rules
- **First-Boot Automation**: Auto-configures hostname, SSH keys, machine-ID, and filesystem expansion
- **VPN Integration**: Seamless routing through Mullvad VPN with direct internet fallback
- **Complete Cleanup**: Safe removal of VMs, networks, UFW rules, and DHCP leases

## Architecture

### Network Isolation
- **Dynamic Bridge Assignment**: Automatically finds next available bridge (virbr0, virbr1, virbr2...)
- **Subnet Auto-Discovery**: Scans existing networks to assign unique subnets (192.168.100.0/24+)
- **Dual Internet Access**: VPN-preferred routing with automatic direct internet fallback
- **DNS Forwarding**: Built-in DNS resolution validation

### VM Lifecycle Management
- **Template-Based**: Creates VMs from qcow2 templates with intelligent cloning
- **Resource Validation**: Enforces minimum requirements and validates host capacity  
- **Disk Management**: Automatic filesystem expansion for resized disks (LVM & standard partitions)
- **Security Hardening**: SSH key regeneration, root login disabled, password auth disabled

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
```bash
# 1. Create isolated network
sudo ./create_vm_network_normal.sh --name myvm-net

# 2. Configure firewall rules
sudo ./configure_host_ufw_normal.sh --network myvm-net

# 3. Create VM (edit script variables first)
sudo ./create_debian_vm.sh myvm 4096 2 20 linked

# 4. Clean up when done (optional)
sudo ./delete_vm_and_cleanup.sh --vm myvm
```

## Script Details

### 1. `create_vm_network_normal.sh`
- Auto-detects next available bridge and subnet
- Configures NAT forwarding with port range 1024-65535
- Enables network autostart and validates DNS functionality
- **Usage**: `sudo ./create_vm_network_normal.sh --name <network_name>`

### 2. `configure_host_ufw_normal.sh`  
- Detects physical and VPN interfaces automatically
- Creates precise UFW rules for VM subnet traffic
- Supports both Mullvad VPN and direct internet routing
- Disables IPv6 for enhanced security
- **Usage**: `sudo ./configure_host_ufw_normal.sh --network <network_name>`

### 3. `create_debian_vm.sh`
- Creates linked clones or full copies from templates
- Handles both LVM and standard partition expansion
- Generates unique hostnames and regenerates SSH keys
- Configures network interfaces with private MAC addresses
- **Usage**: `sudo ./create_debian_vm.sh <name> <ram_MB> <vcpus> <disk_GB> [linked|full]`
- **Note**: Edit `TEMPLATE_IMAGE`, `NETWORK`, and `--os-variant` variables before use

### 4. `delete_vm_and_cleanup.sh`
- Safely removes VMs with snapshot handling
- Cleans up dedicated networks and UFW rules  
- Removes DHCP leases and validates complete cleanup
- Preserves base images for linked clones
- **Usage**: `sudo ./delete_vm_and_cleanup.sh --vm <vm_name>`

## Ideal For

- **Development Environments**: Consistent, isolated VM setups
- **Homelab Automation**: Multi-VM deployments with network segmentation  
- **Cloud Infrastructure**: Scalable VM provisioning on dedicated servers
