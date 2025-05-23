#!/bin/bash
# Create KVM VM from QCOW2 template script
#
# *important: manually change the TEMPLATE_IMAGE, NETWORK and "--os-variant" flag
# variables to match
#
# This script automates KVM debian based VM creation from a template:
# - creates VM from existing qcow2 template (linked clone or full copy)
# - resizes the disk if requested (outside expansion)
# - automatically configures machine-id and hostname
# - handles filesystem expansion for resized disks (inside expansion)
# - regenerates SSH keys and network identifiers
# - validates resource requirements to ensure VM stability
#
# Usage: make script executable and run:
# chmod +x create_debian_vm.sh
# sudo ./create_debian_vm.sh <vm_name> <ram_in_MB> <vcpus> <disk_size_GB> <linked / full>
# *e.g. sudo ./create_debian_vm.sh my_debian_vm 4096 2 20 linked
#
# -------------------------------------------------------------------------------

# Exit on any error
set -e
trap 'echo "ERROR: Command failed at line $LINENO: $BASH_COMMAND"' ERR

# Define variables that can be customized
IMAGES_DIR="/var/lib/libvirt/images"
TEMPLATE_IMAGE="${IMAGES_DIR}/<template>.qcow2" # Change to chosen qcow2 template
NETWORK="default"  # Change to chosen virtual network name

# Resource limits
MIN_RAM=512        # Minimum RAM in MB
MIN_VCPUS=1        # Minimum vCPUs
MIN_DISK_SIZE=5    # Minimum disk size in GB
MAX_VCPUS=$(nproc) # Maximum vCPUs (defaults to host CPU count)

# Setup cleanup on error
cleanup() {
    local exit_code=$?
    echo "Cleaning up temporary files..."
    
    # Remove temporary script if it exists - using variable for safety
    if [ -n "$FIRSTBOOT_SCRIPT" ] && [ -f "$FIRSTBOOT_SCRIPT" ]; then
        secure_delete "$FIRSTBOOT_SCRIPT"
    fi
    
    # Only remove VM and disk if they were created during this run
    if [ "$SETUP_STARTED" = true ]; then
        echo "Removing partially created VM due to error..."
        virsh destroy "${VM_NAME}" &>/dev/null || true
        virsh undefine "${VM_NAME}" &>/dev/null || true
        rm -f "${VM_IMAGE}" || true
    fi
    
    exit $exit_code
}

secure_delete() {
    local file="$1"
    if [[ -f "$file" ]]; then
        if command -v shred &>/dev/null; then
            echo "Securely shredding file: $file"
            shred -u "$file"
        else
            echo "Shred not available, using standard deletion for: $file"
            rm -f "$file"
        fi
    fi
}

# Set up trap for cleanup on error
trap cleanup ERR

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root or with sudo"
    exit 1
fi

# Check for required packages
REQUIRED_PKGS="libvirt-clients libvirt-daemon-system qemu-utils libguestfs-tools"
MISSING_PKGS=""

for pkg in $REQUIRED_PKGS; do
    if ! dpkg -l | grep -q "ii  $pkg "; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo "Required packages not installed:$MISSING_PKGS"
    echo "Please install them with: sudo apt-get install$MISSING_PKGS"
    exit 1
fi

# Validate arguments
if [ $# -lt 4 ]; then
    echo "Usage: $0 <vm_name> <ram_in_MB> <vcpus> <disk_size_GB> [linked|full]"
    echo "Example: $0 my_debian_vm 2048 2 20 linked"
    exit 1
fi

VM_NAME=$1
RAM=$2
VCPUS=$3
DISK_SIZE=${4}
CLONE_TYPE=${5:-"linked"}  # Default to linked if not specified
VM_IMAGE="${IMAGES_DIR}/${VM_NAME}.qcow2"
SETUP_STARTED=false

# VM names must be 1-63 chars, alphanumeric plus dash/underscore, and cannot start with a dash
if [[ ! "$VM_NAME" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,62}$ ]]; then
    echo "Error: VM name must:"
    echo "- Be 1-63 characters long"
    echo "- Contain only letters, numbers, dashes and underscores"
    echo "- Not start with a dash"
    exit 1
fi

# Validate resource requirements
if [ "$RAM" -lt "$MIN_RAM" ]; then
    echo "Error: RAM must be at least ${MIN_RAM}MB for stable operation"
    echo "Recommended minimum for basic Debian server: 1024MB"
    exit 1
fi

if [ "$VCPUS" -lt "$MIN_VCPUS" ]; then
    echo "Error: Number of vCPUs must be at least $MIN_VCPUS"
    exit 1
fi

if [ "$VCPUS" -gt "$MAX_VCPUS" ]; then
    echo "Warning: Requested vCPUs ($VCPUS) exceeds host CPU count ($MAX_VCPUS)"
    echo "This can cause performance issues. Continuing anyway..."
    # Not exiting as overcommitting CPUs is common practice
fi

if [ "$DISK_SIZE" -lt "$MIN_DISK_SIZE" ]; then
    echo "Error: Disk size must be at least ${MIN_DISK_SIZE}GB"
    echo "Recommended minimum for Debian: 10GB"
    exit 1
fi

# Check if template exists
if [ ! -f "$TEMPLATE_IMAGE" ]; then
    echo "Template image does not exist: $TEMPLATE_IMAGE"
    echo "Please update TEMPLATE_IMAGE variable in the script"
    exit 1
fi

# Check if VM already exists
if virsh dominfo "$VM_NAME" &>/dev/null; then
    echo "VM with name $VM_NAME already exists"
    exit 1
fi

# Verify network exists
if ! virsh net-info "$NETWORK" &>/dev/null; then
    echo "Network $NETWORK doesn't exist"
    echo "Available networks:"
    virsh net-list --all
    exit 1
fi

echo "Creating new VM: $VM_NAME"
echo "RAM: ${RAM}MB, vCPUs: $VCPUS, Disk: ${DISK_SIZE}GB, Clone type: $CLONE_TYPE"

# Set flag to indicate setup has started (for cleanup)
SETUP_STARTED=true

# Create disk image based on clone type
if [ "$CLONE_TYPE" = "linked" ]; then
    echo "Creating linked clone from template..."
    qemu-img create -f qcow2 -F qcow2 -b "$TEMPLATE_IMAGE" "$VM_IMAGE"
else
    echo "Creating full copy from template..."
    cp "$TEMPLATE_IMAGE" "$VM_IMAGE"
fi

# Resize the disk if needed - get template size in GB
TEMPLATE_SIZE_GB=$(qemu-img info "$TEMPLATE_IMAGE" | grep 'virtual size' | awk '{print $3}' | tr -d 'GiB')
TEMPLATE_SIZE_GB=${TEMPLATE_SIZE_GB%.*}  # Remove decimal part

# Simple integer comparison - resize if requested size is larger
if [ "$DISK_SIZE" -gt "$TEMPLATE_SIZE_GB" ]; then
    echo "Resizing disk from ${TEMPLATE_SIZE_GB}GB to ${DISK_SIZE}GB..."
    qemu-img resize "$VM_IMAGE" "${DISK_SIZE}G"
    RESIZED=true
else
    # Only show message if size is different (could be smaller)
    if [ "$DISK_SIZE" -ne "$TEMPLATE_SIZE_GB" ]; then
        echo "Note: Requested size (${DISK_SIZE}GB) is smaller than template (${TEMPLATE_SIZE_GB}GB). Disk not resized."
    fi
    RESIZED=false
fi

# Create a secure temporary file for the firstboot script
FIRSTBOOT_SCRIPT=$(mktemp /tmp/firstboot-${VM_NAME}.XXXXXX.sh)
FIRSTBOOT_SCRIPT_NAME=$(basename "$FIRSTBOOT_SCRIPT")

echo "Setting secure permissions on firstboot script..."
chmod 700 "$FIRSTBOOT_SCRIPT"  # Read/write/execute only for owner
chown root:root "$FIRSTBOOT_SCRIPT"

echo "Preparing VM customization using temporary script: $FIRSTBOOT_SCRIPT"

# Create a firstboot script to handle hostname, machine-id, and filesystem expansion
cat > "$FIRSTBOOT_SCRIPT" << 'EOF'
#!/bin/bash
# First boot configuration script for new VM

# Generate a more private MAC address that still follows standards
generate_private_mac() {
    # Use locally administered address (bit 1 of first byte set)
    # This avoids conflicts with real hardware MACs
    first_byte=$(printf "%02x" $(( (0x02 | (RANDOM & 0xfc)) ))) # Ensures bit 1 set, bit 0 clear
    rest_bytes=$(openssl rand -hex 5 | sed 's/\(..\)/\1:/g; s/.$//')
    echo "$first_byte:$rest_bytes"
}

# Check if all required tools are installed
required_tools_installed() {
    local missing=""
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing="$missing $cmd"
        fi
    done
    echo "$missing"
}

# Exit on critical errors
set -e

log_file="/var/log/firstboot-config.log"
trap 'echo "ERROR: Command failed at line $LINENO: $BASH_COMMAND" >> "$log_file"' ERR
exec > >(tee -a "$log_file") 2>&1

echo "Starting first boot configuration at $(date)"

# Ensure DNS resolution works
echo "Setting DNS resolver to ensure connectivity..."
echo "nameserver 1.1.1.1" > /etc/resolv.conf

# Check for required tools and attempt to install them if missing
echo "Checking for required filesystem tools..."
MISSING_TOOLS=$(required_tools_installed growpart pvresize lvextend resize2fs)
if [ -n "$MISSING_TOOLS" ]; then
    echo "Installing missing tools:$MISSING_TOOLS"
    apt-get update -qq
    apt-get install -y cloud-guest-utils lvm2 e2fsprogs
fi

# Regenerate machine-id
echo "Regenerating machine-id..."
rm -f /etc/machine-id
systemd-machine-id-setup

# Set hostname to VM_NAME_PLACEHOLDER
echo "Setting hostname to VM_NAME_PLACEHOLDER..."
hostnamectl set-hostname VM_NAME_PLACEHOLDER

# Regenerate SSH host keys if SSH is installed
# Fix: Use non-interactive SSH key regeneration
if [ -f "/etc/ssh/sshd_config" ]; then
    echo "Regenerating SSH host keys and applying basic hardening..."
    rm -f /etc/ssh/ssh_host_*
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive openssh-server || ssh-keygen -A
    
    # Basic SSH hardening
    if ! grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
        echo "SSH: Disabled root login"
    fi
    
    if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
        echo "SSH: Disabled password authentication"
    fi
    
    systemctl restart ssh 2>/dev/null || echo "Note: SSH service not running or not using systemd"
fi

# Expand filesystem if disk was resized
# RESIZED_PLACEHOLDER will be replaced with true/false
if [ "RESIZED_PLACEHOLDER" = "true" ]; then
    echo "Disk was resized, expanding filesystem..."
    
    # Find root filesystem information
    ROOT_PART=$(findmnt -n -o SOURCE /)
    
    # Check if using LVM
    if [[ "$ROOT_PART" == *"mapper"* ]]; then
        # LVM setup (most common in modern Debian)
        echo "Detected LVM setup with ext4 filesystem"
        
        # Get LV path and extract VG/LV names
        LV_PATH=$(df / | tail -1 | awk '{print $1}')
        VG_NAME=$(lvs --noheadings -o vg_name "$LV_PATH" | tr -d ' ')
        LV_NAME=$(lvs --noheadings -o lv_name "$LV_PATH" | tr -d ' ')
        
        echo "Found logical volume: VG=$VG_NAME, LV=$LV_NAME"
        
        # Grow the partition containing the PV
	ROOT_DEV=$(lsblk -no pkname ${ROOT_PART} | head -n1)
	ROOT_PART_NUM=$(echo ${ROOT_PART} | grep -o '[0-9]*$' || echo "1")
	growpart /dev/$ROOT_DEV $ROOT_PART_NUM || echo "Warning: growpart failed, partition may already be at maximum size" >&2
        
        # Resize the PV to use the new space
        pvresize /dev/${ROOT_DEV}${ROOT_PART_NUM} || echo "Warning: pvresize failed, partition may already be fully resized." >&2
        
        # Extend the LV to use all free space
        lvextend -l +100%FREE /dev/${VG_NAME}/${LV_NAME} || {
            echo "Error: lvextend failed" >&2
            exit 1
        }
        
        # Resize the filesystem (assuming ext4, the Debian default)
        resize2fs "$LV_PATH" || {
            echo "Error: resize2fs failed" >&2
            exit 1
        }
    else
        # Standard partition setup (less common but still supported)
        echo "Detected standard partition setup with ext4 filesystem"
        ROOT_DEV=$(lsblk -no pkname ${ROOT_PART} | head -n1)
        ROOT_PART_NUM=$(echo ${ROOT_PART} | grep -o '[0-9]*$' || echo "1")
        
        # Grow the partition
        growpart /dev/$ROOT_DEV $ROOT_PART_NUM || echo "Warning: growpart failed, partition may already be at maximum size" >&2
        
        # Resize the filesystem (assuming ext4, the Debian default)
        resize2fs "$ROOT_PART" || {
            echo "Error: resize2fs failed" >&2
            exit 1
        }
    fi
    
    echo "Filesystem expansion completed successfully"
fi

# Configure network based on detected system
configure_network() {
    # Detect primary network interface once
    PRIMARY_INTERFACE=$(ip -o link show | grep -v "lo" | grep "state UP" | awk -F': ' '{print $2}' | head -n 1)
    if [ -z "$PRIMARY_INTERFACE" ]; then
        PRIMARY_INTERFACE=$(ip -o link show | grep -v "lo" | awk -F': ' '{print $2}' | head -n 1)
    fi
    echo "Detected primary network interface: $PRIMARY_INTERFACE"
    
    # Generate a random MAC address once
    NEW_MAC=$(generate_private_mac)
    echo "Generated new MAC address: $NEW_MAC"
    
    # Configure Netplan if available
    if [ -d "/etc/netplan" ]; then
        echo "Netplan detected, creating network configuration..."
        
        # Fix permissions on existing netplan files
    	chmod 600 /etc/netplan/*.yaml 2>/dev/null || true
    	
        cat > "/etc/netplan/60-vm-custom.yaml" << NETPLAN
# Netplan configuration created by VM provisioning script
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: true
      macaddress: $NEW_MAC
NETPLAN
        chmod 600 "/etc/netplan/60-vm-custom.yaml"
        
        # Apply the configuration if netplan is available
        if command -v netplan >/dev/null 2>&1; then
            echo "Applying netplan configuration..."
            netplan apply
        else
            echo "Warning: netplan command not found, network changes require reboot" >&2
        fi
    fi
    
    # Configure legacy network interfaces if present
    if [ -f "/etc/network/interfaces" ]; then
        echo "Legacy network config detected, updating MAC addresses..."
        
        # Look for interfaces that need MAC addresses
        IFACES=$(grep -B1 "iface" /etc/network/interfaces | grep -v "lo" | awk '{print $2}' | grep -v "^$")
        if [ -n "$IFACES" ]; then
            for iface in $IFACES; do
                # Check if interface section already has hwaddress
                if grep -A10 "iface $iface" /etc/network/interfaces | grep -q "hwaddress"; then
                    # Update existing hwaddress
                    sed -i "/iface $iface/,/^\s*iface\|^$/ s/^\s*hwaddress .*$/    hwaddress $NEW_MAC/" /etc/network/interfaces
                    echo "Updated MAC for interface $iface"
                else
                    # Add hwaddress if not present
                    sed -i "/iface $iface/a\\    hwaddress $NEW_MAC" /etc/network/interfaces
                    echo "Added MAC for interface $iface"
                fi
            done
        else
            echo "No network interfaces found to update in interfaces file"
        fi
    fi
}

# Call the network configuration function
configure_network

echo "First boot configuration completed successfully at $(date)"

# Create a stamp file to prevent the script from running again on next boot
echo "Creating stamp file to prevent running on next boot..."
touch /var/lib/vm-firstboot.stamp
chmod 644 /var/lib/vm-firstboot.stamp

echo "First boot completed successfully. The script will not run on next boot."
EOF

# Generate random hostname for the VM
VM_HOSTNAME="vm-$(openssl rand -hex 3)"

# Replace placeholders
sed -i "s/VM_NAME_PLACEHOLDER/$VM_HOSTNAME/g" "$FIRSTBOOT_SCRIPT"
if [ "$RESIZED" = "true" ]; then
    sed -i 's/RESIZED_PLACEHOLDER/true/g' "$FIRSTBOOT_SCRIPT"
else
    sed -i 's/RESIZED_PLACEHOLDER/false/g' "$FIRSTBOOT_SCRIPT"
fi

# Customize the VM image with virt-customize
echo "Customizing VM image with systemd firstboot service..."

# Create systemd service file
cat > "/tmp/vm-firstboot.service" << EOF
[Unit]
Description=VM First Boot Configuration
After=network.target
ConditionPathExists=!/var/lib/vm-firstboot.stamp

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vm-firstboot.sh
ExecStartPost=/usr/bin/touch /var/lib/vm-firstboot.stamp
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Install packages, copy firstboot script, enable the systemd service
virt-customize -a "$VM_IMAGE" \
    --run-command "if ! (dpkg -l cloud-guest-utils lvm2 e2fsprogs | grep -q ^ii); then echo 'Required packages not installed. Would install them, but network is isolated.'; fi" \
    --run-command "mkdir -p /usr/local/bin && chmod 0755 /usr/local/bin" \
    --copy-in "$FIRSTBOOT_SCRIPT":/usr/local/bin/ \
    --run-command "mv /usr/local/bin/$(basename $FIRSTBOOT_SCRIPT) /usr/local/bin/vm-firstboot.sh && chmod 0755 /usr/local/bin/vm-firstboot.sh" \
    --copy-in "/tmp/vm-firstboot.service":/etc/systemd/system/ \
    --run-command "systemctl enable vm-firstboot.service" || {
        echo "Error: VM customization failed"
        exit 1
    }

# Clean up temporary service file
rm -f "/tmp/vm-firstboot.service"

# Clean up
secure_delete "$FIRSTBOOT_SCRIPT"

# Create VM
echo "Defining new VM..."
virt-install \
    --name "$VM_NAME" \
    --memory "$RAM" \
    --vcpus "$VCPUS" \
    --disk "$VM_IMAGE" \
    --import \
    --network network="$NETWORK" \
    --os-variant "ubuntu24.04" \
    --noautoconsole

# Verify VM was created successfully
if ! virsh dominfo "$VM_NAME" &>/dev/null; then
    echo "Error: VM was not created successfully"
    exit 1
fi

echo ""
echo "VM created, customized successfully and started!"
echo ""
echo "VM \"$VM_NAME\" has been created with the following specifications:"
echo "- RAM: ${RAM}MB"
echo "- vCPUs: $VCPUS"
echo "- Disk: ${DISK_SIZE}GB"
echo "- Network: $NETWORK"
echo ""
echo "The following has been automatically configured:"
echo "- Hostname set to $VM_HOSTNAME (private hostname for $VM_NAME)"
echo "- Machine-ID regenerated"
echo "- SSH host keys regenerated (if SSH is installed)"
echo "- Network configuration updated with unique identifiers (if applicable)"
if [ "$RESIZED" = true ]; then
    echo "- Filesystem automatically expanded"
fi
echo ""
echo "First boot configuration logs will be available inside the VM at:"
echo "  - Main log: /var/log/firstboot-config.log"
