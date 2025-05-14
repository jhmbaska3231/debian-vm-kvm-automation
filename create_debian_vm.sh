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

# Check for numfmt availability
if ! command -v numfmt &>/dev/null; then
    echo "numfmt command not found. Will use manual size conversion."
    HAS_NUMFMT=false
else
    HAS_NUMFMT=true
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

# Resize the disk if needed
TEMPLATE_SIZE_BYTES=$(qemu-img info --output json "$TEMPLATE_IMAGE" | grep -oP '(?<="virtual-size": )[0-9]+')

# Convert requested size to bytes, handling numfmt absence
if [ "$HAS_NUMFMT" = true ]; then
    # If numfmt is available, use it (this is more accurate)
    REQUESTED_SIZE_BYTES=$(numfmt --from=iec "${DISK_SIZE}G")
else
    # Manual conversion: GB to bytes
    REQUESTED_SIZE_BYTES=$((DISK_SIZE * 1024 * 1024 * 1024))
fi

# Fix for large integer comparison using bc for arbitrary precision arithmetic
COMPARISON_RESULT=$(echo "$REQUESTED_SIZE_BYTES > $TEMPLATE_SIZE_BYTES" | bc -l)
if [ "$COMPARISON_RESULT" = "1" ]; then
    echo "Resizing disk to ${DISK_SIZE}GB..."
    qemu-img resize "$VM_IMAGE" "${DISK_SIZE}G"
    RESIZED=true
else
    RESIZED=false
fi

# Generate a more private hostname
generate_private_hostname() {
    local vm_name="$1"
    echo "vm-$(openssl rand -hex 3)"
}

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
    # Format: x2:xx:xx:xx:xx:xx where x is any hex digit and the 2 means "locally administered"
    first_byte=$(printf "%02x" $(( (0x02 | (RANDOM & 0xfc)) ))) # Ensures bit 1 set, bit 0 clear
    rest_bytes=$(openssl rand -hex 5 | sed 's/\(..\)/\1:/g; s/.$//')
    echo "$first_byte:$rest_bytes"
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
for cmd in growpart pvresize lvextend resize2fs; do
    if ! command -v $cmd &>/dev/null; then
        echo "Warning: $cmd not found, attempting to install required packages..."
        apt-get update -qq
        apt-get install -y cloud-guest-utils lvm2 e2fsprogs
        break
    fi
done

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
    # Detect root filesystem type and partition
    ROOT_PART=$(findmnt -n -o SOURCE /)
    ROOT_DEV=$(lsblk -no pkname ${ROOT_PART} | head -n1)
    ROOT_PART_NUM=$(echo ${ROOT_PART} | grep -o '[0-9]*$' || echo "1")

    if [[ "$ROOT_PART" == *"mapper"* ]]; then
        # LVM setup
        echo "Detected LVM setup, expanding filesystem..."
        
        # Get LV path and extract VG/LV names
        LV_PATH=$(df / | tail -1 | awk '{print $1}')
        VG_NAME=$(lvs --noheadings -o vg_name "$LV_PATH" | tr -d ' ')
        LV_NAME=$(lvs --noheadings -o lv_name "$LV_PATH" | tr -d ' ')
        
        echo "Found logical volume: VG=$VG_NAME, LV=$LV_NAME"
        
        # Grow the partition containing the PV
        if ! growpart /dev/$ROOT_DEV $ROOT_PART_NUM; then
            echo "Warning: growpart failed, partition may already be at maximum size" >&2
        fi
        
        # Resize the PV to use the new space
        if ! pvresize /dev/${ROOT_DEV}${ROOT_PART_NUM}; then
            echo "Warning: pvresize failed, partition may already be fully resized." >&2
        fi
        
        # Extend the LV to use all free space
        if ! lvextend -l +100%FREE /dev/${VG_NAME}/${LV_NAME}; then
            echo "Error: lvextend failed" >&2
            exit 1
        fi
        
        # Resize the filesystem - handle both ext and xfs
        FSTYPE=$(df -T "$LV_PATH" | tail -1 | awk '{print $2}')
        if [ "$FSTYPE" = "xfs" ]; then
            if ! xfs_growfs "$LV_PATH"; then
                echo "Error: xfs_growfs failed" >&2
                exit 1
            fi
        else
            # Default to ext filesystems
            if ! resize2fs "$LV_PATH"; then
                echo "Error: resize2fs failed" >&2
                exit 1
            fi
        fi
    else
        # Standard partition setup
        echo "Detected standard partition setup, expanding filesystem..."
        if ! growpart /dev/$ROOT_DEV $ROOT_PART_NUM; then
            echo "Warning: growpart failed, partition may already be at maximum size" >&2
        fi
        
        # Check filesystem type and use appropriate tool
        FSTYPE=$(df -T "$ROOT_PART" | tail -1 | awk '{print $2}')
        if [ "$FSTYPE" = "xfs" ]; then
            if ! xfs_growfs "$ROOT_PART"; then
                echo "Error: xfs_growfs failed" >&2
                exit 1
            fi
        else
            # Default to ext filesystems
            if ! resize2fs "$ROOT_PART"; then
                echo "Error: resize2fs failed" >&2
                exit 1
            fi
        fi
    fi
    echo "Filesystem expansion completed successfully"
fi

# Reset network MAC addresses in Netplan if exists
if [ -d "/etc/netplan" ]; then
    echo "Netplan detected, regenerating network configuration..."
    
    # Detect primary network interface
    PRIMARY_INTERFACE=$(ip -o link show | grep -v "lo" | grep "state UP" | awk -F': ' '{print $2}' | head -n 1)
    # If no UP interface found, get the first non-loopback interface
    if [ -z "$PRIMARY_INTERFACE" ]; then
        PRIMARY_INTERFACE=$(ip -o link show | grep -v "lo" | awk -F': ' '{print $2}' | head -n 1)
    fi
    echo "Detected primary network interface: $PRIMARY_INTERFACE"
    
    # Update MAC addresses in existing config files
    if grep -q "macaddress:" /etc/netplan/*.yaml 2>/dev/null; then
        # Generate a new MAC address only once
        NEW_MAC=$(generate_private_mac)
        echo "Generated new MAC address: $NEW_MAC"
    fi

    # Create a single high-precedence configuration file
    echo "Creating optimized netplan configuration..."
    cat > "/etc/netplan/60-vm-custom.yaml" << NETPLAN
# Netplan configuration created by VM provisioning script
# This file takes precedence over other netplan configurations
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: true
NETPLAN
    
    # Add MAC address to custom configuration
    if [ -n "$NEW_MAC" ]; then
        sed -i "/dhcp4: true/a\\      macaddress: $NEW_MAC" "/etc/netplan/60-vm-custom.yaml"
        echo "Added MAC address to netplan configuration"
    fi
    
    # Set secure permissions
    chmod 600 "/etc/netplan/60-vm-custom.yaml"
    echo "Created optimized netplan configuration file"
    
    # Set secure permissions on all netplan files
    echo "Setting secure permissions on netplan files..."
    chmod 600 /etc/netplan/*.yaml
    
    # Verify permissions were set correctly
    for netplan_file in /etc/netplan/*.yaml; do
        if [ -f "$netplan_file" ]; then
            perms=$(stat -c "%a" "$netplan_file")
            if [ "$perms" != "600" ]; then
                echo "Warning: Failed to set secure permissions on $netplan_file" >&2
            else
                echo "Secure permissions set on $netplan_file"
            fi
        fi
    done
    
    # Apply the new configuration
    if command -v netplan >/dev/null 2>&1; then
        echo "Applying netplan configuration..."
        netplan apply
    else
        echo "Warning: netplan command not found, network changes may require a reboot to take effect" >&2
    fi
fi

# Legacy: Update /etc/network/interfaces if exists
if [ -f "/etc/network/interfaces" ]; then
    echo "Legacy network config detected, checking for hardware address entries..."
    if grep -q "hwaddress" "/etc/network/interfaces"; then
        echo "Regenerating hardware addresses in network interfaces file..."
        # For each interface with hwaddress, generate new MAC
        for iface in $(grep -B1 "hwaddress" /etc/network/interfaces | grep "iface" | awk '{print $2}'); do
            # Generate a new MAC address
            NEW_MAC=$(generate_private_mac)
            sed -i "/iface $iface/,/^\s*iface\|^$/ s/^\s*hwaddress .*$/    hwaddress $NEW_MAC/" /etc/network/interfaces
            echo "Updated MAC for interface $iface"
        done
    fi
fi

echo "First boot configuration completed successfully at $(date)"

# Path is determined by where the script was initially placed
for script_path in "/var/lib/cloud/scripts/per-once/firstboot.sh" "/etc/init.d/firstboot-$(hostname).sh"; do
    if [ -f "$script_path" ]; then
        echo "Securely removing firstboot script: $script_path"
        if command -v shred &>/dev/null; then
            shred -u "$script_path"
        else
            echo "Note: shred command not available, using standard deletion"
            rm -f "$script_path"
        fi
    fi
done
EOF

# Generate a private hostname for the VM
VM_HOSTNAME=$(generate_private_hostname "$VM_NAME")

# Replace placeholders
sed -i "s/VM_NAME_PLACEHOLDER/$VM_HOSTNAME/g" "$FIRSTBOOT_SCRIPT"
if [ "$RESIZED" = "true" ]; then
    sed -i 's/RESIZED_PLACEHOLDER/true/g' "$FIRSTBOOT_SCRIPT"
else
    sed -i 's/RESIZED_PLACEHOLDER/false/g' "$FIRSTBOOT_SCRIPT"
fi

# Customize the VM image with virt-customize
echo "Customizing VM image..."

# Install necessary tools inside the VM for filesystem expansion
echo "Installing required tools in VM for filesystem expansion..."
virt-customize -a "$VM_IMAGE" \
    --install "cloud-guest-utils,lvm2,e2fsprogs" || \
    echo "Warning: Could not pre-install packages. Will attempt to install them at first boot."

# First, create required cloud-init directory structure in the VM image
virt-customize -a "$VM_IMAGE" \
    --run-command "mkdir -p /var/lib/cloud/scripts/per-once" \
    --chmod 0755:/var/lib/cloud/scripts || {
        echo "Error: Failed to create cloud-init directory structure in VM"
        echo "Attempting alternative method with init.d directory..."
        # Try alternative approach
        virt-customize -a "$VM_IMAGE" \
            --run-command "mkdir -p /etc/init.d"  \
            --copy-in "$FIRSTBOOT_SCRIPT":/etc/init.d/ \
            --run-command "mv /etc/init.d/$FIRSTBOOT_SCRIPT_NAME /etc/init.d/firstboot-${VM_HOSTNAME}.sh" \
            --chmod 0755:/etc/init.d/firstboot-${VM_HOSTNAME}.sh \
            --firstboot-command "/etc/init.d/firstboot-${VM_HOSTNAME}.sh; exit 0"
        
        # If the alternative method was used, clean up and create VM
        secure_delete "$FIRSTBOOT_SCRIPT"
        echo "VM configured using alternative firstboot method."
        
        # Create VM
        echo "Defining new VM..."
        virt-install --name "$VM_NAME" \
            --memory "$RAM" \
            --vcpus "$VCPUS" \
            --disk "$VM_IMAGE" \
            --import \
            --network network="$NETWORK" \
            --os-variant "ubuntu24.04" \
            --noautoconsole
        
        # VM creation verification
        if virsh dominfo "$VM_NAME" &>/dev/null; then
            echo "VM created and customized successfully!"
            echo "Wait for the VM to complete its first boot configuration."
        else
            echo "Error: VM was not created successfully"
            exit 1
        fi
        
        # Skip the rest of the script
        exit 0
    }

# If the cloud-init directory was created successfully, proceed with the original approach
virt-customize -a "$VM_IMAGE" \
    --copy-in "$FIRSTBOOT_SCRIPT":/var/lib/cloud/scripts/per-once/ \
    --run-command "mv /var/lib/cloud/scripts/per-once/$FIRSTBOOT_SCRIPT_NAME /var/lib/cloud/scripts/per-once/firstboot.sh" \
    --chmod 0755:/var/lib/cloud/scripts/per-once/firstboot.sh \
    --firstboot-command "/var/lib/cloud/scripts/per-once/firstboot.sh"

# Clean up
secure_delete "$FIRSTBOOT_SCRIPT"

# Create VM
echo "Defining new VM..."
virt-install --name "$VM_NAME" \
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
