#!/bin/bash
# Create KVM VM from QCOW2 template script
#
# *important: manually change the TEMPLATE_IMAGE, NETWORK, "--os-variant" flag, and "renderer: networkd | NetworkManager" variables to match
#
# This script automates KVM debian based VM creation from a template:
# - creates VM from existing qcow2 template (linked clone or full copy)
# - resizes the disk if requested (outside expansion)
# - handles filesystem expansion for resized disks (inside expansion)
# - configures machine-id, hostname, SSH keys regeneration
#
# Usage: make script executable and run:
# chmod +x create_debian_vm.sh
# sudo ./create_debian_vm.sh <vm_name> <ram_in_MB> <vcpus> <disk_size_GB> <linked | full>
# *e.g. sudo ./create_debian_vm.sh my_debian_vm 4096 2 20 linked
#
# -------------------------------------------------------------------------------

# Exit on any error
set -e
trap 'echo "ERROR: Command failed at line $LINENO: $BASH_COMMAND"' ERR

# Define variables that can be customized
IMAGES_DIR="/var/lib/libvirt/images"
TEMPLATE_IMAGE="${IMAGES_DIR}/your-template.qcow2"  # Change to chosen qcow2 template
NETWORK="your-network"  # Change to chosen virtual network name

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

# LVM expansion function with error handling
expand_lvm_filesystem() {
    echo "Starting LVM Filesystem Expansion"
    
    # Get root filesystem details
    ROOT_PART=$(findmnt -n -o SOURCE /)
    echo "Root partition: $ROOT_PART"
    
    if [[ "$ROOT_PART" != *"mapper"* ]]; then
        echo "Not an LVM setup, using standard partition expansion"
        return 1
    fi
    
    echo "LVM setup detected, proceeding with LVM expansion..."
    
    # Get device details
    PV_DEV=$(pvdisplay | grep "PV Name" | awk '{print $3}')
    ROOT_DEV=$(basename "$PV_DEV" | sed 's/[0-9]*$//')  # Strip /dev/ and partition number
    ROOT_PART_NUM=$(echo "$PV_DEV" | grep -o '[0-9]*$')
    
    echo "Root device: $ROOT_DEV"
    echo "Partition number: $ROOT_PART_NUM"
    
    # Step 1: Grow the partition
    echo "Step 1: Growing partition /dev/${ROOT_DEV}${ROOT_PART_NUM}..."
    if growpart /dev/$ROOT_DEV $ROOT_PART_NUM 2>/dev/null; then
        echo "Partition grown successfully"
    else
        echo "Partition growth failed or already at maximum size"
    fi
    
    # Step 2: Resize physical volume
    echo "Step 2: Resizing physical volume /dev/${ROOT_DEV}${ROOT_PART_NUM}..."
    if pvresize /dev/${ROOT_DEV}${ROOT_PART_NUM} 2>/dev/null; then
        echo "Physical volume resized successfully"
    else
        echo "Physical volume resize failed or already at maximum size"
    fi
    
    # Step 3: Get VG and LV names safely
    echo "Step 3: Getting volume group and logical volume names..."
    VG_NAME=$(lvs --noheadings -o vg_name "$ROOT_PART" 2>/dev/null | tr -d ' ')
    LV_NAME=$(lvs --noheadings -o lv_name "$ROOT_PART" 2>/dev/null | tr -d ' ')
    
    if [ -z "$VG_NAME" ] || [ -z "$LV_NAME" ]; then
        echo "ERROR: Could not determine VG/LV names"
        return 1
    fi
    
    echo "Volume Group: $VG_NAME"
    echo "Logical Volume: $LV_NAME"
    
    # Step 4: Check current sizes and free space
    echo "Step 4: Checking current sizes and free space..."
    FREE_EXTENTS=$(vgdisplay "$VG_NAME" | grep "Free.*PE" | awk '{print $5}')
    
    if [ "$FREE_EXTENTS" -gt 0 ]; then
        echo "Step 5: Extending logical volume..."
        if lvextend -l +100%FREE /dev/${VG_NAME}/${LV_NAME} 2>/dev/null; then
            echo "Logical volume extended successfully"
            
            # Step 6: Resize filesystem
            echo "Step 6: Resizing filesystem..."
            if resize2fs /dev/${VG_NAME}/${LV_NAME} 2>/dev/null; then
                echo "Filesystem resized successfully"
                return 0
            else
                echo "ERROR: resize2fs failed"
                return 1
            fi
        else
            echo "ERROR: lvextend failed"
            return 1
        fi
    else
        echo "No free space available for extension"
        return 0
    fi
}

# Standard partition expansion fallback
expand_standard_filesystem() {
    echo "Standard Partition Filesystem Expansion"
    
    ROOT_PART=$(findmnt -n -o SOURCE /)
    ROOT_DEV=$(lsblk -no pkname ${ROOT_PART} | head -n1 | sed 's|^/dev/||')
    ROOT_PART_NUM=$(lsblk -no name ${ROOT_PART} | grep -o '[0-9]*$' || echo "3")
    
    echo "Expanding standard partition setup..."
    echo "Root partition: $ROOT_PART"
    echo "Root device: /dev/${ROOT_DEV}"
    echo "Partition number: ${ROOT_PART_NUM}"
    
    if growpart /dev/$ROOT_DEV $ROOT_PART_NUM 2>/dev/null; then
        echo "Partition grown successfully"
    else
        echo "Partition growth failed or already at maximum size"
    fi
    
    if resize2fs "$ROOT_PART" 2>/dev/null; then
        echo "Filesystem resized successfully"
        NEW_SIZE=$(df -h / | tail -1 | awk '{print $2}')
        echo "New filesystem size: $NEW_SIZE"
        return 0
    else
        echo "ERROR: resize2fs failed for standard partition"
        return 1
    fi
}

log_file="/var/log/firstboot-config.log"
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
else
    echo "All required tools are already installed"
fi

# Regenerate machine-id
echo "Regenerating machine-id..."
rm -f /etc/machine-id
systemd-machine-id-setup

# Set hostname to VM_NAME_PLACEHOLDER
echo "Setting hostname to VM_NAME_PLACEHOLDER..."
hostnamectl set-hostname VM_NAME_PLACEHOLDER

# Regenerate SSH host keys if installed and start SSH service
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
    
    # Find the correct SSH service name and start it
    SSH_SERVICE=""
    for service in ssh sshd openssh-server; do
        if systemctl list-unit-files | grep -q "^${service}\.service"; then
            SSH_SERVICE="$service"
            break
        fi
    done
    
    if [ -n "$SSH_SERVICE" ]; then
        echo "Starting SSH service: $SSH_SERVICE"
        systemctl enable "$SSH_SERVICE"
        systemctl restart "$SSH_SERVICE"
        
        if systemctl is-active --quiet "$SSH_SERVICE"; then
            echo "SSH service started successfully"
        else
            echo "ERROR: Failed to start SSH service"
        fi
    else
        echo "ERROR: Could not find SSH service"
    fi
fi

# Expand filesystem if disk was resized
if [ "RESIZED_PLACEHOLDER" = "true" ]; then
    echo "Disk was resized, expanding filesystem..."
    
    # Try LVM expansion first, fallback to standard if not LVM
    if expand_lvm_filesystem; then
        echo "LVM filesystem expansion completed successfully"
    elif expand_standard_filesystem; then
        echo "Standard filesystem expansion completed successfully"
    else
        echo "WARNING: Filesystem expansion failed"
    fi
    
    # Show final size
    echo "Final filesystem status:"
    df -h /
fi

# Configure network based on detected system
configure_network() {
    echo "Configuring network..."
    
    # Detect primary network interface
    PRIMARY_INTERFACE=$(ip -o link show | grep -v "lo" | grep "state UP" | awk -F': ' '{print $2}' | head -n 1)
    if [ -z "$PRIMARY_INTERFACE" ]; then
        PRIMARY_INTERFACE=$(ip -o link show | grep -v "lo" | awk -F': ' '{print $2}' | head -n 1)
    fi
    echo "Detected primary network interface: $PRIMARY_INTERFACE"
    
    # Configure Netplan if present
    if [ -d "/etc/netplan" ]; then
        echo "Netplan detected, creating network configuration..."
        
        # Fix permissions on existing netplan files
    	chmod 600 /etc/netplan/*.yaml 2>/dev/null || true
    	
        cat > "/etc/netplan/60-vm-custom.yaml" << NETPLAN
# Netplan configuration created by VM provisioning script
network:
  version: 2
  renderer: networkd
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: true
      dhcp6: false
NETPLAN
        chmod 600 "/etc/netplan/60-vm-custom.yaml"
        
        # Apply the configuration if netplan is present
        if command -v netplan >/dev/null 2>&1; then
            echo "Applying netplan configuration..."
            netplan apply
            echo "Network configuration applied successfully"
        else
            echo "Warning: netplan command not found, network changes require reboot" >&2
        fi
    fi
    
    # Configure legacy network interfaces if present
    if [ -f "/etc/network/interfaces" ]; then
    	echo "Legacy network config detected, configuring DHCP..."
    	
    	# Ensure primary interface is configured for DHCP
    	if ! grep -q "iface $PRIMARY_INTERFACE inet dhcp" /etc/network/interfaces; then
            echo "auto $PRIMARY_INTERFACE" >> /etc/network/interfaces
            echo "iface $PRIMARY_INTERFACE inet dhcp" >> /etc/network/interfaces
            echo "Added $PRIMARY_INTERFACE with DHCP to interfaces file"
    	else
            echo "Interface $PRIMARY_INTERFACE already configured"
    	fi
    fi
    
    # Verify network configuration
    sleep 3
    IP_ADDR=$(ip addr show "$PRIMARY_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
    echo "Final IP address: ${IP_ADDR:-'Not assigned'}"
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

# Install firstboot script and enable the systemd service
virt-customize -a "$VM_IMAGE" \
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
echo "VM Details:"
echo "  Name: $VM_NAME"
echo "  RAM: ${RAM}MB"
echo "  vCPUs: $VCPUS"
echo "  Disk: ${DISK_SIZE}GB"
echo "  Network: $NETWORK"
echo ""
echo "First boot will:"
echo "  - Set hostname to $VM_HOSTNAME (private hostname for $VM_NAME)"
echo "  - Set up networking (systemd-networkd)"
echo "  - Regenerate machine-id and SSH keys"
if [ "$RESIZED" = true ]; then
    echo "  - Expand filesystem to use full ${DISK_SIZE}GB disk"
fi
echo ""
echo "First boot configuration logs will be inside the VM at:"
echo "  - Main log: /var/log/firstboot-config.log"
