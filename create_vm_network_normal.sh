#!/bin/bash
# VM network creation script
#
# This script automates the creation of a new libvirt virtual network:
# - checks and enables IP forwarding
# - finds available bridge name and subnet
# - generates network XML configuration
# - defines, starts, and configures the network to autostart
# - validates network functionality
#
# Usage: make script executable and run:
# chmod +x create_vm_network_normal.sh
# sudo ./create_vm_network_normal.sh --name <virtual_network_name>
#
# -------------------------------------------------------------------------------

# Exit on any error
set -e

# Function to print formatted messages
print_msg() {
    local type=$1
    local message=$2
    
    case $type in
        info)
            echo "[INFO] $message"
            ;;
        success)
            echo "[SUCCESS] $message"
            ;;
        warning)
            echo "[WARNING] $message" >&2
            ;;
        error)
            echo "[ERROR] $message" >&2
            ;;
    esac
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    print_msg error "Please run this script as root or with sudo"
    exit 1
fi

# Check for required dependencies
for cmd in virsh dig ip sysctl; do
    if ! command -v "$cmd" &>/dev/null; then
        print_msg error "$cmd command not found. Please install required dependencies."
        exit 1
    fi
done

# Parse command line arguments
NETWORK_NAME=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --name)
            if [[ -z $2 || $2 == --* ]]; then
                print_msg error "Missing network name after --name"
                exit 1
            fi
            NETWORK_NAME="$2"
            shift 2
            ;;
        *)
            print_msg error "Unknown option: $1"
            echo "Usage: sudo $0 --name NETWORK_NAME"
            exit 1
            ;;
    esac
done

# Validate that a network name was specified
if [ -z "$NETWORK_NAME" ]; then
    print_msg error "Please specify a network name using --name"
    echo "Usage: sudo $0 --name NETWORK_NAME"
    exit 1
fi

# Validate network name format (alphanumeric, dash, underscore)
if ! [[ "$NETWORK_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    print_msg error "Network name must contain only letters, numbers, dashes, and underscores"
    exit 1
fi

# Check if network already exists
if virsh net-info "$NETWORK_NAME" &>/dev/null; then
    print_msg error "Network '$NETWORK_NAME' already exists. Each VM must have its own dedicated network."
    echo "Existing networks:"
    virsh net-list --all
    print_msg info "Please choose a different network name to ensure proper isolation between VMs."
    exit 1
fi

# Step 1: Check and enable IP forwarding
print_msg info "Checking IP forwarding status..."
IP_FORWARD=$(sysctl -n net.ipv4.ip_forward)

if [ "$IP_FORWARD" = "1" ]; then
    print_msg info "IP forwarding is already enabled"
else
    print_msg info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    
    # Make it persistent if not already set
    if ! grep -q "net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" | tee /etc/sysctl.d/99-ipforward.conf > /dev/null
        print_msg success "IP forwarding enabled and made persistent"
    else
        print_msg info "IP forwarding is already set to be persistent"
    fi
fi

# Step 2: Find available bridge name and subnet
print_msg info "Finding available bridge name and subnet..."

# Get existing bridge interfaces and their numbers
EXISTING_BRIDGES=$(ip link | grep -o 'virbr[0-9]\+' | sort -u)
HIGHEST_BRIDGE_NUM=0

for bridge in $EXISTING_BRIDGES; do
    bridge_num=$(echo "$bridge" | grep -o '[0-9]\+')
    if [ "$bridge_num" -gt "$HIGHEST_BRIDGE_NUM" ]; then
        HIGHEST_BRIDGE_NUM=$bridge_num
    fi
done

# Calculate next bridge number
NEXT_BRIDGE_NUM=$((HIGHEST_BRIDGE_NUM + 1))
NEXT_BRIDGE="virbr$NEXT_BRIDGE_NUM"

print_msg info "Next available bridge: $NEXT_BRIDGE"

# Array to store all used subnets
USED_SUBNETS=()

# Source 1: Get subnets from libvirt networks
while read -r network_name; do
    if [ -n "$network_name" ]; then
        ip_info=$(virsh net-dumpxml "$network_name" 2>/dev/null | grep 'ip address' | sed -E 's/.*address="([0-9.]+)".*/\1/')
        if [ -n "$ip_info" ]; then
            subnet=$(echo "$ip_info" | awk -F. '{print $1"."$2"."$3}')
            USED_SUBNETS+=("$subnet")
            print_msg info "Found used subnet from libvirt: $subnet.0/24"
        fi
    fi
done < <(virsh net-list --all | grep -v "^-\|^ Id\|^$" | awk '{print $1}')

# Source 2: Get subnets from actual bridge interfaces
while read -r bridge; do
    if [ -n "$bridge" ]; then
        ip_info=$(ip addr show "$bridge" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
        if [ -n "$ip_info" ]; then
            subnet=$(echo "$ip_info" | awk -F. '{print $1"."$2"."$3}')
            USED_SUBNETS+=("$subnet")
            print_msg info "Found used subnet from interface: $subnet.0/24"
        fi
    fi
done < <(ip addr | grep -o 'virbr[0-9]\+' | sort -u)

# Default subnet base
SUBNET_BASE="192.168"
SUBNET_THIRD=100

# Find available subnet
while true; do
    SUBNET="$SUBNET_BASE.$SUBNET_THIRD"
    CONFLICT=0
    
    # Check if subnet is already in use
    for used_subnet in "${USED_SUBNETS[@]}"; do
        if [ "$used_subnet" = "$SUBNET" ]; then
            print_msg info "Subnet $SUBNET.0/24 is already in use, trying next subnet..."
            CONFLICT=1
            break
        fi
    done
    
    if [ $CONFLICT -eq 0 ]; then
        # Found an available subnet
        break
    fi
    
    # Try next subnet
    SUBNET_THIRD=$((SUBNET_THIRD + 1))
    
    # If it goes above 254, move to next class-B subnet
    if [ $SUBNET_THIRD -gt 254 ]; then
        SUBNET_THIRD=0
        SUBNET_SECOND=$(echo "$SUBNET_BASE" | cut -d. -f2)
        SUBNET_SECOND=$((SUBNET_SECOND + 1))
        
        if [ $SUBNET_SECOND -gt 254 ]; then
            print_msg error "No available subnets found in private IP range"
            exit 1
        fi
        
        SUBNET_BASE="192.$SUBNET_SECOND"
    fi
done

BRIDGE_IP="$SUBNET.1"
DHCP_START="$SUBNET.2"
DHCP_END="$SUBNET.220" # Reserve .221 to .254 for any purpose

print_msg info "Selected subnet: $SUBNET.0/24"
print_msg info "Bridge IP: $BRIDGE_IP"

# Step 3: Generate network XML configuration
TEMP_XML=$(mktemp)
print_msg info "Generating network XML configuration..."

cat > "$TEMP_XML" << EOF
<network>
  <name>$NETWORK_NAME</name>
  <bridge name='$NEXT_BRIDGE' stp='on' delay='0'/>
  <ip address='$BRIDGE_IP' netmask='255.255.255.0'>
    <dhcp>
      <range start='$DHCP_START' end='$DHCP_END'/>
    </dhcp>
  </ip>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
</network>
EOF

# Step 4: Define the network in libvirt
print_msg info "Defining network in libvirt..."
if virsh net-define "$TEMP_XML"; then
    print_msg success "Network defined successfully"
else
    print_msg error "Failed to define network"
    rm "$TEMP_XML"
    exit 1
fi

# Clean up temp file
rm "$TEMP_XML"

# Step 5: Start the network
print_msg info "Starting network '$NETWORK_NAME'..."
if virsh net-start "$NETWORK_NAME"; then
    print_msg success "Network started successfully"
else
    print_msg error "Failed to start network '$NETWORK_NAME'"
    exit 1
fi

# Step 6: Set the network to autostart
print_msg info "Setting network to autostart..."
if virsh net-autostart "$NETWORK_NAME"; then
    print_msg success "Network set to autostart"
    
    # Verify autostart is enabled
    if virsh net-info "$NETWORK_NAME" | grep -q "Autostart.*yes"; then
        AUTOSTART_ENABLED=true
        print_msg success "Autostart verification successful"
    else
        AUTOSTART_ENABLED=false
        print_msg warning "Autostart may not be properly enabled. Please verify manually."
    fi
else
    print_msg warning "Failed to set network to autostart"
    AUTOSTART_ENABLED=false
fi

# Step 7: Verify the network is running
print_msg info "Verifying network is running..."
if virsh net-list --all | grep -q "$NETWORK_NAME.*active"; then
    print_msg success "Network is active"
else
    print_msg error "Network is not active. Something went wrong."
    exit 1
fi

# Step 8: Verify DNS forwarding works via libvirt
print_msg info "Verifying DNS forwarding (this may take a moment)..."

# Give some time for the bridge to become fully operational
sleep 3

# Try multiple times as DNS may take a moment to start working
MAX_ATTEMPTS=3
attempt=1
dns_working=false

while [ $attempt -le $MAX_ATTEMPTS ] && [ "$dns_working" = false ]; do
    if dig @"$BRIDGE_IP" google.com +short +timeout=5 | grep -q "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$"; then
        dns_working=true
    else
        print_msg warning "DNS test attempt $attempt failed, waiting before retry..."
        sleep 3
        attempt=$((attempt + 1))
    fi
done

if [ "$dns_working" = true ]; then
    print_msg success "DNS forwarding is working properly"
else
    print_msg warning "DNS forwarding test failed. The network may still work, but DNS might have issues."
    print_msg info "Please manually verify DNS later using: dig @$BRIDGE_IP google.com"
fi

# Final summary
echo ""
print_msg success "Virtual network setup complete!"
echo ""
echo "Network Details:"
echo "- Network Name: $NETWORK_NAME"
echo "- Bridge Interface: $NEXT_BRIDGE"
echo "- IP Address: $BRIDGE_IP"
echo "- DHCP Range: $DHCP_START - $DHCP_END"
echo "- Subnet: $SUBNET.0/24"
if [ "$AUTOSTART_ENABLED" = true ]; then
    echo "- Autostart: Enabled (network will start automatically at boot)"
else
    echo "- Autostart: Status unclear (verify with 'virsh net-info $NETWORK_NAME')"
fi
echo ""
echo "Next Step: Configure UFW rules for this network using:"
echo "sudo ./configure_host_ufw_normal.sh --network $NETWORK_NAME"

exit 0
