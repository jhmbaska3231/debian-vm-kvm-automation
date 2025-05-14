#!/bin/bash
# Host UFW firewall configuration script
#
# This script configures UFW rules for a KVM virtual network:
# - detects physical interface, VPN interface, and virtual bridge interface
# - configures UFW rules for VM traffic with both VPN and direct internet access
# - disables IPv6
# - validates all commands and network names
#
# Usage: make script executable and run:
# chmod +x configure_host_ufw_normal.sh
# sudo ./configure_host_ufw_normal.sh --network <virtual_network_name>
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

# Check for UFW
if ! command -v ufw &>/dev/null; then
    print_msg error "UFW is not installed. Please install it with: sudo apt-get install ufw"
    exit 1
fi

# Parse command line arguments
TARGET_NETWORK=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            if [[ -z $2 || $2 == --* ]]; then
                print_msg error "Missing network name after --network"
                exit 1
            fi
            TARGET_NETWORK="$2"
            shift 2
            ;;
        *)
            print_msg error "Unknown option: $1"
            echo "Usage: sudo $0 --network NAME"
            exit 1
            ;;
    esac
done

# Validate that a network was specified
if [ -z "$TARGET_NETWORK" ]; then
    print_msg error "You must specify a target network using --network"
    echo "Usage: sudo $0 --network NAME"
    echo "Available networks:"
    virsh net-list --all
    exit 1
fi

# Validate that the specified network exists in libvirt
if ! virsh net-list --all | grep -q "^\s*$TARGET_NETWORK\s"; then
    print_msg error "Network '$TARGET_NETWORK' does not exist in libvirt"
    echo "Available networks:"
    virsh net-list --all
    exit 1
fi

# Set basic UFW policies if not already set
if ! ufw status | grep -q "Status: active"; then
    print_msg info "Setting up basic UFW policies..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Enable UFW without confirmation if not active
    echo "y" | ufw enable
    print_msg success "UFW enabled with default policies"
else
    print_msg info "UFW is already active"
fi

# Get physical network interface used for direct internet
PHYSICAL_IFACE=$(ip route | grep default | head -n1 | awk '{print $5}')
if [ -z "$PHYSICAL_IFACE" ]; then
    print_msg error "Could not detect physical network interface"
    exit 1
fi
print_msg info "Detected physical network interface: $PHYSICAL_IFACE"

# Get VPN interface (Mullvad only)
VPN_IFACE=$(ip a | grep -E "wg[0-9]|tun[0-9]|mullvad" | head -n1 | awk '{print $2}' | tr -d ':')
if [ -z "$VPN_IFACE" ]; then
    print_msg warning "No Mullvad VPN interface detected. Will configure direct internet access only."
    print_msg info "When you connect Mullvad VPN later, you may need to rerun this script."
else
    print_msg info "Detected Mullvad VPN interface: $VPN_IFACE"
fi

# Function to get subnet from IP address and CIDR
get_subnet() {
    local ip=$1
    local cidr=$2
    
    # Convert IP to integer
    local ip_int=0
    IFS='.' read -r -a octets <<< "$ip"
    for i in {0..3}; do
        ip_int=$((ip_int + octets[i] * 256**(3-i)))
    done
    
    # Create netmask
    local mask=$((0xffffffff << (32 - cidr)))
    
    # Calculate network address (bitwise AND)
    local net_int=$((ip_int & mask))
    
    # Convert back to dotted decimal
    local net_addr=""
    for i in {0..3}; do
        octet=$((net_int >> (8*(3-i)) & 0xff))
        if [ -z "$net_addr" ]; then
            net_addr="$octet"
        else
            net_addr="$net_addr.$octet"
        fi
    done
    
    echo "$net_addr/$cidr"
}

# Get virtual bridge interface for the target network
# First try to get the bridge name from virsh (for active networks)
BRIDGE_NAME=$(virsh net-info "$TARGET_NETWORK" 2>/dev/null | grep "Bridge:" | awk '{print $2}')

# If not found or empty, try looking in XML files
if [ -z "$BRIDGE_NAME" ] || [ "$BRIDGE_NAME" = "-" ]; then
    if [ -f "/etc/libvirt/qemu/networks/$TARGET_NETWORK.xml" ]; then
        BRIDGE_NAME=$(grep -o "bridge name='[^']*'" "/etc/libvirt/qemu/networks/$TARGET_NETWORK.xml" | cut -d "'" -f 2)
    fi
fi

# Final validation to find the bridge interface
if [ -z "$BRIDGE_NAME" ]; then
    print_msg error "Could not determine bridge interface for network: $TARGET_NETWORK"
    exit 1
fi

# Verify the bridge exists and is up
if ! virsh net-info "$TARGET_NETWORK" | grep -q "Active.*yes"; then
    print_msg warning "Network '$TARGET_NETWORK' is not running according to libvirt"
    echo -n "Do you want to start the network now? (y/n): "
    read -r answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        print_msg info "Starting network '$TARGET_NETWORK'..."
        if virsh net-start "$TARGET_NETWORK"; then
            print_msg success "Network started successfully"
            # Small delay to allow the bridge to come up
            sleep 2
        else
            print_msg error "Failed to start network '$TARGET_NETWORK'"
            exit 1
        fi
    else
        print_msg warning "Continuing with network in DOWN state. UFW rules will be added but may not work until network is started."
    fi
elif ip link show "$BRIDGE_NAME" 2>/dev/null | grep -q "NO-CARRIER.*state DOWN"; then
    print_msg info "Bridge interface '$BRIDGE_NAME' exists but shows NO-CARRIER. This is normal when no VMs are actively using the network."
fi

print_msg info "Configuring UFW rules for target network: $TARGET_NETWORK (bridge: $BRIDGE_NAME)"

# Get bridge IP and subnet
BRIDGE_IP=$(ip -4 addr show dev "$BRIDGE_NAME" | grep -oP 'inet \K[\d.]+')
if [ -z "$BRIDGE_IP" ]; then
    print_msg error "Could not get IP for $BRIDGE_NAME"
    exit 1
fi

# Get subnet CIDR (usually /24 for KVM networks)
SUBNET_CIDR=$(ip -4 addr show dev "$BRIDGE_NAME" | grep -oP 'inet [\d.]+/\K[\d]+')
if [ -z "$SUBNET_CIDR" ]; then
    SUBNET_CIDR=24  # Default to /24 if not found
fi

# Calculate full subnet
BRIDGE_SUBNET=$(get_subnet "$BRIDGE_IP" "$SUBNET_CIDR")

print_msg info "Processing $BRIDGE_NAME ($TARGET_NETWORK) with subnet $BRIDGE_SUBNET"

# Allow VM subnet to contact host for DNS and services
if ! ufw status | grep -q "$BRIDGE_SUBNET.*ALLOW IN"; then
    ufw allow from "$BRIDGE_SUBNET" comment "Allow $TARGET_NETWORK subnet to contact host"
    print_msg success "Added rule: Allow $BRIDGE_SUBNET to contact host"
else
    print_msg info "Rule already exists: Allow $BRIDGE_SUBNET to contact host"
fi

# Allow outbound from host to VM network
if ! ufw status | grep -q "ALLOW OUT.*on $BRIDGE_NAME"; then
    ufw allow out on "$BRIDGE_NAME" comment "Allow outbound from host to $TARGET_NETWORK"
    print_msg success "Added rule: Allow outbound from host to $BRIDGE_NAME"
else
    print_msg info "Rule already exists: Allow outbound from host to $BRIDGE_NAME"
fi

# Set up VPN routing if Mullvad VPN is available
if [ -n "$VPN_IFACE" ]; then
    if ! ufw status | grep -q "$BRIDGE_NAME.*$VPN_IFACE.*ALLOW FWD"; then
        ufw route allow in on "$BRIDGE_NAME" out on "$VPN_IFACE" comment "Allow $TARGET_NETWORK NAT through VPN"
        print_msg success "Added rule: Route $BRIDGE_NAME traffic through VPN ($VPN_IFACE)"
    else
        print_msg info "Rule already exists: Route $BRIDGE_NAME traffic through VPN ($VPN_IFACE)"
    fi
fi

# Always set up direct internet routing as well
if ! ufw status | grep -q "$BRIDGE_NAME.*$PHYSICAL_IFACE.*ALLOW FWD"; then
    ufw route allow in on "$BRIDGE_NAME" out on "$PHYSICAL_IFACE" comment "Allow $TARGET_NETWORK direct internet access"
    print_msg success "Added rule: Route $BRIDGE_NAME traffic directly to internet ($PHYSICAL_IFACE)"
else
    print_msg info "Rule already exists: Route $BRIDGE_NAME traffic directly to internet ($PHYSICAL_IFACE)"
fi

# Disable IPv6 
if grep -q "IPV6=yes" /etc/default/ufw; then
    print_msg info "Disabling IPv6 in UFW for security..."
    sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
    IPV6_DISABLED=true
elif grep -q "IPV6=no" /etc/default/ufw; then
    print_msg info "IPv6 is already disabled in UFW"
    IPV6_DISABLED=true
else
    print_msg warning "Could not find IPv6 setting in /etc/default/ufw"
    print_msg info "Attempting to add IPV6=no setting..."
    echo "IPV6=no" >> /etc/default/ufw
    
    # Verify the setting was added successfully
    if grep -q "IPV6=no" /etc/default/ufw; then
        print_msg success "Successfully added IPv6 disable setting"
        IPV6_DISABLED=true
    else
        print_msg error "Failed to disable IPv6 in UFW configuration"
        print_msg info "You may need to manually edit /etc/default/ufw and set IPV6=no"
        IPV6_DISABLED=false
    fi
fi

# Reload UFW to apply changes
print_msg info "Reloading UFW to apply changes..."
ufw reload

echo ""
print_msg success "UFW configuration complete!"
echo ""
echo "Summary:"
echo "UFW basic policies: Set"
echo "Physical interface: $PHYSICAL_IFACE"
echo "Target network: $TARGET_NETWORK"
echo "  - Bridge: $BRIDGE_NAME"
echo "  - Subnet: $BRIDGE_SUBNET"

if [ -n "$VPN_IFACE" ]; then
    echo "Mullvad VPN interface: $VPN_IFACE"
    echo "Routing: Both VPN and direct internet (VPN preferred when connected)"
else
    echo "Mullvad VPN interface: Not detected"
    echo "Routing: Direct internet only (run script again after connecting VPN)"
fi

if [ "$IPV6_DISABLED" = true ]; then
    echo "IPv6: Disabled"
else
    echo "! IPv6: Failed to disable - manual intervention required"
fi

echo ""
echo "Verify configuration:"
echo "To check current UFW status: sudo ufw status verbose"
echo ""
echo "Routing behavior:"
echo "- When Mullvad VPN is connected: VM will use VPN for internet access"
echo "- When Mullvad VPN is disconnected: VM will automatically use direct internet"

exit 0
