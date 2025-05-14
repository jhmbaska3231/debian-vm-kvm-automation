#!/bin/bash
# Delete VM and network cleanup script
#
# This script safely removes a single VM and its dedicated network:
# - detects the specific network used by this VM
# - checks if any other VMs are using the network before deletion
# - deletes the VM and its associated qcow2 disk
# - removes the VM's dedicated network
# - cleans up UFW rules specific to this VM's network
# - ensures no impact on other VMs in the system
#
# Usage: make script executable and run:
# chmod +x delete_vm_and_cleanup.sh
# sudo ./delete_vm_and_cleanup.sh --vm <VM_name>
#
# -------------------------------------------------------------------------------

# Exit on any error
set -e

# Create log directory and file with proper permissions
LOG_DIR="/var/log/vm_management"
mkdir -p "$LOG_DIR" 2>/dev/null || {
    echo "[WARNING] Cannot create log directory in /var/log/vm_management, using /tmp instead"
    LOG_DIR="/tmp"
}
# Set appropriate permissions for the log directory
if [ "$LOG_DIR" != "/tmp" ]; then
    chmod 755 "$LOG_DIR" 2>/dev/null || true
fi

LOG_FILE="$LOG_DIR/vm_cleanup_$(date +%Y%m%d_%H%M%S).log"
touch "$LOG_FILE" 2>/dev/null || {
    echo "[WARNING] Cannot write to $LOG_FILE, using /tmp instead"
    LOG_FILE="/tmp/vm_cleanup_$(date +%Y%m%d_%H%M%S).log"
}

# Create a temp file for UFW rule numbers
UFW_TEMP=$(mktemp)
# Set up cleanup trap for temp files
trap 'rm -f "$UFW_TEMP"; echo "Script terminated. Log file: $LOG_FILE"' EXIT INT TERM

# Function to print formatted messages
print_msg() {
    local type=$1
    local message=$2
    
    case $type in
        info)
            echo "[INFO] $message"
            echo "[INFO] $message" >> "$LOG_FILE"
            ;;
        success)
            echo "[SUCCESS] $message"
            echo "[SUCCESS] $message" >> "$LOG_FILE"
            ;;
        warning)
            echo "[WARNING] $message" >&2
            echo "[WARNING] $message" >> "$LOG_FILE"
            ;;
        error)
            echo "[ERROR] $message" >&2
            echo "[ERROR] $message" >> "$LOG_FILE"
            ;;
    esac
}

# Log script start and command line
echo "====== VM Cleanup Script Started at $(date) ======" > "$LOG_FILE"
echo "Command: $0 $*" >> "$LOG_FILE"
print_msg info "Script started. Logging to $LOG_FILE"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    print_msg error "Please run this script as root or with sudo"
    exit 1
fi

# Check for required commands
for cmd in virsh dig ip sysctl ufw grep awk file; do
    if ! command -v "$cmd" &>/dev/null; then
        print_msg error "$cmd command not found. Please install required dependencies."
        exit 1
    fi
done

# Parse command line arguments
VM_NAME=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --vm)
            if [[ -z $2 || $2 == --* ]]; then
                print_msg error "Missing VM name after --vm"
                exit 1
            fi
            VM_NAME="$2"
            shift 2
            ;;
        *)
            print_msg error "Unknown option: $1"
            echo "Usage: sudo $0 --vm <VM_name>"
            exit 1
            ;;
    esac
done

# Validate that VM name was specified
if [ -z "$VM_NAME" ]; then
    print_msg error "You must specify a VM name using --vm"
    echo "Usage: sudo $0 --vm <VM_name>"
    exit 1
fi

# Check if VM exists
if ! virsh dominfo "$VM_NAME" &>/dev/null; then
    print_msg warning "VM '$VM_NAME' does not exist or is not defined in libvirt"
    print_msg info "Please check the VM name and try again"
    print_msg info "Available VMs:"
    virsh list --all | tee -a "$LOG_FILE"
    exit 1
fi

print_msg info "Starting deletion process for VM: $VM_NAME"

# Detect the networks for this VM
print_msg info "Detecting network interfaces for VM '$VM_NAME'..."
VM_NETWORKS=()
VM_NETWORK_TYPES=()

# Get all network interfaces for this VM
while read -r if_line; do
    # Skip empty lines and headers
    if [ -z "$if_line" ] || [[ "$if_line" == *"Interface"* ]]; then
        continue
    fi
    
    # Extract interface type and source
    if_type=$(echo "$if_line" | awk '{print $2}')
    if_source=$(echo "$if_line" | awk '{print $3}')
    
    # Record all network interfaces
    if [ "$if_type" = "network" ]; then
        VM_NETWORKS+=("$if_source")
        VM_NETWORK_TYPES+=("$if_type")
        print_msg info "Found network interface: $if_source (type: $if_type)"
    fi
done < <(virsh domiflist "$VM_NAME" 2>/dev/null)

# No networks found for VM
if [ ${#VM_NETWORKS[@]} -eq 0 ]; then
    print_msg warning "No networks found for VM '$VM_NAME'. Cannot proceed with cleanup."
    print_msg info "VM network information:"
    virsh domiflist "$VM_NAME" | tee -a "$LOG_FILE"
    exit 1
fi

# If multiple networks found, warn user and exit
if [ ${#VM_NETWORKS[@]} -gt 1 ]; then
    print_msg error "Multiple networks found for VM '$VM_NAME': ${VM_NETWORKS[*]}"
    print_msg error "Each VM should have exactly one dedicated network. This situation is unexpected."
    print_msg info "Please manually inspect and clean up the networks:"
    for net in "${VM_NETWORKS[@]}"; do
        print_msg info "  - $net"
    done
    print_msg info "To delete a network: virsh net-destroy NETWORK_NAME && virsh net-undefine NETWORK_NAME"
    exit 1
else
    # Single network found
    SELECTED_NETWORK="${VM_NETWORKS[0]}"
    SELECTED_TYPE="${VM_NETWORK_TYPES[0]}"
    print_msg success "Found network for this VM: $SELECTED_NETWORK"
fi

# Skip the default network
if [ "$SELECTED_NETWORK" = "default" ]; then
    print_msg warning "The VM is using the default network. This is unusual since you mentioned default should be disabled."
    print_msg warning "Will not delete the default network for safety reasons."
    print_msg info "If you want to delete the default network, do it manually with: virsh net-destroy default; virsh net-undefine default"
    SKIP_NETWORK_CLEANUP=true
else
    # Check if any other VMs are using this network
    print_msg info "Checking if other VMs are using network '$SELECTED_NETWORK'..."
    
    # Get all VMs
    ALL_VMS=$(virsh list --all --name 2>/dev/null) || {
        print_msg error "Failed to get list of VMs"
        exit 1
    }
    OTHER_VM_USING_NETWORK=false
    OTHER_VMS_USING_NETWORK=()
    
    for other_vm in $ALL_VMS; do
        # Skip the VM to be deleted
        if [ "$other_vm" = "$VM_NAME" ]; then
            continue
        fi
        
        # Check if this VM uses another network
        if virsh domiflist "$other_vm" 2>/dev/null | grep -q "$SELECTED_NETWORK"; then
            OTHER_VM_USING_NETWORK=true
            OTHER_VMS_USING_NETWORK+=("$other_vm")
        fi
    done
    
    if [ "$OTHER_VM_USING_NETWORK" = true ]; then
        print_msg error "Network '$SELECTED_NETWORK' is used by other VMs: ${OTHER_VMS_USING_NETWORK[*]}"
        print_msg error "Each VM should have its own dedicated network. This situation is unexpected."
        print_msg info "To safely proceed, first delete the other VMs using this network: ${OTHER_VMS_USING_NETWORK[*]}"
        exit 1
    else
        print_msg success "Network '$SELECTED_NETWORK' is not used by any other VMs. Safe to delete."
    fi
fi

# Get VM state and shut down if running
VM_STATE=$(virsh dominfo "$VM_NAME" | grep "State:" | awk '{print $2 " " $3}')
print_msg info "VM state: $VM_STATE"

if echo "$VM_STATE" | grep -q "running"; then
    print_msg info "Shutting down VM..."
    
    # Try graceful shutdown first
    virsh shutdown "$VM_NAME"
    print_msg info "Shutdown initiated. Waiting for VM to stop (up to 30 seconds)..."
    
    # Wait for up to 30 seconds for the VM to shut down with countdown
    for i in {30..1}; do
        if ! virsh dominfo "$VM_NAME" 2>/dev/null | grep -q "State:.*running"; then
            print_msg success "VM gracefully shut down after $((30-i)) seconds"
            break
        fi
        if [ $i -eq 20 ]; then
            print_msg warning "VM is taking longer than expected to shut down. Will continue waiting..."
        fi
        printf "\rWaiting for VM to shut down... %d " $i
        sleep 1
    done
    echo ""
    
    # Force shutdown if still running
    if virsh dominfo "$VM_NAME" 2>/dev/null | grep -q "State:.*running"; then
        print_msg warning "VM did not shut down gracefully within 30 seconds. Using force stop."
        virsh destroy "$VM_NAME"
        print_msg info "VM forcefully stopped"
    fi
fi

# Get associated disk information
print_msg info "Getting VM disk information..."
VM_DISKS=()
LINKED_CLONE=false
ANY_LINKED_CLONE=false  # Track if any disk is a linked clone
BASE_IMAGE=""

# Get disk list from virsh
while read -r disk_line; do
    # Skip empty lines and headers
    if [ -z "$disk_line" ] || [[ "$disk_line" == *Target* ]]; then
        continue
    fi
    
    # Extract target and source from the line (using awk only once)
    read -r disk_target disk_source <<< "$(echo "$disk_line" | awk '{print $1, $2}')"
    
    # Skip if source is not a valid file path
    if [[ "$disk_source" == "-" || -z "$disk_source" ]]; then
        continue
    fi
    
    # Add to disk array
    VM_DISKS+=("$disk_source")
    print_msg info "Found disk: $disk_target → $disk_source"
    
    # Get disk information directly with one call
    if ! DISK_INFO=$(qemu-img info "$disk_source" 2>/dev/null); then
        print_msg warning "Could not get disk information for: $disk_source"
        continue
    fi
    
    # Get disk format
    DISK_FORMAT=$(grep "file format:" <<< "$DISK_INFO" | awk -F ': ' '{print $2}')
    
    # Check if this is a linked clone (has a backing file)
    if echo "$DISK_INFO" | grep -i "backing file"; then
        LINKED_CLONE=true
        ANY_LINKED_CLONE=true
        
        # Extract the backing file path
        BASE_IMAGE=$(echo "$DISK_INFO" | grep -oP 'backing file: \K[^\n(]+' | sed 's/^ *//;s/ *$//')
        
        if [ -n "$BASE_IMAGE" ]; then
            print_msg info "Detected linked clone with backing file: $BASE_IMAGE"
            
            # Validate base image path
            if [ -f "$BASE_IMAGE" ]; then
                print_msg info "Base image exists at: $BASE_IMAGE"
            else
                print_msg warning "Backing file detected but not found at path: $BASE_IMAGE"
            fi
        else
            print_msg warning "Detected backing file but couldn't extract the path"
        fi
    fi
done < <(virsh domblklist "$VM_NAME" | tail -n +3)

# After examining all disks, set the final linked clone status
LINKED_CLONE=$ANY_LINKED_CLONE

# Summarize findings
if [ ${#VM_DISKS[@]} -eq 0 ]; then
    print_msg warning "No disk files found for VM '$VM_NAME'"
else
    print_msg info "Found ${#VM_DISKS[@]} disk(s) for VM '$VM_NAME'"
    if [ "$LINKED_CLONE" = true ]; then
        print_msg info "VM is a linked clone using base image: $BASE_IMAGE"
    else
        print_msg info "VM is a standard VM (not a linked clone)"
    fi
fi

# Get network information (bridge and subnet) for the selected network
BRIDGE_NAME=""
BRIDGE_SUBNET=""
if [ -n "$SELECTED_NETWORK" ] && [ "$SKIP_NETWORK_CLEANUP" != true ]; then
    print_msg info "Getting detailed information for network: $SELECTED_NETWORK"
    
    # Get bridge name from virsh if network exists
    if virsh net-info "$SELECTED_NETWORK" &>/dev/null; then
        BRIDGE_NAME=$(virsh net-info "$SELECTED_NETWORK" 2>/dev/null | grep "Bridge:" | awk '{print $2}')
        if [ "$BRIDGE_NAME" = "-" ]; then
            BRIDGE_NAME=""
        fi
        print_msg info "Network bridge: $BRIDGE_NAME"
    fi
    
    # If bridge name not found from virsh, try to find from XML file
    if [ -z "$BRIDGE_NAME" ] && [ -f "/etc/libvirt/qemu/networks/$SELECTED_NETWORK.xml" ]; then
        BRIDGE_NAME=$(grep -o "bridge name='[^']*'" "/etc/libvirt/qemu/networks/$SELECTED_NETWORK.xml" | cut -d "'" -f 2)
        if [ -n "$BRIDGE_NAME" ]; then
            print_msg info "Found bridge name from XML file: $BRIDGE_NAME"
        fi
    fi
    
    # Get bridge subnet if the bridge exists
    if [ -n "$BRIDGE_NAME" ] && ip -4 addr show dev "$BRIDGE_NAME" &>/dev/null; then
        BRIDGE_IP=$(ip -4 addr show dev "$BRIDGE_NAME" | grep -oP 'inet \K[\d.]+')
        SUBNET_CIDR=$(ip -4 addr show dev "$BRIDGE_NAME" | grep -oP 'inet [\d.]+/\K[\d]+')
        if [ -n "$BRIDGE_IP" ] && [ -n "$SUBNET_CIDR" ]; then
            # Simple subnet calculation for /24
            if [ "$SUBNET_CIDR" = "24" ]; then
                IFS='.' read -r -a octets <<< "$BRIDGE_IP"
                BRIDGE_SUBNET="${octets[0]}.${octets[1]}.${octets[2]}.0/24"
            else
                # For other masks, use the IP with CIDR
                BRIDGE_SUBNET="$BRIDGE_IP/$SUBNET_CIDR"
            fi
            print_msg info "Network subnet: $BRIDGE_SUBNET"
        fi
    fi
fi

# Step 1: Delete the VM
print_msg info "----- STEP 1: Deleting VM -----"
print_msg info "Undefining VM '$VM_NAME'..."

if [ "$LINKED_CLONE" = true ]; then
    print_msg info "Detected linked clone. Will preserve the base image: $BASE_IMAGE"
fi

# Try to undefine VM with different options based on whether it's a linked clone
if [ "$LINKED_CLONE" = true ]; then
    # For linked clones, got to be careful not to use --remove-all-storage
    # as it might try to remove the backing file
    if ! virsh undefine "$VM_NAME"; then
        print_msg error "Failed to undefine VM. Unable to continue."
        exit 1
    fi
    
    # Manually delete the linked clone disk files but preserve the base image
    for disk in "${VM_DISKS[@]}"; do
        if [ -f "$disk" ] && [ "$disk" != "$BASE_IMAGE" ]; then
            print_msg info "Deleting linked clone disk file: $disk"
            if rm -f "$disk"; then
                print_msg success "Disk deleted successfully: $disk"
            else
                print_msg error "Failed to delete disk file: $disk"
            fi
        elif [ "$disk" = "$BASE_IMAGE" ]; then
            print_msg info "Preserving base image: $disk"
        fi
    done
else
    # Not a linked clone, try with --remove-all-storage first
    if ! virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null; then
        print_msg warning "Could not undefine VM with --remove-all-storage option. Trying alternative method..."
        if ! virsh undefine "$VM_NAME"; then 
            print_msg error "Failed to undefine VM. Unable to continue."
            exit 1
        fi
        
        # Delete associated disk files
        for disk in "${VM_DISKS[@]}"; do
            if [ -f "$disk" ]; then
                print_msg info "Deleting disk file: $disk"
                if rm -f "$disk"; then
                    print_msg success "Disk deleted successfully: $disk"
                else
                    print_msg error "Failed to delete disk file: $disk"
                fi
            fi
        done
    else
        print_msg success "VM undefined and disks removed successfully"
    fi
fi

print_msg success "VM deletion completed"

# Step 2: Delete the network if one was found and not skipped
if [ -n "$SELECTED_NETWORK" ] && [ "$SKIP_NETWORK_CLEANUP" != true ]; then
    print_msg info "----- STEP 2: Deleting Network -----"
    
    # Check if network is still active before proceeding
    NETWORK_ACTIVE=false
    if virsh net-info "$SELECTED_NETWORK" &>/dev/null; then
        # Get network state
        NET_STATE=$(virsh net-info "$SELECTED_NETWORK" | grep "Active:" | awk '{print $2}')
        
        if [ "$NET_STATE" = "yes" ]; then
            NETWORK_ACTIVE=true
            
            # Store network-related info for DHCP cleanup later
            # Store PID before destroying the network
            if [ -f "/var/run/libvirt/network/dnsmasq-$SELECTED_NETWORK.pid" ]; then
                DNSMASQ_PID=$(cat "/var/run/libvirt/network/dnsmasq-$SELECTED_NETWORK.pid" 2>/dev/null || echo "")
                print_msg info "Saved dnsmasq PID for cleanup: $DNSMASQ_PID"
            fi
            
            # Stop the network if it's active
            print_msg info "Stopping network '$SELECTED_NETWORK'..."
            if virsh net-destroy "$SELECTED_NETWORK"; then
                print_msg success "Network stopped successfully"
            else
                print_msg warning "Could not stop network, it may already be inactive"
                NETWORK_ACTIVE=false
            fi
        fi
        
        # Disable autostart
        print_msg info "Disabling network autostart..."
        virsh net-autostart --disable "$SELECTED_NETWORK" || true
        
        # Undefine the network
        print_msg info "Undefining network '$SELECTED_NETWORK'..."
        if virsh net-undefine "$SELECTED_NETWORK"; then
            print_msg success "Network undefined successfully"
        else
            print_msg warning "Could not undefine network, continuing anyway"
        fi
    else
        print_msg warning "Network '$SELECTED_NETWORK' is not defined in libvirt, skipping network deletion"
    fi
    
    # Remove XML file if it still exists
    XML_FILE="/etc/libvirt/qemu/networks/$SELECTED_NETWORK.xml"
    if [ -f "$XML_FILE" ]; then
        print_msg info "Removing network XML file: $XML_FILE"
        if rm -f "$XML_FILE"; then
            print_msg success "Network XML file removed"
        else
            print_msg warning "Could not remove XML file"
        fi
    fi
    
    print_msg success "Network deletion completed"

    # Step 3: Clean up UFW rules
    print_msg info "----- STEP 3: Cleaning up UFW rules -----"
    
    # Check if UFW is active
    if ! ufw status &>/dev/null || ! ufw status | grep -q "Status: active"; then
        print_msg info "UFW is not active, skipping firewall rule cleanup"
    else
        # Debug: Log complete UFW status for diagnostics
        print_msg info "Complete UFW status for diagnostics:"
        ufw status numbered 2>&1 | tee -a "$LOG_FILE" || print_msg warning "Could not get UFW status"
    
        # Create precise patterns of unique identifiers for matching
        BRIDGE_PATTERN=""
        SUBNET_PATTERN=""
        NETWORK_PATTERN=""
        
        if [ -n "$BRIDGE_NAME" ]; then
            # Add word boundaries to avoid partial matches
            BRIDGE_PATTERN="\\b$BRIDGE_NAME\\b"
            echo "[INFO] Using bridge pattern for matching: $BRIDGE_PATTERN" >> "$LOG_FILE"
        fi
        
        if [ -n "$BRIDGE_SUBNET" ]; then
            # Escape dots in subnet for regex
            SUBNET_PATTERN=$(echo "$BRIDGE_SUBNET" | sed 's/\./\\./g')
            echo "[INFO] Using subnet pattern for matching: $SUBNET_PATTERN" >> "$LOG_FILE"
        fi
        
        if [ -n "$SELECTED_NETWORK" ]; then
            # Add word boundaries for network name
            NETWORK_PATTERN="\\b$SELECTED_NETWORK\\b"
            echo "[INFO] Using network pattern for matching: $NETWORK_PATTERN" >> "$LOG_FILE"
        fi
        
        # Capture UFW rules in a more robust way
        print_msg info "Getting UFW rules..."
        ALL_UFW_RULES=$(ufw status numbered 2>/dev/null) || {
            print_msg warning "Error getting UFW status, will try alternative approach"
            ALL_UFW_RULES=$(cat /etc/ufw/user.rules 2>/dev/null) || {
                print_msg error "Could not access UFW rules, skipping UFW cleanup"
                # Using "exit 1" here would terminate the script, use "false" instead
                false
            }
        }
        
        # Only continue if there's UFW rules
        if [ -n "$ALL_UFW_RULES" ]; then
            # Manually parse rules line by line with proper error handling
            print_msg info "Parsing UFW rules for deletion..."
            RULE_NUMS_TO_DELETE=()
            
            while IFS= read -r rule; do
                # Skip headers and empty lines
                if [[ "$rule" == *"Status:"* || "$rule" == *"--"* || -z "$rule" ]]; then
                    continue
                fi
                
                # Extract rule number
                RULE_NUM=$(echo "$rule" | grep -oP '^\[\K[0-9]+(?=\])' || echo "")
                if [ -z "$RULE_NUM" ]; then continue; fi
                
                RULE_TEXT=$(echo "$rule" | cut -d ']' -f2- | sed 's/^[[:space:]]*//' || echo "")
                if [ -z "$RULE_TEXT" ]; then continue; fi
                
                echo "[INFO] Examining rule #$RULE_NUM: $RULE_TEXT" >> "$LOG_FILE"
                
                # Match patterns
                SHOULD_DELETE=false
                
                if [ -n "$BRIDGE_PATTERN" ] && echo "$RULE_TEXT" | grep -qE "$BRIDGE_PATTERN"; then
                    echo "[INFO]   - Bridge pattern matched" >> "$LOG_FILE"
                    SHOULD_DELETE=true
                fi
                
                if [ -n "$SUBNET_PATTERN" ] && echo "$RULE_TEXT" | grep -qE "$SUBNET_PATTERN"; then
                    echo "[INFO]   - Subnet pattern matched" >> "$LOG_FILE"
                    SHOULD_DELETE=true
                fi
                
                if [ -n "$NETWORK_PATTERN" ] && echo "$RULE_TEXT" | grep -qE "$NETWORK_PATTERN"; then
                    echo "[INFO]   - Network pattern matched" >> "$LOG_FILE"
                    SHOULD_DELETE=true
                fi
                
                if [ "$SHOULD_DELETE" = true ]; then
                    print_msg info "  - Rule #$RULE_NUM will be deleted"
                    RULE_NUMS_TO_DELETE+=("$RULE_NUM")
                else
                    print_msg info "  - Rule #$RULE_NUM does not match criteria, keeping"
                fi
            done < <(echo "$ALL_UFW_RULES")
            
            # Sort rule numbers in reverse order (important for UFW)
            if [ ${#RULE_NUMS_TO_DELETE[@]} -gt 0 ]; then
                print_msg info "Sorting ${#RULE_NUMS_TO_DELETE[@]} rules for deletion in reverse order..."
                IFS=$'\n' SORTED_NUMS=($(sort -rn <<<"${RULE_NUMS_TO_DELETE[*]}"))
                unset IFS
                
                # Delete rules one by one
                for rule_num in "${SORTED_NUMS[@]}"; do
                    print_msg info "Deleting UFW rule #$rule_num..."
                    # Use yes command to handle confirmation prompts
                    yes | ufw delete "$rule_num" 2>&1 | tee -a "$LOG_FILE" || {
                        print_msg warning "Error deleting UFW rule #$rule_num, trying without confirmation"
                        ufw --force delete "$rule_num" 2>&1 | tee -a "$LOG_FILE" || {
                            print_msg error "Failed to delete UFW rule #$rule_num"
                        }
                    }
                done
                
                print_msg success "UFW rules cleanup completed"
            else
                print_msg info "No UFW rules found matching the deletion criteria"
            fi
        else
            print_msg warning "Could not obtain UFW rules, skipping UFW cleanup"
        fi
    fi

    # Step 4: Check for DHCP leases
    print_msg info "----- STEP 4: Cleaning up DHCP leases -----"
    
    LEASE_FILES=$(find /var/lib/libvirt/dnsmasq/ -name "$SELECTED_NETWORK.*" 2>/dev/null) || true
    
    if [ -z "$LEASE_FILES" ]; then
        print_msg info "No DHCP lease files found"
    else
        print_msg info "Found DHCP lease files to clean up:"
        echo "$LEASE_FILES" | while read -r file; do
            echo "  - $file"
        done
        
        # DHCP lease file cleanup
        # Only try to reload dnsmasq if network was active when started
        if [ "$NETWORK_ACTIVE" = true ] && [ -n "$DNSMASQ_PID" ]; then
            print_msg info "Checking if dnsmasq process is still running..."
            if kill -0 "$DNSMASQ_PID" 2>/dev/null; then
                print_msg info "Attempting to reload dnsmasq configuration..."
                if kill -HUP "$DNSMASQ_PID" 2>/dev/null; then
                    print_msg success "Reloaded dnsmasq configuration"
                else
                    print_msg warning "Failed to reload dnsmasq. Process exists but may be unresponsive."
                fi
            else
                print_msg info "DHCP service already stopped, proceeding with lease file removal"
            fi
        else
            print_msg info "Network was already inactive, proceeding with lease file removal"
        fi
        
        # Now safe to remove lease files
        for file in $LEASE_FILES; do
            print_msg info "Removing lease file: $file"
            if rm -f "$file"; then
                print_msg success "Lease file removed: $file"
            else
                print_msg warning "Could not remove lease file: $file"
            fi
        done
    fi
    
    print_msg success "DHCP lease cleanup completed"
else
    if [ "$SKIP_NETWORK_CLEANUP" = true ]; then
        print_msg info "Network cleanup was skipped as configured"
    else
        print_msg info "No dedicated network found for this VM, skipping network-related cleanup steps"
    fi
fi

# Final verification
print_msg info "----- Final Verification -----"

# Verify VM is gone
if virsh dominfo "$VM_NAME" &>/dev/null; then
    print_msg error "VM '$VM_NAME' still exists! Cleanup may have failed."
else
    print_msg success "VM '$VM_NAME' successfully removed"
fi

# Verify network is gone
if [ -n "$SELECTED_NETWORK" ] && [ "$SKIP_NETWORK_CLEANUP" != true ]; then
    if virsh net-info "$SELECTED_NETWORK" &>/dev/null; then
        print_msg error "Network '$SELECTED_NETWORK' still exists! Cleanup may have failed."
    else
        print_msg success "Network '$SELECTED_NETWORK' successfully removed"
    fi
    
    # Verify bridge is gone
    if [ -n "$BRIDGE_NAME" ] && ip link show "$BRIDGE_NAME" &>/dev/null; then
        print_msg warning "Bridge interface '$BRIDGE_NAME' still exists!"
        print_msg info "This might be temporary - bridges are sometimes removed after libvirt restart"
    else
        print_msg success "Bridge interface successfully removed"
    fi
fi

# Check if disk files still exist
DISK_FILES_EXIST=false
for disk in "${VM_DISKS[@]}"; do
    # Skip base image for linked clones
    if [ "$LINKED_CLONE" = true ] && [ "$disk" = "$BASE_IMAGE" ]; then
        print_msg info "Base image preserved as expected: $disk"
        continue
    fi
    
    if [ -f "$disk" ]; then
        print_msg warning "Disk file still exists: $disk"
        # Check if the file is actually accessible or just a stale path
        if [ -r "$disk" ]; then
            file_info=$(file -b "$disk" 2>/dev/null || echo "unknown")
            disk_size=$(du -h "$disk" 2>/dev/null | awk '{print $1}' || echo "unknown")
            print_msg warning "Detected file type: $file_info (size: $disk_size)"
            print_msg warning "This is unexpected. You may need to manually remove it with: sudo rm -f $disk"
        else
            print_msg warning "File exists but is not readable. May be a stale path."
        fi
        DISK_FILES_EXIST=true
    fi
done

if [ "$DISK_FILES_EXIST" = false ] && [ ${#VM_DISKS[@]} -gt 0 ]; then
    print_msg success "All disk files successfully removed (except for base images in linked clones)"
fi

# Check for orphaned files in /var/lib/libvirt/images/ that match the VM name
print_msg info "Checking for orphaned disk files in /var/lib/libvirt/images/..."

ORPHANED_FILES=$(find /var/lib/libvirt/images/ -name "*${VM_NAME}*" 2>/dev/null || true)
if [ -n "$ORPHANED_FILES" ]; then
    print_msg warning "Found potential orphaned files related to this VM:"
    echo "$ORPHANED_FILES" | while read -r file; do
        # Skip base image for linked clones
        if [ "$LINKED_CLONE" = true ] && [ "$file" = "$BASE_IMAGE" ]; then
            print_msg info "  - $file (base image, not removing)"
            continue
        fi
        
        # Check if this file was already in VM_DISKS
        ALREADY_PROCESSED=false
        for known_disk in "${VM_DISKS[@]}"; do
            if [ "$file" = "$known_disk" ]; then
                ALREADY_PROCESSED=true
                break
            fi
        done
        
        if [ "$ALREADY_PROCESSED" = true ]; then
            # Already handled above
            continue
        fi
        
        # New orphaned file found
        file_info=$(file -b "$file" 2>/dev/null || echo "unknown")
        file_size=$(du -h "$file" 2>/dev/null | awk '{print $1}' || echo "unknown")
        print_msg warning "  - $file (type: $file_info, size: $file_size)"
        print_msg warning "    You may want to manually remove this file if it's no longer needed"
    done
else
    print_msg success "No orphaned files found in /var/lib/libvirt/images/"
fi

# Final summary
echo ""
print_msg success "Cleanup completed at $(date)!"
echo ""
print_msg info "Summary:"
print_msg info "- VM '$VM_NAME' has been deleted"

if [ "$LINKED_CLONE" = true ]; then
    print_msg info "- VM was a linked clone, base image preserved: $BASE_IMAGE"
fi

if [ -n "$SELECTED_NETWORK" ] && [ "$SKIP_NETWORK_CLEANUP" != true ]; then
    echo "- Dedicated network '$SELECTED_NETWORK' has been removed"
    echo "- Associated bridge interface has been removed"
    echo "- UFW rules for this network have been cleaned up"
    echo "- DHCP lease files have been cleaned up"
elif [ "$SKIP_NETWORK_CLEANUP" = true ]; then
    echo "- Network cleanup was skipped (default or shared network)"
else
    echo "- No dedicated network was found for cleanup"
fi

echo ""
print_msg info "Log file is available at: $LOG_FILE"
print_msg info "Log contains details of all deleted UFW rules and cleanup steps"

exit 0
