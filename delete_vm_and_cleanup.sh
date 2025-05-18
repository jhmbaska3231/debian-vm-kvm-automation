#!/bin/bash
# Delete VM and network cleanup script
#
# This script safely removes a single VM and its dedicated network:
# - detects the specific network used by this VM
# - checks if any other VMs are using the network before deletion
# - checks and deletes any VM snapshots before removal
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

# Create log directory and file
LOG_DIR="/var/log/vm_management"
LOG_FILE="$LOG_DIR/vm_cleanup_$(date +%Y%m%d_%H%M%S).log"

# Ensure log directory exists with proper permissions
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Initialize the log file
touch "$LOG_FILE"

# Set up cleanup trap for temp files
trap 'echo "Script terminated. Log file: $LOG_FILE"' EXIT INT TERM

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
    print_msg error "Please specify a VM name using --vm"
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
    print_msg warning "The VM is using the default network."
    print_msg warning "Will not delete the default network for safety reasons."
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

# Check if VM is running and shut down if necessary
if virsh dominfo "$VM_NAME" | grep -q "State:.*running"; then
    print_msg info "VM is running, shutting down..."
    
    # Try graceful shutdown first
    virsh shutdown "$VM_NAME"
    print_msg info "Shutdown initiated. Waiting for VM to stop (up to 15 seconds)..."
    
    # Wait for up to 15 seconds for the VM to shut down with countdown
    for i in {15..1}; do
        if ! virsh dominfo "$VM_NAME" 2>/dev/null | grep -q "State:.*running"; then
            print_msg success "VM gracefully shut down after $((15-i)) seconds"
            break
        fi
        printf "\rWaiting for VM to shut down... %d " $i
        sleep 1
    done
    echo ""
    
    # Force shutdown if still running
    if virsh dominfo "$VM_NAME" 2>/dev/null | grep -q "State:.*running"; then
        print_msg warning "VM did not shut down gracefully within 15 seconds. Using force stop."
        virsh destroy "$VM_NAME"
        print_msg info "VM forcefully stopped"
    fi
else
    print_msg info "VM is already stopped"
fi

# Check for and delete VM snapshots
print_msg info "Checking for VM snapshots..."

SNAPSHOT_COUNT=0

# Get snapshot names directly
SNAPSHOT_NAMES=$(virsh snapshot-list "$VM_NAME" --name 2>/dev/null | grep -v '^$' || echo "")

if [ -n "$SNAPSHOT_NAMES" ]; then
    # Count snapshots
    SNAPSHOT_COUNT=$(echo "$SNAPSHOT_NAMES" | wc -l)
    print_msg info "Found $SNAPSHOT_COUNT snapshot(s) for VM '$VM_NAME'"
    print_msg info "Deleting snapshots one by one..."
    
    # Loop through snapshots and delete them individually
    echo "$SNAPSHOT_NAMES" | while read -r snap_name; do
        print_msg info "Deleting snapshot: $snap_name"
        if ! virsh snapshot-delete "$VM_NAME" --snapshotname "$snap_name"; then
            print_msg error "Failed to delete snapshot '$snap_name'"
            print_msg error "VM deletion cannot proceed with snapshots remaining. Exiting script."
            print_msg info "To manually delete snapshots, use: virsh snapshot-list $VM_NAME && virsh snapshot-delete $VM_NAME --snapshotname <name>"
            exit 1
        else
            print_msg success "Snapshot '$snap_name' deleted successfully"
        fi
    done
    
    print_msg success "All snapshots deleted successfully"
else
    print_msg info "No snapshots found for VM '$VM_NAME'"
fi

# Get associated disk information
print_msg info "Analyzing VM disk configuration..."
VM_DISKS=()
LINKED_CLONE=false
BASE_IMAGE=""

# Process all disks to determine configuration
while read -r disk_target disk_source; do
    # Skip if source is not a valid file path
    [ -z "$disk_source" ] || [ "$disk_source" = "-" ] && continue
    
    # Add to disk array
    VM_DISKS+=("$disk_source")
    
    # Get disk information and check for backing file
    if DISK_INFO=$(qemu-img info "$disk_source" 2>/dev/null); then
        # Check if this disk has a backing file (indicating linked clone)
        if echo "$DISK_INFO" | grep -qi "backing file"; then
            LINKED_CLONE=true
            # Extract the backing file path
            BASE_IMAGE=$(echo "$DISK_INFO" | grep -oP 'backing file: \K[^\n(]+' | sed 's/^ *//;s/ *$//')
        fi
    fi
done < <(virsh domblklist "$VM_NAME" | tail -n +3 | awk '{print $1, $2}')

# Provide consolidated summary
if [ ${#VM_DISKS[@]} -eq 0 ]; then
    print_msg warning "No disk files found for VM '$VM_NAME'"
elif [ "$LINKED_CLONE" = true ]; then
    if [ -n "$BASE_IMAGE" ] && [ -f "$BASE_IMAGE" ]; then
        print_msg info "VM is a linked clone (${#VM_DISKS[@]} disk(s)) with base image: $BASE_IMAGE"
    else
        print_msg warning "VM appears to be a linked clone (${#VM_DISKS[@]} disk(s)) but base image not found: $BASE_IMAGE"
    fi
else
    print_msg info "VM is a standard VM with ${#VM_DISKS[@]} disk(s)"
fi

# Get network information (bridge and subnet) for the selected network
BRIDGE_NAME=""
BRIDGE_SUBNET=""
if [ -n "$SELECTED_NETWORK" ] && [ "$SKIP_NETWORK_CLEANUP" != true ]; then
    print_msg info "Getting network bridge and subnet information..."
    
    # Get bridge name directly from virsh net-info
    if BRIDGE_NAME=$(virsh net-info "$SELECTED_NETWORK" 2>/dev/null | awk '/Bridge:/ && $2 != "-" {print $2}'); then
        # Get bridge subnet using a single efficient command
        if [ -n "$BRIDGE_NAME" ]; then
            BRIDGE_SUBNET=$(ip -4 addr show dev "$BRIDGE_NAME" 2>/dev/null | awk '/inet / {
                ip = $2
                split(ip, parts, "/")
                if (parts[2] == "24") {
                    split(parts[1], octets, ".")
                    print octets[1] "." octets[2] "." octets[3] ".0/24"
                } else {
                    print ip
                }
            }')
            print_msg info "Network bridge: $BRIDGE_NAME, subnet: $BRIDGE_SUBNET"
        fi
    else
        print_msg warning "Could not get bridge information for network '$SELECTED_NETWORK'"
    fi
fi

# Step 1: Delete the VM
echo ""
print_msg info "----- STEP 1: Deleting VM -----"

# Handle VM deletion based on disk configuration
if [ "$LINKED_CLONE" = true ]; then
    # For linked clones, undefine VM and manually handle disk deletion
    print_msg info "Removing linked clone VM and disks (preserving base image)..."
    
    if ! virsh undefine "$VM_NAME"; then
        print_msg error "Failed to undefine VM. Unable to continue."
        exit 1
    fi
    
    # Manually delete only the linked clone disk files
    for disk in "${VM_DISKS[@]}"; do
        if [ -f "$disk" ] && [ "$disk" != "$BASE_IMAGE" ]; then
            if rm -f "$disk"; then
                print_msg success "Removed linked clone disk: $disk"
            else
                print_msg error "Failed to delete disk file: $disk"
            fi
        fi
    done
else
    # For standard VMs, try to remove VM and all storage in one operation
    print_msg info "Removing VM and all associated disks..."
    
    if ! virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null; then
        print_msg warning "Bulk removal failed, using alternative method..."
        
        if ! virsh undefine "$VM_NAME"; then 
            print_msg error "Failed to undefine VM. Unable to continue."
            exit 1
        fi
        
        # Manually delete disk files
        for disk in "${VM_DISKS[@]}"; do
            if [ -f "$disk" ]; then
                if rm -f "$disk"; then
                    print_msg success "Removed disk: $disk"
                else
                    print_msg error "Failed to delete disk file: $disk"
                fi
            fi
        done
    else
        print_msg success "VM and disks removed successfully"
    fi
fi

print_msg success "VM deletion completed"


# Step 2: Delete the network if one was found and not skipped
echo ""
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
    echo ""
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
    echo ""
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

# Final verification and summary
echo ""
print_msg info "----- Cleanup Summary and Verification -----"

# Collect verification results
VERIFICATION_ISSUES=()
SUMMARY_ITEMS=()

# Verify VM deletion
if virsh dominfo "$VM_NAME" &>/dev/null; then
    VERIFICATION_ISSUES+=("VM '$VM_NAME' still exists")
else
    SUMMARY_ITEMS+=("VM '$VM_NAME' deleted successfully")
    if [ "$SNAPSHOT_COUNT" -gt 0 ]; then
        SUMMARY_ITEMS+=("$SNAPSHOT_COUNT snapshot(s) removed")
    fi
fi

# Verify network deletion if applicable
if [ -n "$SELECTED_NETWORK" ] && [ "$SKIP_NETWORK_CLEANUP" != true ]; then
    if virsh net-info "$SELECTED_NETWORK" &>/dev/null; then
        VERIFICATION_ISSUES+=("Network '$SELECTED_NETWORK' still exists")
    else
        SUMMARY_ITEMS+=("Network '$SELECTED_NETWORK' and bridge removed")
        SUMMARY_ITEMS+=("UFW rules and DHCP leases cleaned up")
    fi
elif [ "$SKIP_NETWORK_CLEANUP" = true ]; then
    SUMMARY_ITEMS+=("Network cleanup skipped (default/shared network)")
fi

# Verify disk deletion and check for orphans
DISK_ISSUES=()
for disk in "${VM_DISKS[@]}"; do
    # Skip base image for linked clones
    if [ "$LINKED_CLONE" = true ] && [ "$disk" = "$BASE_IMAGE" ]; then
        continue
    fi
    if [ -f "$disk" ]; then
        DISK_ISSUES+=("$disk")
    fi
done

# Check for orphaned files
if [ "$LINKED_CLONE" = true ] && [ -n "$BASE_IMAGE" ]; then
    ORPHANED_FILES=$(find /var/lib/libvirt/images/ -name "*${VM_NAME}*" 2>/dev/null | grep -v "$BASE_IMAGE" || true)
else
    ORPHANED_FILES=$(find /var/lib/libvirt/images/ -name "*${VM_NAME}*" 2>/dev/null || true)
fi

# Report disk status
if [ ${#DISK_ISSUES[@]} -gt 0 ] || [ -n "$ORPHANED_FILES" ]; then
    if [ ${#DISK_ISSUES[@]} -gt 0 ]; then
        VERIFICATION_ISSUES+=("${#DISK_ISSUES[@]} disk file(s) still exist")
    fi
    if [ -n "$ORPHANED_FILES" ]; then
        ORPHAN_COUNT=$(echo "$ORPHANED_FILES" | wc -l)
        VERIFICATION_ISSUES+=("$ORPHAN_COUNT orphaned file(s) found")
    fi
else
    if [ "$LINKED_CLONE" = true ]; then
        SUMMARY_ITEMS+=("Linked clone disks removed (base image preserved)")
    else
        SUMMARY_ITEMS+=("All disk files removed")
    fi
fi

# Present consolidated results
if [ ${#VERIFICATION_ISSUES[@]} -gt 0 ]; then
    print_msg warning "Cleanup completed with issues:"
    for issue in "${VERIFICATION_ISSUES[@]}"; do
        print_msg warning "- $issue"
    done
    if [ -n "$ORPHANED_FILES" ]; then
        print_msg info "Orphaned files found:"
        echo "$ORPHANED_FILES" | while read -r file; do
            print_msg info "  - $file"
        done
    fi
else
    print_msg success "Cleanup completed successfully!"
    for item in "${SUMMARY_ITEMS[@]}"; do
        print_msg success "- $item"
    done
fi

# Add preserved base image information if applicable
if [ "$LINKED_CLONE" = true ]; then
    print_msg info "- Base image preserved: $BASE_IMAGE"
fi

echo ""

exit 0
