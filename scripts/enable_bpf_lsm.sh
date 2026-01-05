#!/bin/bash
# enable_bpf_lsm.sh - Enable BPF LSM in GRUB
# This script modifies GRUB to include 'bpf' in the LSM list

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

GRUB_FILE="/etc/default/grub"
BACKUP_FILE="/etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)"

# Check current LSM status
echo "Current LSM list:"
cat /sys/kernel/security/lsm

# Check if bpf is already enabled
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM is already enabled!"
    exit 0
fi

echo ""
echo "BPF LSM is not enabled. Modifying GRUB..."

# Backup current GRUB config
cp "$GRUB_FILE" "$BACKUP_FILE"
echo "Backed up GRUB config to: $BACKUP_FILE"

# Get current GRUB_CMDLINE_LINUX value
CURRENT_CMDLINE=$(grep "^GRUB_CMDLINE_LINUX=" "$GRUB_FILE" | cut -d'"' -f2)

# New LSM list with bpf added
NEW_LSM="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"

# Check if there's already an lsm= parameter
if echo "$CURRENT_CMDLINE" | grep -q "lsm="; then
    # Replace existing lsm= parameter
    NEW_CMDLINE=$(echo "$CURRENT_CMDLINE" | sed "s/lsm=[^ ]*/lsm=landlock,lockdown,yama,integrity,apparmor,bpf/")
else
    # Add lsm= parameter
    if [[ -z "$CURRENT_CMDLINE" ]]; then
        NEW_CMDLINE="$NEW_LSM"
    else
        NEW_CMDLINE="$CURRENT_CMDLINE $NEW_LSM"
    fi
fi

# Update GRUB config
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$NEW_CMDLINE\"|" "$GRUB_FILE"

echo "Updated GRUB_CMDLINE_LINUX to:"
grep "^GRUB_CMDLINE_LINUX=" "$GRUB_FILE"

# Update GRUB
echo ""
echo "Running update-grub..."
update-grub

echo ""
echo "=============================================="
echo "BPF LSM has been enabled in GRUB configuration."
echo ""
echo "YOU MUST REBOOT for changes to take effect!"
echo ""
echo "After reboot, verify with:"
echo "  cat /sys/kernel/security/lsm"
echo ""
echo "Expected output should include 'bpf'"
echo "=============================================="

