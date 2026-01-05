#!/bin/bash
# install_deps.sh - Install dependencies for LOTL Detector
# Run with: sudo ./install_deps.sh

set -euo pipefail

echo "Installing LOTL Detector dependencies..."

# Update package list
apt-get update

# Install BPF Compiler Collection and dependencies
apt-get install -y \
    bpfcc-tools \
    libbpfcc \
    libbpfcc-dev \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    python3-pip \
    python3-venv

echo ""
echo "Dependencies installed successfully!"
echo ""
echo "To set up the Python environment:"
echo "  cd /path/to/lotl-detector"
echo "  python3 -m venv .venv"
echo "  source .venv/bin/activate"
echo "  pip install -e ."

