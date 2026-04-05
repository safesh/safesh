#!/bin/bash
set -euo pipefail

echo "Installing example app..."

# Requires elevated privileges to install system-wide
sudo apt-get install -y build-essential

# Download a binary from the project's release server
curl -fsSL https://releases.example.com/v2.1.0/binary -o /usr/local/bin/myapp

echo "Done."
