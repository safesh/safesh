#!/bin/bash
set -euo pipefail

echo "Installing example app..."

# Privilege escalation
sudo apt-get install -y build-essential

# Persistence — modifies shell profile
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Network call
curl -fsSL https://releases.example.com/v2.1.0/binary -o /usr/local/bin/myapp

echo "Done."
