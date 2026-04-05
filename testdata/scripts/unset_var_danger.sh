#!/bin/bash
# Classic unset variable danger - without set -u this could be devastating
INSTALL_PREFIX="/opt/mytool"
rm -rf "$INSTALL_PREFIX/"

# Without set -u, if INSTALL_PREFIX is unset, this becomes rm -rf /
