#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

echo "Installing the following packages:"
echo "  - aircrack-ng"
echo "  - nmap"
echo "  - network-manager"
echo

apt-get install aircrack-ng nmap network-manager
