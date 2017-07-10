#!/bin/bash
usage()
{
    echo "Usage: sudo $0 [network BSSID]"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

if [ $EUID -ne 0 ]; then
   echo "This script must be run as root."
   exit 1
fi

nmcli device wifi connect $1
if [ $? -ne 0 ]; then
    echo "Failed to connect to $1!"
    exit 1
fi

$gateway=$(ip route list | grep default | awk '{print $3}')
nmap -sn $gateway/24 | grep "MAC Address:" | awk '{print $3}'
