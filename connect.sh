#!/bin/bash
usage()
{
    echo "Usage: sudo $0 [network BSSID] [--forget]"
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

./get-bssid.sh "$1"
if [[ $? -eq 0 ]]; then
    active=$(nmcli -f Name -t connection show --active)
    if [[ "$active" != "$1" ]]; then
        echo "Network already exists, simply bringing it up."
        nmcli connection up $1 | grep -P "Error|Warning"; r=$?
    else
        echo "Connection is already active."
        r=1
    fi
else
    nmcli -w 5 device wifi connect "$1" | grep Error; r=$?
fi

if [[ $r -eq 0 ]]; then
    echo "Failed to connect to $1!"
    nmcli connection delete "$1"
    exit $r
fi

# Get the network name we just connected to.
name=$(nmcli -f IN-USE,SSID device wifi list | grep '*' | tail -n +2 |
    awk '{print $2}')
echo "The network name is: $name"

# Find all MAC addresses
gateway=$(ip route list | grep default | awk '{print $3}')
echo "The subnet is: $gateway/24"

nmap -sn $gateway/24 --min-parallelism 16 --host-timeout 2s |
    grep "MAC Address:" | awk '{print $3}' | tr '[:upper:]' '[:lower:]'

if [[ "$2" == "--forget" ]]; then
    nmcli connection delete "$name"
fi
