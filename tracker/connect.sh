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

# TODO: Sort by timestamp for better cleanup replacement.
before=$(nmcli -t -f UUID connection show)
./get-bssid.sh "$1"
if [[ $? -eq 0 ]]; then
    active=$(nmcli -f Name -t connection show --active)
    if [[ "$active" != "$1" ]]; then
        echo "Network already exists, simply bringing it up."
        nmcli connection up $1 |& grep -P "Error|Warning"; r=$?
    else
        echo "Connection is already active."
        r=1
    fi
else
    echo "Creating new connection to \"$1\""
    nmcli -w 5 device wifi connect "$1" |& grep Error; r=$?
fi

if [[ $r -eq 0 ]]; then
    echo "Failed to connect to $1!"
    nmcli connection delete "$1" |& grep Error; q=$?
    if [[ $q -eq 0 ]]; then
        after=$(nmcli -t -f UUID connection show)
        echo "Before: $before"
        echo "After:  $after"
        uuid=$(echo $after | sed -e "s/$(echo $before)//")
        if [[ "$uuid" != "" ]]; then
            echo "Deleting connection via $uuid"
            nmcli connection delete $uuid
        fi
        exit $q
    fi
    exit $r
fi

# Get the network name we just connected to.
name=$(nmcli -t -f IN-USE,SSID dev wifi list | grep '*' | awk -F: '{print $2}')
echo "The network name is: $name"

# Find all MAC addresses
gateway=$(ip route list | grep default | awk '{print $3}')
echo "The subnet is: $gateway/24"

nmap -sn $gateway/24 --min-parallelism 16 --host-timeout 2s |
    grep "MAC Address:" | awk '{print $3}' | tr '[:upper:]' '[:lower:]'

if [[ "$2" == "--forget" ]]; then
    nmcli connection delete "$name"
fi
