#!/bin/bash
usage()
{
    echo "Usage: $0 [network name]"
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

value=$(echo $1 | tr -d '[:space:]')
line=$(nmcli connection show "$value" | grep "802-11-wireless.seen-bssids");r=$?
if [[ $r -ne 0 ]]; then
    exit $r
fi

mac=$(echo -n $line | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
echo "The known BSSID(s) of $value: $mac"
