#!/bin/bash
usage()
{
    echo "Usage: sudo $0 [interface] [default=start|stop]"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

if [ $# -eq 1 ] || [[ "$2" == "start" ]]; then
    airmon-ng start $1
elif [[ "$2" == "stop" ]]; then
    airmon-ng stop $1
else
    usage
fi
